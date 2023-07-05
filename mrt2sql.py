#!/usr/bin/env python3
"""Export BGP routes info from MRT dumps into a SQLite DB for easier querying."""
import argparse
import enum
import pathlib
import sqlite3

import mrtparse

# https://datatracker.ietf.org/doc/html/rfc6396#section-5.3
class EntryType(enum.Enum):
    TABLE_DUMP_V2 = 13

class EntrySubType(enum.Enum):
    PEER_INDEX_TABLE = 1
    RIB_IPV4_UNICAST = 2
    RIB_IPV4_MULTICAST = 3
    RIB_IPV6_UNICAST = 4
    RIB_IPV6_MULTICAST = 5
    RIB_GENERIC = 6
    RIB_IPV4_UNICAST_ADDPATH = 8
    RIB_IPV4_MULTICAST_ADDPATH = 9
    RIB_IPV6_UNICAST_ADDPATH = 10
    RIB_IPV6_MULTICAST_ADDPATH = 11
    RIB_GENERIC_ADDPATH = 12

_ROUTE_SUBTYPES = (
    EntrySubType.RIB_IPV4_UNICAST.value,
    EntrySubType.RIB_IPV6_UNICAST.value,
    EntrySubType.RIB_IPV4_UNICAST_ADDPATH.value,
    EntrySubType.RIB_IPV6_UNICAST_ADDPATH.value,
)

_DB_INIT_SCRIPT = pathlib.Path(__file__).parent / 'dbinit.sql'
def db_init(db_filename):
    with open(_DB_INIT_SCRIPT, encoding='utf8') as f:
        script = f.read()
    con = sqlite3.connect(db_filename)
    con.executescript(script)
    con.commit()
    return con

def parse_mrt(mrt_filename, dbconn):
    with open(mrt_filename, 'rb') as f:
        mrt_reader = mrtparse.Reader(f)

        for entry in mrt_reader:
            data = entry.data
            if EntryType.TABLE_DUMP_V2.value not in data['type']:
                continue
            direct_feed_ases = set()
            if EntrySubType.PEER_INDEX_TABLE.value in data['subtype']:
                total_peers = data['peer_count']
                direct_feed_ases |= {peer['peer_as'] for peer in data['peer_entries']}
                direct_feed_ases.discard(0)
                print(f'{mrt_filename} total {total_peers} direct feeds ({len(direct_feed_ases)} unique ASes)')

                dbconn.executemany("INSERT OR IGNORE INTO ASNs VALUES(:peer_as, TRUE)", data['peer_entries'])
            if any(subtype in data['subtype'] for subtype in _ROUTE_SUBTYPES):
                prefix_network = data['prefix']
                prefix_length = data['length']
                dbconn.execute("INSERT OR IGNORE INTO Prefixes VALUES(?, ?)", (prefix_network, prefix_length))
                for rib_entry in data['rib_entries']:
                    for path_attribute in rib_entry['path_attributes']:
                        # AS_PATH=2
                        if 2 in path_attribute['type']:
                            as_path = tuple(map(int, path_attribute['value'][0]['value']))
                            origin_asn = as_path[-1]
                            #print(f"Adding: {prefix_network}/{prefix_length} PATH {as_path}")
                            path_id = hash(as_path)
                            for path_index, asn in enumerate(as_path):
                                dbconn.execute(
                                    "INSERT OR IGNORE INTO ASNs VALUES(?, ?)",
                                    (asn, asn in direct_feed_ases)
                                )
                                dbconn.execute(
                                    "INSERT OR IGNORE INTO Paths VALUES(?, ?, ?)",
                                    (path_id, path_index, asn)
                                )
                                if path_index > 0:
                                    previous_asn = as_path[path_index-1]
                                    dbconn.execute(
                                        "INSERT OR IGNORE INTO NeighbourASNs(receiver_asn, sender_asn) VALUES(?, ?)",
                                        (previous_asn, asn)
                                    )
                                    if origin_asn != asn:
                                        # If the prefix origin isn't the current ASN, that means this AS provides
                                        # transit for the one before it in the path
                                        dbconn.execute(
                                            "UPDATE NeighbourASNs SET transit=1 WHERE receiver_asn==? AND sender_asn==?",
                                            (previous_asn, asn)
                                        )
                            dbconn.execute(
                                "INSERT OR IGNORE INTO PrefixPaths VALUES(?, ?, ?)",
                                (prefix_network, prefix_length, path_id)
                            )
                            dbconn.execute(
                                "INSERT OR IGNORE INTO PrefixOriginASNs VALUES(?, ?, ?)",
                                (origin_asn, prefix_network, prefix_length)
                            )
    dbconn.commit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('db_filename', help='SQLite DB to write to')
    parser.add_argument('mrt_filenames', help='MRT dump filenames', nargs='+')
    args = parser.parse_args()

    db = db_init(args.db_filename)
    for filename in args.mrt_filenames:
        parse_mrt(filename, db)

if __name__ == '__main__':
    main()
