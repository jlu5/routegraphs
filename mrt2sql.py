#!/usr/bin/env python3
"""Export BGP routes info from MRT dumps into a SQLite DB for easier querying."""
import argparse
import ipaddress
import pathlib
import sqlite3

import pybgpkit_parser

_DB_INIT_SCRIPT = pathlib.Path(__file__).parent / 'dbinit.sql'
def db_init(db_filename):
    with open(_DB_INIT_SCRIPT, encoding='utf8') as f:
        script = f.read()
    con = sqlite3.connect(db_filename)
    con.executescript(script)
    con.commit()
    return con

def parse_mrt(mrt_filename, dbconn):
    mrt_reader = pybgpkit_parser.Parser(mrt_filename)
    for entry in mrt_reader:
        if entry['elem_type'] != 'A':
            continue

        # Feed ASN
        feed_asn = entry['peer_asn']
        dbconn.execute("INSERT OR REPLACE INTO ASNs VALUES(?, 1)", (feed_asn,))

        ipn = ipaddress.ip_network(entry['prefix'])
        prefix_length = ipn.prefixlen
        network_address = ipn.network_address
        broadcast_address = ipn.broadcast_address
        dbconn.execute("INSERT OR IGNORE INTO Prefixes VALUES(?, ?, ?)",
            (network_address.packed, prefix_length, broadcast_address.packed))

        as_path = tuple(map(int, entry['as_path'].split()))
        origin_asn = as_path[-1]
        #print(f"Adding: {prefix_network}/{prefix_length} PATH {as_path}")
        path_id = hash(as_path)
        for path_index, asn in enumerate(as_path):
            dbconn.execute(
                "INSERT OR IGNORE INTO ASNs VALUES(?, 0)", (asn,)
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
            (network_address.packed, prefix_length, path_id)
        )
        dbconn.execute(
            "INSERT OR IGNORE INTO PrefixOriginASNs VALUES(?, ?, ?)",
            (origin_asn, network_address.packed, prefix_length)
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
