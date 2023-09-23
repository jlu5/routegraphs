#!/usr/bin/env python3
"""Export BGP routes info from MRT dumps into a SQLite DB for easier querying."""
import argparse
import pathlib
import re
import socket
import sqlite3
import traceback

import pybgpkit_parser

_DB_INIT_SCRIPT = pathlib.Path(__file__).parent / 'dbinit.sql'
def db_init(db_filename):
    with open(_DB_INIT_SCRIPT, encoding='utf8') as f:
        script = f.read()
    con = sqlite3.connect(db_filename)
    con.executescript(script)
    con.commit()
    return con

def get_resource_name(registry_path: str, asn: int | None = None) -> str:
    if asn:
        path = pathlib.Path(registry_path) / 'data' / 'aut-num' / f'AS{asn}'
        field = 'as-name'
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                m = re.match(fr'{field}:\s+(.*)', line)
                if m:
                    name = m.group(1)
                    print(f'get_resource_name: AS{asn} -> {name}')
                    return name
    except OSError as e:
        print(f"Error loading resource from {path}: {e}")
        traceback.print_exc()
    return ''

# FIXME(clearnet support): this is not entirely correct
# what does it mean to have multiple origin ASes but the rest of the path be the same?
_AS_PATH_SEGMENT_RE = re.compile('\\{(\\d+)')
def parse_mrt(mrt_filename, dbconn, registry_path=None):
    mrt_reader = pybgpkit_parser.Parser(mrt_filename, filters={'type': 'announce'})
    as_names = {}
    for entry in mrt_reader:
        # Feed ASN
        feed_asn = entry['peer_asn']
        if registry_path and feed_asn not in as_names:
            as_names[feed_asn] = get_resource_name(registry_path, asn=feed_asn)
        dbconn.execute("INSERT OR REPLACE INTO ASNs VALUES(?, 1, ?)", (feed_asn, as_names.get(feed_asn, '')))

        prefix = entry['prefix']
        network_address, prefix_length = prefix.split('/', 1)
        prefix_length = int(prefix_length)
        if ':' in network_address:
            ip_bits = 128
            socket_family = socket.AF_INET6
        else:
            ip_bits = 32
            socket_family = socket.AF_INET

        # This part used to use the Python ipaddress module, but that is much slower than doing a bit of math ourselves
        network_address_packed = socket.inet_pton(socket_family, network_address)
        broadcast_mask = (1<<(ip_bits-prefix_length))-1
        broadcast_address = int.from_bytes(network_address_packed, 'big') | broadcast_mask
        broadcast_address_packed = broadcast_address.to_bytes(ip_bits//8, 'big')
        dbconn.execute("INSERT OR IGNORE INTO Prefixes VALUES(?, ?, ?)",
            (network_address_packed, prefix_length, broadcast_address_packed))

        as_path = entry['as_path'].split()
        as_path_parts = []
        ok = True
        for path_segment in as_path:
            try:
                asn = int(path_segment)
            except ValueError:
                match = _AS_PATH_SEGMENT_RE.match(path_segment)
                if not match:
                    print(f"WARN: Ignoring unsupported AS path {as_path!r}")
                    ok = False
                    break
                asn = int(match.group(1))
                print(f"Guessing origin ASN {path_segment!r} -> {asn} for path {as_path!r}")
            as_path_parts.append(asn)
        if not ok:
            continue
        as_path = tuple(as_path_parts)

        path_id = hash(as_path)
        for path_index, asn in enumerate(as_path):
            if registry_path and asn not in as_names:
                as_names[asn] = get_resource_name(registry_path, asn=asn)
            dbconn.execute(
                "INSERT OR IGNORE INTO ASNs VALUES(?, 0, ?)", (asn, as_names.get(asn, ''))
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
                if as_path[-1] != asn:
                    # If the prefix origin isn't the current ASN, that means this AS provides
                    # transit for the one before it in the path
                    dbconn.execute(
                        "UPDATE NeighbourASNs SET transit=1 WHERE receiver_asn==? AND sender_asn==?",
                        (previous_asn, asn)
                    )
        dbconn.execute(
            "INSERT OR IGNORE INTO PrefixPaths VALUES(?, ?, ?)",
            (network_address_packed, prefix_length, path_id)
        )
        dbconn.execute(
            "INSERT OR IGNORE INTO PrefixOriginASNs VALUES(?, ?, ?)",
            (as_path[-1], network_address_packed, prefix_length)
        )
    dbconn.commit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('db_filename', help='SQLite DB to write to')
    parser.add_argument('-r', '--registry-path', help='path to dn42 registry')
    parser.add_argument('mrt_filenames', help='MRT dump filenames', nargs='+')
    args = parser.parse_args()

    db = db_init(args.db_filename)
    for filename in args.mrt_filenames:
        parse_mrt(filename, db, args.registry_path)

if __name__ == '__main__':
    main()
