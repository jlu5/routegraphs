#!/usr/bin/env python3
"""Export BGP routes info from MRT dumps into a SQLite DB for easier querying."""
import argparse
import itertools
import logging
import pathlib
import re
import socket
import sqlite3

import pybgpkit_parser
from dn42regparse import get_as_name, get_fields

logger = logging.getLogger("mrt2sql")

_DB_INIT_SCRIPT = pathlib.Path(__file__).parent / 'dbinit.sql'
def db_init(db_filename):
    with open(_DB_INIT_SCRIPT, encoding='utf8') as f:
        script = f.read()
    con = sqlite3.connect(db_filename)
    con.executescript(script)
    con.commit()
    return con

def unpack_cidr(prefix: str) -> (bytes, int, bytes):
    """Unpack a CIDR prefix string into binary network address, prefix length, and binary broadcast address"""
    network_address, prefix_length = prefix.split('/', 1)
    prefix_length = int(prefix_length)
    if ':' in network_address:
        ip_bits = 128
        socket_family = socket.AF_INET6
    else:
        ip_bits = 32
        socket_family = socket.AF_INET

    # This used to use the Python ipaddress module, but that is much slower
    network_address_packed = socket.inet_pton(socket_family, network_address)
    broadcast_mask = (1<<(ip_bits-prefix_length))-1
    broadcast_address = int.from_bytes(network_address_packed, 'big') | broadcast_mask
    broadcast_address_packed = broadcast_address.to_bytes(ip_bits//8, 'big')
    return (network_address_packed, prefix_length, broadcast_address_packed)

# FIXME(clearnet support): this is not entirely correct
# what does it mean to have multiple origin ASes but the rest of the path be the same?
_AS_PATH_SEGMENT_RE = re.compile('\\{(\\d+)')
def parse_mrt(mrt_filename, dbconn, registry_path=None):
    # pylint: disable=no-member
    mrt_reader = pybgpkit_parser.Parser(mrt_filename, filters={'type': 'announce'})
    as_names = {}
    for entry in mrt_reader:
        logger.debug("MRT entry: %s", entry)
        as_path_raw = entry.as_path.split()
        as_path_parts = []
        ok = True
        for path_segment in as_path_raw:
            try:
                asn = int(path_segment)
            except ValueError:
                match = _AS_PATH_SEGMENT_RE.match(path_segment)
                if not match:
                    logger.warning("Ignoring unsupported AS path %r", as_path_raw)
                    ok = False
                    break
                asn = int(match.group(1))
                logger.info("Guessing origin ASN %r -> %d for path %r", path_segment, asn, as_path_raw)
            as_path_parts.append(asn)
        if not ok:
            continue
        as_path = tuple(as_path_parts)

        # Feed ASN
        feed_asn = as_path[0]
        if registry_path and feed_asn not in as_names:
            as_names[feed_asn] = get_as_name(registry_path, feed_asn)
        dbconn.execute("INSERT OR REPLACE INTO ASNs VALUES(?, 1, ?)", (feed_asn, as_names.get(feed_asn, '')))

        prefix = entry.prefix
        unpacked_cidr = unpack_cidr(prefix)
        network_address_packed, prefix_length, _ = unpacked_cidr
        dbconn.execute("INSERT OR IGNORE INTO Prefixes VALUES(?, ?, ?)", unpacked_cidr)

        path_id = hash(as_path)
        for path_index, asn in enumerate(as_path):
            if registry_path and asn not in as_names:
                as_names[asn] = get_as_name(registry_path, asn)
            dbconn.execute(
                "INSERT OR IGNORE INTO ASNs VALUES(?, 0, ?)", (asn, as_names.get(asn, ''))
            )
            dbconn.execute(
                "INSERT OR IGNORE INTO Paths VALUES(?, ?, ?)",
                (path_id, path_index, asn)
            )
            if path_index > 0:
                previous_asn = as_path[path_index-1]
                if previous_asn == asn:
                    continue
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
            "INSERT OR IGNORE INTO Announcements VALUES(?, ?, ?)",
            (as_path[-1], network_address_packed, prefix_length)
        )
    dbconn.commit()

# XXX hardcoded
_DEFAULT_V4_MAX_LENGTH = 29
_DEFAULT_V6_MAX_LENGTH = 64
def parse_roa(dbconn, registry_root):
    path4 = pathlib.Path(registry_root) / 'data' / 'route'
    path6 = pathlib.Path(registry_root) / 'data' / 'route6'
    for roa_file in itertools.chain(path4.iterdir(), path6.iterdir()):
        cidr = roa_file.name.replace('_', '/')
        network_address_packed, prefix_length, broadcast_address_packed = unpack_cidr(cidr)
        roa_fields = get_fields(roa_file)

        asns = roa_fields['origin'].split()
        for asn_entry in asns:
            # Chop off the "AS" part of each AS reference
            asn = int(asn_entry[2:])

            # Default ROA length if not specified is /29 or the length of the prefix, whichever is larger
            default_max_length = _DEFAULT_V6_MAX_LENGTH if ':' in cidr else _DEFAULT_V4_MAX_LENGTH
            max_length = int(roa_fields.get('max-length', default_max_length))
            max_length = max(prefix_length, max_length)
            dbconn.execute(
                "INSERT OR IGNORE INTO ROAEntries VALUES(?, ?, ?, ?, ?)",
                (network_address_packed, prefix_length, broadcast_address_packed, asn, max_length)
            )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('db_filename', help='SQLite DB to write to')
    parser.add_argument('-r', '--registry-path', help='path to dn42 registry')
    parser.add_argument('-v', '--verbose', help='enables debug logging', action='store_true')
    parser.add_argument('mrt_filenames', help='MRT dump filenames', nargs='+')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    if not args.registry_path:
        logger.warning('dn42 registry path not specified, AS names will be missing')

    db = db_init(args.db_filename)

    if args.registry_path:
        logger.info('Reading ROA entries from %s', args.registry_path)
        parse_roa(db, args.registry_path)

    for filename in args.mrt_filenames:
        logger.info('Reading MRT dump %s', filename)
        parse_mrt(filename, db, args.registry_path)

if __name__ == '__main__':
    main()
