#!/usr/bin/env python3
"""Check ROA validity of a prefix anouncement"""
import argparse
import sqlite3

from mrt2sql import unpack_cidr
from utils import get_cidr

# CIDR, max length
ROAEntry = tuple[str, int]

def get_valid_origins(dbconn, cidr: str) -> dict[int, set[ROAEntry]]:
    network_addr, length, broadcast_addr = unpack_cidr(cidr)
    roa_entries = dbconn.execute(
        '''SELECT asn, network, length, max_length
        FROM ROAEntries
        WHERE network <= ? AND broadcast_address >= ? AND max_length >= ?
        ORDER BY length DESC''', (network_addr, broadcast_addr, length))

    result = {}
    for asn, network_addr, length, max_length in roa_entries:
        asn = int(asn)
        roa_cidr = get_cidr(network_addr, length)
        result.setdefault(asn, set()).add((roa_cidr, max_length))
    return result

def check_roa(dbconn, cidr: str, asn: int):
    network_addr, length, broadcast_addr = unpack_cidr(cidr)
    roa_entries = dbconn.execute(
        '''SELECT DISTINCT network, length, max_length, asn
        FROM ROAEntries
        WHERE network <= ? AND broadcast_address >= ? AND asn == ? AND max_length >= ?
        ORDER BY length DESC''', (network_addr, broadcast_addr, asn, length))
    return roa_entries.fetchall()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('db_filename', help='SQLite DB to read FROM')
    parser.add_argument('prefix', help='CIDR to check')
    parser.add_argument('asn', help='Origin ASN', type=int, nargs='?')
    args = parser.parse_args()

    db = sqlite3.connect(f'file:{args.db_filename}?mode=ro')
    if args.asn:
        results = check_roa(db, args.prefix, args.asn)
    else:
        results = get_valid_origins(db, args.prefix)
    print(results)
    print(bool(results))

if __name__ == '__main__':
    main()
