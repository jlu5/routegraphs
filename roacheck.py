#!/usr/bin/env python3
"""Check ROA validity of a prefix anouncement"""
import argparse
import sqlite3

from mrt2sql import unpack_cidr

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
    parser.add_argument('asn', help='Origin ASN', type=int)
    args = parser.parse_args()

    db = sqlite3.connect(f'file:{args.db_filename}?mode=ro')
    results = check_roa(db, args.prefix, args.asn)
    print(results)
    print(bool(results))

if __name__ == '__main__':
    main()
