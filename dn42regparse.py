#!/usr/bin/env python3
"""A crude parser for the dn42 registry"""
import argparse
import pathlib
import pprint
import re

_field_re = re.compile(r'[a-z-]+?: .*?')
def get_fields(path: str) -> dict[str, str]:
    """Fetch fields from the dn42 resource object at path."""
    fields = {}
    try:
        with open(path, encoding='utf-8') as f:
            last_fieldname = None
            field = None
            for line in f:
                if _field_re.match(line):
                    last_fieldname, field = line.split(':', 1)
                    field = field.strip()
                else:
                    field = line.strip()
                if last_fieldname in fields:
                    fields[last_fieldname] += f'\n{field}'
                else:
                    fields[last_fieldname] = field
    except OSError as e:
        print(f"get_fields ERROR: {path}: {e}")
    return fields

def get_as_name(registry_root: str, asn: int) -> str:
    """Fetch the name of an AS"""
    path = pathlib.Path(registry_root) / 'data' / 'aut-num' / f'AS{asn}'
    fields = get_fields(path)
    return fields.get('as-name', '')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='path to dn42 registry file')
    args = parser.parse_args()

    result = get_fields(args.path)
    pprint.pprint(result)

if __name__ == '__main__':
    main()
