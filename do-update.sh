#!/bin/bash
# Periodic update script - import new mrt dumps and parse them into sql
set -xe
cd "${0%/*}"
pushd "data/"

if [[ -z "$NODOWNLOAD" ]]; then
    for mrtfile in master4_latest.mrt master6_latest.mrt; do
        rm -f "$mrtfile" "$mrtfile.bz2"
        wget --no-check-certificate "https://mrt.collector.dn42/$mrtfile.bz2"
        bunzip2 "$mrtfile.bz2"
    done
    wget "https://dn42.burble.com/roa/dn42_roa_46.json" -O dn42_roa_46.json.new
    mv dn42_roa_46.json.new dn42_roa_46.json
fi

DB_OUT="dn42.db"

rm -f "$DB_OUT.new"
time python3 ../mrt2sql.py "$DB_OUT.new" master4_latest.mrt master6_latest.mrt "$@"
if [[ -f "$DB_OUT" ]]; then
    mv "$DB_OUT" "$DB_OUT.bak"
fi
mv "$DB_OUT.new" "$DB_OUT"
echo "OK"
