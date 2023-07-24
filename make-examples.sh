#!/bin/bash

DB="$1"
if [[ -z "$DB" ]]; then
    echo "usage: $0 /path/to/sqlite.db"
    exit 1
fi

DIR="examples"

graph() {
    name="$1"
    set -x
    shift
    python3 routegraphs.py "$DB" "$DIR/$name".dot "$@"
    dot -Tsvg "$DIR/$name".dot > "$DIR/$name".svg
    echo "Created $DIR/$name.svg"
    set +x
}

set -e
cd "${0%/*}" || exit 1
mkdir -p "${DIR}"
graph test-highdef-v6 fd86:bad:11b7::/48 4242423914 4242421588 64719 4242421817 4242423088
graph test-highdef 172.22.108.0/25 4242423914 4242421588 64719 4242421817 4242423088
graph test-hackint 172.20.66.64/28 4242423914 4242421588 64719 4242421817 4242423088
graph test-no-grc-feed 172.20.0.81 4242420101 4242423905
# graph test-roa-fail 172.20.120.0/23 4242423622 64915 4242421080
graph test-anycast 172.23.0.53 4242421080 4242422601 4242423914 4242423088 4242421817 4242421588 64719
graph test-no-backbone 10.127.111.128/25 4242421080 4201271111 4242422458
graph test-resolve-ip fd42:d42:d42:80::1 4242421080 64719 4242421588
graph test-resolve-overlapping-announcements fd42:4242:2601:ac12::1 4242421080
