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
    python3 routegraphs.py --algo clearnet "$DB" "$DIR/$name".dot "$@"
    dot -Tsvg "$DIR/$name".dot > "$DIR/$name".svg
    echo "Created $DIR/$name.svg"
    set +x
}

set -e
cd "${0%/*}" || exit 1
mkdir -p "${DIR}"
graph test-clearnet-google-dns 8.8.8.8 174 852 20473
graph test-clearnet-telus 75.157.0.0/16 852 6327 812
graph test-clearnet-hetzner 78.46.170.2 3320 63949 20473 53667
