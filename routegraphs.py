#!/usr/bin/env python3
"""Graph the connectivity FROM a set of ASes to a particular prefix"""

import argparse
import collections
from dataclasses import dataclass, field
import ipaddress
import sqlite3

import graphviz

def get_path(dbconn, path_id, start_asn=None):
    query = dbconn.execute(
        '''SELECT asn FROM Paths WHERE path_id==? ORDER BY list_index''', (path_id,)
    )
    path = query.fetchall()
    if start_asn in path:
        path = path[path.index(start_asn):]
    return tuple(path)

@dataclass
class PathsToPrefixResult:
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network
    paths: set = field(default_factory=set)
    guessed_upstreams: set = field(default_factory=set)

def get_most_specific_prefix(dbconn, prefix_or_ip):
    ipn = ipaddress.ip_network(prefix_or_ip, strict=False)
    if ipn.num_addresses == 1:
        ip = ipn.network_address
        datalength = 16 if ipn.version == 6 else 4
        matching_prefixes = dbconn.execute(
            '''SELECT network, length FROM Prefixes WHERE network<=? AND broadcast_address>=? AND length(network)==? ORDER BY length DESC''',
            (ip.packed, ip.packed, datalength)
        )
        match = matching_prefixes.fetchone()
        if not match:
            raise ValueError(f"No route found for {ipn}")
        result = ipaddress.ip_network(match)
    else:
        prefix_exists = dbconn.execute(
            '''SELECT * FROM Prefixes WHERE network==? AND length==?''',
            (ipn.network_address.packed, ipn.prefixlen))
        if not prefix_exists.fetchone():
            raise ValueError(f"Prefix {ipn} does not exist")
        result = ipn
    print(f'get_most_specific_prefix: Resolving prefix {prefix_or_ip} -> {result}')
    return result

_MAX_SEEN_ASNS = 50
def asn_paths_to_prefix(dbconn, prefix, asn, seen_asns=None):
    """
    Get a set of optimal paths from ASN to prefix.

    This returns a tuple (set of paths, whether the path is confirmed from dn42 GRC)
    """
    #print(f'asn_paths_to_prefix({prefix}, {asn}, seen_asns={seen_asns})')
    seen_asns = seen_asns or set()
    if isinstance(prefix, str):
        prefix = get_most_specific_prefix(dbconn, prefix)
    collector_paths = dbconn.execute(
        '''SELECT Paths.path_id FROM Paths INNER JOIN PrefixPaths ON Paths.path_id==PrefixPaths.path_id
        WHERE asn==? AND prefix_network==? AND prefix_length==?;''',
        (asn, prefix.network_address.packed, prefix.prefixlen)
    )
    minlen = float('inf')
    candidate_paths = collections.defaultdict(set)
    guessed_upstreams = set()
    for collector_path_id in collector_paths.fetchall():
        path = get_path(dbconn, collector_path_id, start_asn=asn)
        if len(path) <= minlen:  # memory saving, ignore everything with longer length than current best
            candidate_paths[len(path)].add(path)
        minlen = min(minlen, len(path))
    if minlen != float('inf'):
        print(f'Known best paths FROM {asn} to {prefix} (len {minlen}):', candidate_paths[minlen])
    else:
        print(f'No known paths FROM {asn} to {prefix}, searching for possible transit upstreams...')
        # Here we look for any ASes Y1, Y2, ... that received a prefix FROM the target AS X.
        # We'll guess that these are upstreams for the X since full transit in dn42 is so common,
        # although we cannot be sure, because we don't have any collector data for X or its downstreams
        possible_transits = dbconn.execute(
            '''SELECT receiver_asn FROM NeighbourASNs WHERE sender_asn=?;''',
            (asn,)
        ).fetchall()
        print(f"Guessing transits for {asn}:", possible_transits)
        if not possible_transits:
            print(f"Could not find any adjacencies for {asn}")

        guessed_upstreams.add(asn)
        next_seen_asns = set(seen_asns) | set(possible_transits) | {asn}
        if len(seen_asns) <= _MAX_SEEN_ASNS:
            for upstream in possible_transits:
                if upstream not in seen_asns:
                    recur_result = asn_paths_to_prefix(
                        dbconn, prefix, upstream, seen_asns=next_seen_asns)
                    # Add the current ASN to the result of the recursive call
                    recur_result.paths = {(asn, *path) for path in recur_result.paths}
                    if recur_result.paths:
                        recur_path_len = len(next(iter(recur_result.paths)))
                        if recur_path_len <= minlen:
                            candidate_paths[recur_path_len] |= recur_result.paths
                        minlen = min(minlen, recur_path_len)
                        guessed_upstreams |= recur_result.guessed_upstreams
        else:
            print(f'Exhausted search space ({len(seen_asns)} > {_MAX_SEEN_ASNS} ASNs), stopping...')

        print(f'Guessed best paths FROM {asn} to {prefix} (len {minlen}):', candidate_paths[minlen])
    return PathsToPrefixResult(prefix, candidate_paths[minlen], guessed_upstreams)

def asns_paths_to_prefix(dbconn, prefix, source_asns):
    summary = PathsToPrefixResult('')
    for source_asn in source_asns:
        result = asn_paths_to_prefix(dbconn, prefix, source_asn)
        summary.prefix = result.prefix
        summary.paths |= result.paths
        summary.guessed_upstreams |= result.guessed_upstreams
    return summary

def get_suggested_asns(dbconn, limit=10):
    return dbconn.execute(
        '''SELECT receiver_asn, COUNT(sender_asn) FROM NeighbourASNs GROUP BY receiver_asn ORDER BY COUNT(sender_asn) DESC LIMIT 10;''').fetchall()

def _row_factory(_cursor, row):
    if len(row) == 1:
        return row[0]
    return row

def getdb(filename):
    dbconn = sqlite3.connect(f'file:{filename}?mode=ro')
    dbconn.row_factory = _row_factory
    return dbconn

def graph(source_asns, result):
    dot = graphviz.Digraph(comment=f'Connectivity to {result.prefix}',
        node_attr={'penwidth': '1.5'})
    dot.attr(rankdir='LR')
    seen_edges = set()

    # This used a named node to avoid https://github.com/xflr6/graphviz/issues/53
    dot.node('dest_prefix', label=str(result.prefix), color='green')

    def _add_edge(n1, n2, **kwargs):
        if (n1, n2) not in seen_edges:
            dot.edge(n1, n2, **kwargs)
            seen_edges.add((n1, n2))

    # with dot.subgraph(name='cluster source ASes') as subgraph:
    for asn in source_asns:
        dot.node(f'AS{asn}', color='blue')

    for path in result.paths:
        assert path, "Got an empty path?"
        current_asn = None
        for idx, current_asn in enumerate(path):
            if idx:
                previous_asn = path[idx-1]
                attrs = {}
                if previous_asn in result.guessed_upstreams:
                    attrs = {'style': 'dashed', 'color': 'grey'}
                elif previous_asn == current_asn:
                    continue
                _add_edge(f'AS{previous_asn}', f'AS{current_asn}', **attrs)

        _add_edge(f'AS{current_asn}', 'dest_prefix')
    return dot

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('db_filename', help='SQLite DB to read FROM')
    parser.add_argument('out_filename', help='file to export .dot graph to')
    parser.add_argument('target', help='target prefix to graph')
    parser.add_argument('source_asn', help='source ASNs to graph FROM', type=int, nargs='+')
    args = parser.parse_args()

    dbconn = getdb(args.db_filename)

    result = asns_paths_to_prefix(dbconn, args.target, args.source_asn)
    if result:
        print("Paths to graph:", result)
        dot = graph(args.source_asn, result)
        dot.save(args.out_filename)


if __name__ == '__main__':
    main()
