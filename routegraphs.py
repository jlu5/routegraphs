#!/usr/bin/env python3
"""Graph the connectivity FROM a set of ASes to a particular prefix"""

import argparse
import collections
from dataclasses import dataclass, field
import ipaddress
import sqlite3

import graphviz
import networkx

def get_path(dbconn, path_id, start_index=0):
    query = dbconn.execute(
        '''SELECT asn FROM Paths WHERE path_id==? AND list_index >= ? ORDER BY list_index''', (path_id, start_index)
    )
    path = query.fetchall()
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

def asn_paths_to_prefix(dbconn, prefix, asn):
    """
    Get a set of optimal paths from ASN to prefix.

    This returns a tuple (set of paths, whether the path is confirmed from dn42 GRC)
    """
    if isinstance(prefix, str):
        prefix = get_most_specific_prefix(dbconn, prefix)
    collector_paths = dbconn.execute(
        '''SELECT Paths.path_id, Paths.list_index FROM Paths INNER JOIN PrefixPaths ON Paths.path_id==PrefixPaths.path_id
        WHERE asn==? AND prefix_network==? AND prefix_length==?;''',
        (asn, prefix.network_address.packed, prefix.prefixlen)
    )
    minlen = float('inf')
    candidate_paths = collections.defaultdict(set)
    guessed_upstreams = set()
    for collector_path_id, asn_index in collector_paths.fetchall():
        path = get_path(dbconn, collector_path_id, start_index=asn_index)
        if len(path) <= minlen:  # don't bother adding anything with longer length than current shortest
            candidate_paths[len(path)].add(path)
        minlen = min(minlen, len(path))
    if minlen != float('inf'):
        print(f'Known best paths FROM {asn} to {prefix} (len {minlen}):', candidate_paths[minlen])
    else:
        edges = dbconn.execute('''SELECT receiver_asn, sender_asn FROM NeighbourASNs''')
        graph = networkx.Graph()
        for edge in edges:
            graph.add_edge(*edge)
        origin_asns = dbconn.execute(
            '''SELECT asn FROM PrefixOriginASNs WHERE prefix_network=? AND prefix_length=?''',
            (prefix.network_address.packed, prefix.prefixlen)).fetchall()
        for target_asn in origin_asns:
            print(f"Computing paths from {asn} -> {target_asn}")
            paths = set()
            for path in networkx.all_shortest_paths(graph, asn, target_asn):
                if len(path) <= minlen:
                    paths.add(tuple(path))
                    minlen = len(path)
                else:
                    break  # Don't bother adding paths longer than minimum
            candidate_paths[minlen] |= paths

        guessed_upstreams.add(asn)
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

def graph_result(source_asns, result):
    dot = graphviz.Digraph(name=f'Connectivity to {result.prefix}',
        node_attr={'penwidth': '1.5', 'margin': '0.02'})
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
        dot = graph_result(args.source_asn, result)
        dot.save(args.out_filename)


if __name__ == '__main__':
    main()
