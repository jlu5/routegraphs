#!/usr/bin/env python3
"""Graph the connectivity FROM a set of ASes to a particular prefix"""

import argparse
import collections
from dataclasses import dataclass, field
import html
import ipaddress
import sqlite3

import graphviz
import networkx

@dataclass
class PathsToPrefixResult:
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network
    paths: set = field(default_factory=set)
    guessed_upstreams: set = field(default_factory=set)

class RouteGraph():
    def __init__(self, db_filename):
        self.dbconn = sqlite3.connect(f'file:{db_filename}?mode=ro')
        self.dbconn.row_factory = self._row_factory

        edges = self.dbconn.execute('''SELECT receiver_asn, sender_asn FROM NeighbourASNs''')
        self.graph = networkx.Graph()
        for edge in edges:
            self.graph.add_edge(*edge)

    @staticmethod
    def _row_factory(_cursor, row):
        """Custom sqlite3 row factory to flatten single-item queries and escape text outputs"""
        new_row = (html.escape(item) if isinstance(item, str) else item for item in row)
        if len(row) == 1:
            return next(new_row)
        return tuple(new_row)

    def get_path(self, path_id, start_index=0):
        query = self.dbconn.execute(
            '''SELECT asn FROM Paths WHERE path_id==? AND list_index >= ? ORDER BY list_index''', (path_id, start_index)
        )
        path = query.fetchall()
        return tuple(path)

    def get_most_specific_prefix(self, prefix_or_ip):
        ipn = ipaddress.ip_network(prefix_or_ip, strict=False)
        if ipn.num_addresses == 1:
            ip = ipn.network_address
            datalength = 16 if ipn.version == 6 else 4
            matching_prefixes = self.dbconn.execute(
                '''SELECT network, length FROM Prefixes WHERE network<=? AND broadcast_address>=? AND length(network)==? ORDER BY length DESC''',
                (ip.packed, ip.packed, datalength)
            )
            match = matching_prefixes.fetchone()
            if not match:
                raise ValueError(f"No route found for {ipn}")
            result = ipaddress.ip_network(match)
        else:
            prefix_exists = self.dbconn.execute(
                '''SELECT * FROM Prefixes WHERE network==? AND length==?''',
                (ipn.network_address.packed, ipn.prefixlen))
            if not prefix_exists.fetchone():
                raise ValueError(f"Prefix {ipn} does not exist")
            result = ipn
        print(f'get_most_specific_prefix: Resolving prefix {prefix_or_ip} -> {result}')
        return result

    def asn_paths_to_prefix(self, prefix, asn):
        """
        Get a set of optimal paths from ASN to prefix.

        Results are returned in PathsToPrefixResult class instances
        """
        if isinstance(prefix, str):
            prefix = self.get_most_specific_prefix(prefix)
        collector_paths = self.dbconn.execute(
            '''SELECT Paths.path_id, Paths.list_index FROM Paths INNER JOIN PrefixPaths ON Paths.path_id==PrefixPaths.path_id
            WHERE asn==? AND prefix_network==? AND prefix_length==?;''',
            (asn, prefix.network_address.packed, prefix.prefixlen)
        )
        minlen = float('inf')
        candidate_paths = collections.defaultdict(set)
        guessed_upstreams = set()
        for collector_path_id, asn_index in collector_paths.fetchall():
            path = self.get_path(collector_path_id, start_index=asn_index)
            if len(path) <= minlen:  # don't bother adding anything with longer length than current shortest
                candidate_paths[len(path)].add(path)
            minlen = min(minlen, len(path))
        if minlen != float('inf'):
            print(f'Known best paths FROM {asn} to {prefix} (len {minlen}):', candidate_paths[minlen])
        else:
            origin_asns = self.dbconn.execute(
                '''SELECT asn FROM PrefixOriginASNs WHERE prefix_network=? AND prefix_length=?''',
                (prefix.network_address.packed, prefix.prefixlen)).fetchall()
            for target_asn in origin_asns:
                print(f"Computing paths from {asn} -> {target_asn}")
                paths = set()
                for path in networkx.all_shortest_paths(self.graph, asn, target_asn):
                    if len(path) <= minlen:
                        paths.add(tuple(path))
                        minlen = len(path)
                    else:
                        break  # Don't bother adding paths longer than minimum
                candidate_paths[minlen] |= paths

            guessed_upstreams.add(asn)
            print(f'Guessed best paths FROM {asn} to {prefix} (len {minlen}):', candidate_paths[minlen])
        return PathsToPrefixResult(prefix, candidate_paths[minlen], guessed_upstreams)

    def asns_paths_to_prefix(self, prefix, source_asns):
        summary = PathsToPrefixResult('')
        for source_asn in source_asns:
            result = self.asn_paths_to_prefix(prefix, source_asn)
            summary.prefix = result.prefix
            summary.paths |= result.paths
            summary.guessed_upstreams |= result.guessed_upstreams
        return summary

    def get_suggested_asns(self, limit=10):
        return self.dbconn.execute(
            f'''SELECT local_asn, COUNT(peer_asn) FROM
        (SELECT receiver_asn AS local_asn, sender_asn AS peer_asn
        FROM NeighbourASNs UNION
        SELECT sender_asn AS local_asn, receiver_asn AS peer_asn
        FROM NeighbourASNs)
        GROUP BY local_asn ORDER BY COUNT(peer_asn) DESC
        LIMIT {int(limit)}''').fetchall()

    @staticmethod
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

    routegraph = RouteGraph(args.db_filename)

    result = routegraph.asns_paths_to_prefix(args.target, args.source_asn)
    if result:
        print("Paths to graph:", result)
        dot = routegraph.graph_result(args.source_asn, result)
        dot.save(args.out_filename)


if __name__ == '__main__':
    main()
