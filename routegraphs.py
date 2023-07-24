#!/usr/bin/env python3
"""Graph the connectivity FROM a set of ASes to a particular prefix"""

import argparse
import collections
from dataclasses import dataclass, field
import enum
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
# From https://bgp.tools/kb/what-is-a-upstream 2023-07-23
TIER1_ASNS = frozenset({
    6762, # Sparkle
    12956, # Telefonica
    2914, # NTT
    3356, # Lumen
    6453, # TATA
    701, # Verizon
    6461, # Zayo
    3257, # GTT
    1299, # Telia
    3491, # PCCW
    7018, # AT&T
    3320, # DTAG
    5511, # Orange
    6830, # Liberty Global
    7922, # Comcast
    174, # Cogent
    6939, # HE
})

class AdjacencyAlgorithm(enum.Enum):
    dn42 = 0
    clearnet = 1

def _make_placeholders(lst):
    return ', '.join('?' for _ in lst)

def _get_shortest_sublists(lst):
    minlen = float('inf')
    result = set()
    for sublst in lst:
        if len(sublst) < minlen:
            minlen = len(sublst)
            result.clear()
            result.add(sublst)
        elif len(sublst) == minlen:
            result.add(sublst)
    return (minlen, result)

def asn_paths_to_prefix(dbconn, prefix, asn, algo, seen_asns=None):
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
    elif algo == AdjacencyAlgorithm.dn42:
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
                        dbconn, prefix, upstream, algo, seen_asns=next_seen_asns)
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
    elif algo == AdjacencyAlgorithm.clearnet:
        # Like the bgp.tools methodology:
        # - Reverse these paths; assume this is how other ASes will reach the target once they hit a T1
        # - Then graph how the source AS can reach any of these T1s
        origin_ases = dbconn.execute(
            '''SELECT asn FROM PrefixOriginASNs WHERE prefix_network=? AND prefix_length=?''',
            (prefix.network_address.packed, prefix.prefixlen)
        ).fetchall()
        print(f'origin ases for {prefix}: {origin_ases}')

        # Find all ways that T1s can reach the origin ASes for the dest prefix
        # This looks for any path segments containing a T1 AS and an origin ASN after it, which means that the T1 will likely consider the origin as a downstream
        #relevant_t1s = {as_path[-1] for as_path in source_paths_to_t1s}
        #TODO
        relevant_t1s = TIER1_ASNS
        t1_path_ids_to_origin = dbconn.execute(
            # A is the list entry of a T1, B is the list entry of the target ASN
            f'''SELECT A.path_id, A.list_index, B.list_index FROM Paths A, Paths B WHERE A.path_id == B.path_id AND A.asn IN ({_make_placeholders(relevant_t1s)})
            AND B.asn IN ({_make_placeholders(origin_ases)}) AND B.list_index > A.list_index;''',
        (*relevant_t1s, *origin_ases)).fetchall()
        t1_paths_to_origin = set()
        for path_id, t1_list_index, origin_asn_list_index in t1_path_ids_to_origin:
            path_fragment = dbconn.execute(
                '''SELECT asn FROM Paths WHERE path_id == ? AND list_index >= ? AND list_index <= ? ORDER BY list_index''',
                (path_id, t1_list_index, origin_asn_list_index)).fetchall()
            t1_paths_to_origin.add(tuple(path_fragment))
        print(f"T1 paths to origins {origin_ases}: {t1_paths_to_origin}")

        t1_to_origin_by_as = collections.defaultdict(set)
        # TODO
        for t1_path_to_origin in t1_paths_to_origin:
            t1_to_origin_by_as[t1_path_to_origin[0]].add(t1_path_to_origin)
        print(f"T1 paths to origins {origin_ases}: {t1_to_origin_by_as}")
        shortest_t1_to_origin = {}
        for t1, paths in t1_to_origin_by_as.items():
            # neighbour_t1s = dbconn.execute(
            #     f'''SELECT sender_asn from NeighbourASNs where receiver_asn=? AND sender_asn IN ({_make_placeholders(TIER1_ASNS)})''',
            #     (asn, *TIER1_ASNS)).fetchall()
            # for neighbour_t1 in neighbour_t1s:
            #     if neighbour_t1_paths := t1_to_origin_by_as.get(neighbour_t1):
            #         paths = paths | {(asn, *path) for path in neighbour_t1_paths}
            _, shortest_t1_to_origin[t1] = _get_shortest_sublists(paths)
        print(f"Shortest T1 paths to origins {origin_ases}: {shortest_t1_to_origin}")

        # Find all ways that the requested (source) ASN can reach a T1.
        if asn in TIER1_ASNS:
            asn_to_origin = shortest_t1_to_origin.get(asn)
            if asn_to_origin:
                minlen = len(next(iter(asn_to_origin)))
                candidate_paths[minlen] |= asn_to_origin
                # TODO fix else case, e.g. AS3320
            # else:
                # neighbours = dbconn.execute(
                #      '''SELECT sender_asn FROM NeighbourASNs WHERE receiver_asn=? AND sender_asn IN ({});''', (asn,)).fetchall()
                # source_paths_to_t1s = {(asn, neighbour) for neighbour in neighbours}
        else:
            source_asns_path_ids_to_t1s = dbconn.execute(
                # A is the list entry of a T1, B is the list entry of the target ASN
                f'''SELECT A.path_id, A.list_index, B.list_index FROM Paths A, Paths B WHERE A.path_id == B.path_id AND A.asn IN ({_make_placeholders(TIER1_ASNS)})
                AND B.asn = ?;''',
                (*TIER1_ASNS, asn)
            ).fetchall()
            source_paths_to_t1s = set()
            for path_id, t1_list_index, source_asn_list_index in source_asns_path_ids_to_t1s:
                low_idx = min(t1_list_index, source_asn_list_index, )
                high_idx = max(t1_list_index, source_asn_list_index, )
                path_fragment = dbconn.execute(
                    '''SELECT asn FROM Paths WHERE path_id == ? AND list_index >= ? AND list_index <= ? ORDER BY list_index''',
                    (path_id, low_idx, high_idx)).fetchall()
                if path_fragment[0] != asn:
                    path_fragment.reverse()
                source_paths_to_t1s.add(tuple(path_fragment))
            print(f'Paths from requested source {asn} to Tier 1 ISPs:', source_paths_to_t1s)
            guessed_upstreams.add(asn)

            print('minlen: ', minlen)
            minlen, source_path_to_t1s = _get_shortest_sublists(source_paths_to_t1s)
            minlen += min(map(len, t1_paths_to_origin)) - 1
            for source_path_to_t1 in source_path_to_t1s:
                t1 = source_path_to_t1[-1]
                for t1_path_to_origin in shortest_t1_to_origin.get(t1, set()):
                    candidate_paths[minlen].add(source_path_to_t1 + t1_path_to_origin)

    else:
        raise ValueError(f"Unknown adjacency algorithm {algo}")
    return PathsToPrefixResult(prefix, candidate_paths[minlen], guessed_upstreams)

def asns_paths_to_prefix(dbconn, prefix, source_asns, algo=AdjacencyAlgorithm.dn42):
    summary = PathsToPrefixResult('')
    for source_asn in source_asns:
        result = asn_paths_to_prefix(dbconn, prefix, source_asn, algo=algo)
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
    parser.add_argument('--algo', help='algorithm to guess paths not in the MRT dump',
                        choices=[attr for attr in dir(AdjacencyAlgorithm) if not attr.startswith('_')],
                        default='dn42')
    parser.add_argument('target', help='target prefix to graph')
    parser.add_argument('source_asn', help='source ASNs to graph FROM', type=int, nargs='+')
    args = parser.parse_args()

    dbconn = getdb(args.db_filename)

    result = asns_paths_to_prefix(dbconn, args.target, args.source_asn, algo=getattr(AdjacencyAlgorithm, args.algo))
    if result:
        print("Paths to graph:", result)
        dot = graph(args.source_asn, result)
        dot.save(args.out_filename)


if __name__ == '__main__':
    main()
