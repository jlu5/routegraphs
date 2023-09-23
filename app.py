#!/usr/bin/env python3
"""Flask frontend to routegraph"""
from dataclasses import dataclass
import datetime
import os
import socket
import sqlite3
import traceback
from typing import Any, Iterable, List

import flask
import networkx

import routegraphs

app = flask.Flask(__name__)

DB_FILENAME = os.environ.get('ROUTEGRAPHS_DB')
if not DB_FILENAME:
    raise ValueError("Must specify ROUTEGRAPHS_DB environment variable")

_EMOJI_TRUE = '✅'
_EMOJI_FALSE = '❌'
_EMOJI_UNKNOWN = '❓'
@dataclass
class Table():
    name: str
    headings: List[str]
    data: List[Iterable[Any]]  # list of rows
    true_emoji: str = _EMOJI_TRUE
    false_emoji: str = _EMOJI_FALSE
    heading_type: str = 'h2'

def wrap_get_backend(f):
    """
    Wrap a function to dynamically load the routegraphs backend and pass it in as the first argument.
    """
    def newf(*args, **kwargs):
        try:
            backend = routegraphs.RouteGraph(DB_FILENAME)
            return f(backend, *args, **kwargs)
        except sqlite3.OperationalError:
            traceback.print_exc()
            return render_error('Failed to query DB')
        except (OSError, sqlite3.Error):
            traceback.print_exc()
            return render_error('Failed to load DB')
    # Flask keeps track of the bound function name, which must be unique
    newf.__name__ = f.__name__ + '_wrapped'
    return newf

def render_error(error_str=None):
    return flask.render_template('error.html.j2', error=error_str)

def get_graph(backend):
    target_prefix = flask.request.args.get('ip_prefix')

    asns = flask.request.args.getlist('asn')
    if not asns:
        raise ValueError('No source ASNs specified')
    try:
        asns = list(map(int, asns))
    except ValueError as e:
        raise ValueError(f'Invalid ASN in request: {asns!r}') from e

    routegraph_data = backend.asns_paths_to_prefix(target_prefix.strip(), asns)
    dot = backend.graph_result(asns, routegraph_data)
    return dot.pipe(format='svg').decode('utf-8')

@app.route("/")
@wrap_get_backend
def index(backend):
    graph_svg = None
    error = None
    if flask.request.args.get('ip_prefix') and flask.request.args.getlist('asn'):
        try:
            graph_svg = get_graph(backend)
        except (ValueError, LookupError, networkx.exception.NetworkXException) as e:
            return render_error(e)
    try:
        # TODO: move this into a helper
        db_last_update = os.stat(DB_FILENAME).st_mtime
        dt = datetime.datetime.utcfromtimestamp(db_last_update)
        db_last_update = dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except OSError as e:
        return render_error(e)

    def _add_asn_button(asn):
        return f'<button onclick="addAsn({asn})">Add</button>'

    origin_asns_table = None
    if prefix := flask.request.args.get('ip_prefix'):
        prefix_asns = []
        try:
            ipprefix = backend.get_most_specific_prefix(prefix)
        except ValueError:
            return render_error(f'Invalid CIDR {prefix}')
        for asn in backend.dbconn.execute(
                '''SELECT asn FROM PrefixOriginASNs
                WHERE prefix_network == ? AND prefix_length == ?''',
                (ipprefix.network_address.packed, ipprefix.prefixlen)):
            prefix_asns.append((
                _get_asn_link(asn) + _add_asn_button(asn),
            ))
        origin_asns_table = Table(f'Origin ASNs for {ipprefix}',
            ['Origin ASNs'],
            prefix_asns,
            heading_type='h3'
        )

    suggested_asns = []
    for asn, peercount in backend.get_suggested_asns():
        suggested_asns.append((
            _get_asn_link(asn) + _add_asn_button(asn),
            peercount
        ))
    suggested_asns_table = Table(
        'Quick reference: largest ASes',
        ['ASN', 'Peer count'],
        suggested_asns,
        heading_type='h3'
    )

    return flask.render_template(
        'routegraphs.html.j2', graph_svg=graph_svg, error=error, db_last_update=db_last_update,
        origin_asns_table=origin_asns_table, suggested_asns_table=suggested_asns_table)

def _get_asn_link(asn):
    return f'<a href="/asn/{asn}">{asn}</a>'

@app.route("/asns")
@wrap_get_backend
def get_asns(backend):
    data = []
    for row in backend.dbconn.execute(
        '''SELECT local_asn, name, COUNT(peer_asn), direct_feed FROM
        (SELECT receiver_asn AS local_asn, sender_asn AS peer_asn
        FROM NeighbourASNs UNION
        SELECT sender_asn AS local_asn, receiver_asn AS peer_asn
        FROM NeighbourASNs)
        INNER JOIN ASNs on ASNs.asn = local_asn
        GROUP BY local_asn ORDER BY COUNT(peer_asn) DESC;'''):
        asn, name, n_upstreams, direct_feed = row
        direct_feed = bool(direct_feed)
        data.append((_get_asn_link(asn), name, n_upstreams, direct_feed))
    return flask.render_template(
        'table-generic.html.j2',
        page_title='All ASNs',
        tables=[
            Table('All Visible Networks',
                  ['AS Number', 'AS Name', '# downstreams', 'Route server feed?'],
                  data)
        ])

@app.route("/asn/<asn>")
@wrap_get_backend
def get_asn_info(backend, asn):
    asn_prefixes = []
    try:
        asn = int(asn)
    except ValueError:
        return render_error(f'Invalid ASN {asn}')
    as_name = backend.dbconn.execute(
        '''SELECT name FROM ASNs WHERE asn == ?;''', (asn,)).fetchone()
    for row in backend.dbconn.execute(
        '''SELECT prefix_network, prefix_length FROM PrefixOriginASNs
        WHERE asn == ?;''', (asn,)):
        network_binary, prefix_length = row
        network = socket.inet_ntop(
            socket.AF_INET6 if len(network_binary) == 16 else socket.AF_INET,
            network_binary)
        cidr = f'{network}/{prefix_length}'
        cidr_link = f'<a href="/?ip_prefix={cidr}">{cidr}</a>'
        asn_prefixes.append((cidr_link,))

    direct_feeds = set(backend.dbconn.execute(
        '''SELECT asn FROM ASNs WHERE direct_feed == 1'''))

    asn_peers = []
    for row in backend.dbconn.execute(
        '''SELECT DISTINCT peer_asn, name, MAX(receives_transit), MAX(sends_transit) FROM
        (SELECT receiver_asn AS local_asn, sender_asn AS peer_asn, transit AS receives_transit, 0 AS sends_transit
        FROM NeighbourASNs UNION
        SELECT sender_asn AS local_asn, receiver_asn AS peer_asn, 0 AS receives_transit, transit AS sends_transit
        FROM NeighbourASNs)
        INNER JOIN ASNs on ASNs.asn = peer_asn
        WHERE local_asn = ? AND peer_asn <> local_asn
        GROUP BY peer_asn''', (asn,)):
        peer_asn, peer_as_name, receives_transit, sends_transit = row
        # We only know for sure whether an ASN receives transit if they are a direct feed...
        if sends_transit:
            sends_transit = _EMOJI_TRUE
        elif peer_asn in direct_feeds:
            sends_transit = _EMOJI_FALSE
        else:
            sends_transit = _EMOJI_UNKNOWN

        if receives_transit:
            receives_transit = _EMOJI_TRUE
        elif asn in direct_feeds:
            receives_transit = _EMOJI_FALSE
        else:
            receives_transit = _EMOJI_UNKNOWN
        asn_peers.append((_get_asn_link(peer_asn), peer_as_name, receives_transit, sends_transit))

    return flask.render_template(
        'table-generic.html.j2',
        page_title=f'AS info for {asn}',
        tables=[
            Table(f'{asn} - {as_name} Prefixes',
                  ['Prefix'],
                  asn_prefixes),
            Table(f'{asn} - {as_name} Peers',
                  ['Peer ASN', 'Peer Name', 'Receives transit?', 'Sends transit?'],
                  asn_peers)
        ])
