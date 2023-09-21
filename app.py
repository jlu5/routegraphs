#!/usr/bin/env python3
"""Flask frontend to routegraph"""
import datetime
import json
import os
import sqlite3
import traceback

import flask
import networkx

import routegraphs

app = flask.Flask(__name__)

DB_FILENAME = os.environ.get('ROUTEGRAPHS_DB')
if not DB_FILENAME:
    raise ValueError("Must specify ROUTEGRAPHS_DB environment variable")

def wrap_get_backend(f):
    """
    Wrap a function to dynamically load the routegraphs backend and pass it in as the first argument.
    """
    def newf(*args, **kwargs):
        try:
            backend = routegraphs.RouteGraph(DB_FILENAME)
            return f(backend, *args, **kwargs)
        except (OSError, sqlite3.Error):
            traceback.print_exc()
            return 'Failed to load DB'
    # Flask keeps track of the bound function name, which must be unique
    newf.__name__ = f.__name__ + '_wrapped'
    return newf

@wrap_get_backend
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
def index():
    graph_svg = None
    error = None
    if flask.request.args.get('ip_prefix') and flask.request.args.getlist('asn'):
        try:
            # false positive because of decorator adding backend param
            # pylint: disable=no-value-for-parameter
            graph_svg = get_graph()
        except (ValueError, LookupError, networkx.exception.NetworkXException) as e:
            error = str(e)
    try:
        db_last_update = os.stat(DB_FILENAME).st_mtime
        dt = datetime.datetime.utcfromtimestamp(db_last_update)
        db_last_update = dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except OSError as e:
        error = str(e)
        db_last_update = None
    return flask.render_template('routegraphs.html.j2', graph_svg=graph_svg, error=error, db_last_update=db_last_update)

@app.route("/asn-most-peers.json")
@wrap_get_backend
def get_suggested_asns(backend):
    data = backend.get_suggested_asns()
    return json.dumps(data)
