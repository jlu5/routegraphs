#!/usr/bin/env python3
"""Flask frontend to routegraph"""
import datetime
import json
import os

import flask

import routegraphs

app = flask.Flask(__name__)

DB_FILENAME = os.environ.get('ROUTEGRAPHS_DB')
if not DB_FILENAME:
    raise ValueError("Must specify ROUTEGRAPHS_DB environment variable")

def get_graph():
    target_prefix = flask.request.args.get('ip_prefix')

    asns = flask.request.args.getlist('asn')
    if not asns:
        raise ValueError('No source ASNs specified')
    try:
        asns = list(map(int, asns))
    except ValueError as e:
        raise ValueError(f'Invalid ASN in request: {asns!r}') from e

    try:
        dbconn = routegraphs.getdb(DB_FILENAME)
    except OSError:
        return 'Failed to load DB'

    routegraph_data = routegraphs.asns_paths_to_prefix(dbconn, target_prefix.strip(), asns)
    dot = routegraphs.graph(asns, routegraph_data)
    return dot.pipe(format='svg').decode('utf-8')

@app.route("/")
def index():
    graph_svg = None
    error = None
    if flask.request.args.get('ip_prefix') and flask.request.args.getlist('asn'):
        try:
            graph_svg = get_graph()
        except Exception as e:
            error = str(e)
    try:
        db_last_update = os.stat(DB_FILENAME).st_mtime
        dt = datetime.datetime.utcfromtimestamp(db_last_update)
        db_last_update = dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except OSError as e:
        error = str(e)
    return flask.render_template('routegraphs.html.j2', graph_svg=graph_svg, error=error, db_last_update=db_last_update)

@app.route("/asn-most-peers.json")
def get_suggested_asns():
    try:
        dbconn = routegraphs.getdb(DB_FILENAME)
    except OSError:
        return 'Failed to load DB'
    data = routegraphs.get_suggested_asns(dbconn)
    return json.dumps(data)
