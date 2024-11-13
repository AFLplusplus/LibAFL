#!/usr/bin/python3

import json
import os
import networkx as nx
import sys

cfg = dict()

if "CFG_OUTPUT_PATH" not in os.environ:
    sys.exit("CFG_OUTPUT_PATH not set")

input_path = os.environ["CFG_OUTPUT_PATH"]


for dirpath, _, files in os.walk(input_path):
    for x in files:
        if x.endswith(".cfg"):
            cfg[x] = json.load(open(os.path.join(dirpath, x)))

G = nx.DiGraph()
GG = nx.DiGraph()
# First add all the edges

node_ids = 0
f_ids = 0

fname2id = dict()

for mname, module in cfg.items():
    fnname2SG = dict()
    # First, add all the intra-procedural edges

    for fname, v in module["edges"].items():
        if fname not in fname2id:
            GG.add_node(f_ids, label=fname)
            fname2id[fname] = f_ids
            f_ids += 1

        sz = len(v)
        for idx in range(node_ids, node_ids + sz):
            G.add_node(idx)
            G.nodes[idx]["label"] = mname + " " + fname + " " + str(idx - node_ids)
        node_id_list = list(range(node_ids, node_ids + sz))
        node_ids += sz
        SG = G.subgraph(node_id_list)
        fnname2SG[fname] = SG
        for src, dsts in enumerate(v):
            for item in dsts:
                G.add_edge(node_id_list[src], node_id_list[item])

    # Next, build inter-procedural edges
    for fname, calls in module["calls"].items():
        for idx, target_fns in calls.items():
            # G.nodes isn't sorted

            src = sorted(fnname2SG[fname].nodes())[0] + int(idx)
            for target_fn in target_fns:
                if target_fn in fnname2SG:
                    offset = module["entries"][target_fn]

                    dst = sorted(fnname2SG[target_fn].nodes)[0] + offset

                    # Now we have 2 index, build the edge
                    G.add_edge(src, dst)
                    GG.add_edge(fname2id[fname], fname2id[target_fn])

nx.nx_agraph.write_dot(G, "cfg.xdot")
nx.nx_agraph.write_dot(GG, "cg.xdot")
