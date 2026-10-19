"""Load Research Dataset Service exports with pyarrow, pandas and NetworkX.

Used by internal/research.TestExportsLoadInPythonTools (FR-10.34). Each
argument is KIND=PATH with KIND parquet, csv, jsonl, audit or behavior.
Prints one JSON object: for each library and file kind, the row count (for
GraphML, the number of Call nodes of the audit subgraph or the number of
nodes of the behavior model).
"""

import json
import sys

import networkx
import pandas
import pyarrow
import pyarrow.csv
import pyarrow.json
import pyarrow.parquet


def main(args):
    out = {"versions": {"pyarrow": pyarrow.__version__, "pandas": pandas.__version__, "networkx": networkx.__version__},
           "pyarrow": {}, "pandas": {}, "networkx": {}}
    for arg in args:
        kind, path = arg.split("=", 1)
        if kind == "parquet":
            out["pyarrow"][kind] = pyarrow.parquet.read_table(path).num_rows
            out["pandas"][kind] = len(pandas.read_parquet(path, engine="pyarrow"))
        elif kind == "csv":
            out["pyarrow"][kind] = pyarrow.csv.read_csv(path).num_rows
            out["pandas"][kind] = len(pandas.read_csv(path))
        elif kind == "jsonl":
            out["pyarrow"][kind] = pyarrow.json.read_json(path).num_rows
            out["pandas"][kind] = len(pandas.read_json(path, lines=True))
        elif kind == "audit":
            g = networkx.read_graphml(path)
            out["networkx"][kind] = sum(1 for _, d in g.nodes(data=True) if d.get("kind") == "Call")
        elif kind == "behavior":
            out["networkx"][kind] = networkx.read_graphml(path).number_of_nodes()
        else:
            raise SystemExit("unknown kind " + kind)
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main(sys.argv[1:])
