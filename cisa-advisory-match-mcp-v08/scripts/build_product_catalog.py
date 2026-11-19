"""Build a local advisory product candidate index from an operator-supplied snapshot."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from advisory_matcher.catalog_index import build_catalog
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('snapshot',help='Local official CSAF checkout (origin must be verified by operator)')
p.add_argument('output',help='New SQLite output path; existing output will not be overwritten')
p.add_argument('--revision',default='operator-provided-unverified',help='Exact recorded source revision, if verified')
a=p.parse_args(); print(json.dumps(build_catalog(a.snapshot,a.output,revision=a.revision),indent=2))
