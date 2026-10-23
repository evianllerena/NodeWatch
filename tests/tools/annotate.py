"""Print failing tests from a tests/run.py --report file as GitHub Actions error annotations."""

import json
import sys

r = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"python={r.get('python')} run={r['run']} failures={len(r['failures'])} errors={len(r['errors'])}")
for d in r.get("details", [])[:40]:
    lines = [ln.strip() for ln in d["traceback"].strip().splitlines() if ln.strip()][-3:]
    msg = " | ".join(lines).replace("%", "%25")
    print(f"::error title={d['kind']}: {d['test']}::{msg[:900]}")
