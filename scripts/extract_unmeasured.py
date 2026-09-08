"""Collect the ATR regex conditions that carry no timing measurement.

Produces ``unmeasured-cfg.json`` in the working directory, which is the input
``hazards.json`` names for the CFG condition sweep. Run it from the repository
root so that path resolves where the record says it does:

    python scripts/extract_unmeasured.py <path to a pinned ATR checkout>

The corpus root is an argument rather than a constant because this file ships in
the package and the checkout lives wherever the operator put it.
"""
import sys, json, hashlib; sys.path.insert(0,"src")
from pathlib import Path
import yaml
from agent_defs import evaluate as ev
if len(sys.argv) != 2:
    raise SystemExit(__doc__)
ROOT=Path(sys.argv[1])
out={}; total=0; ported_total=0
for f in sorted((ROOT/"rules").rglob("*.yaml")):
    d=yaml.safe_load(f.read_text(encoding="utf-8"))
    if not isinstance(d,dict): continue
    rid=d.get("id","")
    for cond in (d.get("detection",{}).get("conditions") or []):
        if not isinstance(cond,dict) or cond.get("operator")!="regex": continue
        v=cond.get("value")
        if not isinstance(v,str): continue
        total+=1
        ported,notes=ev.port_utf16_surrogates(v)
        if notes: ported_total+=1
        for text in {v, ported}:
            if ev.measurement_for_pattern(text) is None:
                out.setdefault(text, set()).add(rid)
print(f"raw regex conditions in corpus : {total}")
print(f"conditions needing a UTF-16 port: {ported_total}")
print(f"distinct UNMEASURED strings     : {len(out)}")
rows=[{"pattern":k,"rules":sorted(v),
       "fingerprint":hashlib.sha256(k.encode('utf-8','surrogatepass')).hexdigest()[:16]}
      for k,v in sorted(out.items())]
Path("unmeasured-cfg.json").write_text(json.dumps(rows, indent=1, ensure_ascii=False), encoding="utf-8")
print("rules touched:", len({r for v in out.values() for r in v}))
