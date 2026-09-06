import sys, json, hashlib; sys.path.insert(0,"src")
from pathlib import Path
import yaml
from agent_defs import evaluate as ev
ROOT=Path(r"C:/atrx/Agent-Threat-Rule-agent-threat-rules-faf743f")
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
