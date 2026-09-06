import sys; sys.path.insert(0,"src")
from pathlib import Path
from agent_defs.loaders import atr
from agent_defs.model import Surface
res=atr.load(Path(r"C:/atrx/Agent-Threat-Rule-agent-threat-rules-faf743f"),
             source_rev="faf743fee8a5018467959ec8ea7ccdb1a1aab333")
run=[r for r in res.rules if r.runnable]
cfg=[r for r in res.rules if (b:=r.binding(Surface.CFG)) and b.eligible]
conds=sum(len(r.binding(Surface.CFG).conditions) for r in cfg)
print(f"flat runnable : {len(run)}")
print(f"CFG eligible  : {len(cfg)}")
print(f"CFG conditions: {conds}")
