<!-- Design round 2 -->

Verification notes:

All shell verification ran in `C:/Users/yuezh/PycharmProjects/agent-defs` with `/c/Program Files/PowerShell/7/pwsh`, profiles disabled. These are fresh round 2 checks of existing behavior, not verification of an implementation diff.

1. Admission, settings preservation, hook behavior, and scan completeness:

~~~powershell
$env:PYTHONPATH = 'src'
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -m pytest -q tests/test_model_and_lanes.py tests/test_claude_settings_safety.py tests/test_claude_code_hook.py tests/test_claude_hook_failures.py tests/test_hook_integration.py tests/test_scan_completeness.py
~~~

Outcome: exit 0; **190 passed in 15.21 s**. These tests establish current adapter and installer behavior. They do not establish asynchronous delivery, a proposed activation guard, or live harness enforcement.

2. Recompute the supplied 0 KB fit, construct an upward-drift counterexample, and check the lane arithmetic:

~~~powershell
$env:PYTHONPATH = 'src'
@'
import json
from agent_defs.lanes import trials_needed, u95_zero_hits
x = [1, 8, 32, 64, 128, 231, 427]
y = [.102, .120, .156, .191, .306, .439, .675]
xm, ym = sum(x)/len(x), sum(y)/len(y)
b = sum((n-xm)*(v-ym) for n,v in zip(x,y))/sum((n-xm)**2 for n in x)
a = ym-b*xm
r2 = 1-sum((v-a-b*n)**2 for n,v in zip(x,y))/sum((v-ym)**2 for v in y)
drift = [v-(.100+.000300*n) for n,v in zip(x,y)]
assert all(right > left for left,right in zip(drift,drift[1:]))
print(json.dumps({'observed_slope_ms': b*1000, 'observed_r2': r2, 'assumed_true_slope_ms': .3, 'compatible_increasing_drift_s': drift, 'fraction_of_fitted_slope_from_drift': 1-.000300/b}))
for n in [466, 598, 2833, 2995]:
    print(json.dumps({'trials': n, 'zero_hit_u95': u95_zero_hits(n), 'zero_hit_u95_percent': 100*u95_zero_hits(n)}))
print(json.dumps({'ADVISE_trials_needed': trials_needed(.005), 'DENY_trials_needed': trials_needed(.001)}))
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

Outcome: exit 0. Observed slope **1.348016549 ms/rule**, R² **0.995996457**. A hypothetical true slope of 0.300 ms/rule plus strictly increasing drift reproduces every supplied observation; drift accounts for **77.745%** of the fitted slope in that construction. Zero-hit upper bounds: **0.640799% at 466**, **0.499706% at 598**, **0.105688% at 2,833**, and **0.099974% at 2,995**. Required clean counts: ADVISE **598**, DENY **2,995**. The construction demonstrates non-identification; it does not establish that drift actually occurred.

3. Probe registration, real worker dispatch, and RECORD logging without touching installed settings:

~~~powershell
$env:PYTHONPATH = 'src'
@'
import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from agent_defs import evaluate as e
from agent_defs.hooks import _claude_code_impl as h
from agent_defs.hooks._settings import merge
from agent_defs.model import Surface
with TemporaryDirectory() as tmp:
    config = h.default_config()
    log = Path(tmp) / 'findings.jsonl'
    config['log_path'] = str(log)
    merged, _ = merge('{}', h.hook_spec(Path(tmp) / 'config.json'), h.owned)
    print(json.dumps({'registered_events': sorted(json.loads(merged)['hooks']), 'starter_surfaces': sorted({r.surface.value for r in h.STARTER_RULES})}))
    real = e._run_worker
    for event, value in [('PreToolUse', 'ordinary'), ('PostToolUse', 'ordinary'), ('PostToolUse', {'a': 'ordinary', 'b': 'ordinary'})]:
        field = 'tool_input' if event == 'PreToolUse' else 'tool_response'
        with patch.object(e, '_run_worker', wraps=real) as worker:
            response = h.process({'hook_event_name': event, field: value}, config)
        print(json.dumps({'event': event, 'structured': isinstance(value, dict), 'workers': worker.call_count, 'response': response, 'log_exists': log.exists()}))
    rule = h.STARTER_RULES[0]
    response = h.process({'hook_event_name': 'PostToolUse', 'session_id': 'probe-session', 'tool_use_id': 'probe-tool', 'tool_response': rule.examples_positive[0]}, config, [rule])
    row = json.loads(log.read_text())
    print(json.dumps({'record_match_response': response, 'log_event_keys': sorted(row), 'finding_keys': sorted(row['records'][0])}))
    with patch.object(h, 'scan', return_value=e.ScanResult((), 0, 1, 0, False)):
        response = h.process({'hook_event_name': 'PostToolUse', 'tool_response': 'ordinary'}, config, [rule])
    print(json.dumps({'record_incomplete_response': response}))
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

Outcome: exit 0. Both events are registered although all starter rules are OUT. Starter Pre starts **0 workers**, scalar Post **1**, and two-leaf Post **2**. All three clean cases return `{}` and create no log. A completed RECORD match returns `{}`; its log has neither session nor tool-call identity even when supplied. An injected incomplete result returns both model context and a user warning in RECORD. Matching used real workers; the incomplete-result case deliberately substituted a result to exercise response policy.

4. Validate and replace the review from a temporary file in the repository root:

~~~powershell
@'
import os
from pathlib import Path
root = Path('C:/Users/yuezh/PycharmProjects/agent-defs').resolve()
temporary = root / '.Review-Codex-design-round2.tmp'
target = root / 'Review-Codex.md'
data = temporary.read_bytes()
review = data.decode('utf-8')
assert review.startswith('<!-- Design round 2 -->\n\nVerification notes:\n')
assert review.splitlines().count('Verification status: VERIFIED') == 1
assert review.splitlines().count('Commit verdict: BLOCK') == 1
assert temporary.parent.resolve() == target.parent.resolve() == root
os.replace(temporary, target)
assert target.read_bytes() == data
assert not temporary.exists()
print('Review format checks passed; same-directory replacement and exact readback passed.')
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

Outcome: exit 0; format checks, same-directory replacement, and exact readback passed.

The official Claude Code hooks reference was fetched on 2026-09-06; relevant links appear beside the documentation claims below. Neither root instruction file exists, so the supplied baseline instructions apply. The cited 2,833-file inventory and its plan were not located in this checkout; its count is treated as your supplied premise, not independently verified evidence. No original latency run, full corpus calibration, or live asynchronous harness session was repeated. Initial `git status --short` showed only ` M Review-Codex.md`. This review changes that file only; no installed settings, commit, push, or destructive Git operation was performed.

Verification status: VERIFIED

Commit verdict: BLOCK

This verdict applies to the round 2 design **as worded**, specifically the directional inference in disagreement 1 and the inference from present admission limits to performance irrelevance in disagreement 3. There is no implementation diff to approve or reject. I endorse the revised sequence below.

**1. I reject the direction argument; I accept the descriptive affine-fit claim.**

Upward drift means later measurements become more expensive. Superlinearity means their marginal cost increases with rule count. The first does not imply the second. In `observed_cost(n) = true_cost(n) + drift(time(n))`, drift proportional to `n` adds to the slope and leaves an affine relationship exactly affine. Even drift linear in run index need not be convex in `n`: your tested counts are very unevenly spaced.

The counterexample uses your actual 0 KB observations. Suppose true cost is `0.100 + 0.000300*n` seconds. Add drift of `[0.0017, 0.0176, 0.0464, 0.0718, 0.1676, 0.2697, 0.4469]` seconds at the seven successive measurements. That drift is strictly increasing and accounts for about 78% of the observed fitted slope, while reproducing the same R² of 0.996. It requires no pattern-mix explanation. It is a possible decomposition, not a diagnosis of the experiment.

An affine fit could count against a *specified* drift model that predicts detectable positive curvature, given assumptions about baseline cost, time spacing, noise, and pattern mix. Those assumptions are absent here. Monotone upward drift as a class does not predict that curvature. Therefore I would not record even the proposed weak directional conclusion from ordering alone. The problem is identifiability, not a claim that a large confound certainly exists.

I accept this replacement:

> An affine model fits the observed timings well over the tested bundles of 1 to 427 rules at three payload sizes; no knee is apparent in those observations. Sizes were tested in monotone order and bundles were prefixes, so the count effect is confounded with time and pattern composition. An interleaved, randomized, blocked rerun is needed to estimate scaling. The fit alone does not rule out substantial upward drift contributing to the slope.

Round 1 already said local approximate linearity was supported. Calling the descriptive fit unsupported would be too strong; interpreting it as an identified scaling law would also be too strong. Your proposed rerun addresses the right defects.

**2. I accept guarded removal of the unused Pre registration as the first implementation change, ahead of A.**

I placed it too late in round 1. Healthy starter Pre invocations evaluate no IN rule and record no scan. Removing their process launches has a clear rationale without first building a corpus artifact or rerunning the latency experiment. A dedicated measurement is unnecessary to justify the removal.

The approximately 0.099 s remains a reported measurement for the measured environment, not a guaranteed reduction in every installation's elapsed tool latency. Other matching hooks can overlap this work, and machines differ. Claude documents that matching hooks run in parallel, so a slower parallel handler can determine the wait. This qualifies the claimed saving, not the priority of removing redundant work. [Claude Code hook execution](https://code.claude.com/docs/en/hooks#hook-handler-fields).

Approve it as a small installer change with an explicit invariant: **an enabled executable IN bundle cannot become active until its required Pre registration is effective in that harness**. This applies to RECORD IN rules too; the absence of blocking authority does not excuse missing promised observation. An activation failure must leave the candidate inactive and report unavailable coverage, not silently claim it was enabled.

The guard must execute in installation, update, or bundle activation. Putting it only in the Pre handler that is absent cannot work. A future IN activation should establish registration and any required trust/reload first, confirm the harness can invoke it, and then activate the bundle generation. If activation fails partway, retain the prior active bundle. On removal, disable IN before removing its registration. A settings file containing an entry is weaker evidence than a harness that has actually loaded it.

For today's fixed starter release, this can remain narrow: omit its owned Pre entry and require the future corpus-enabling release to implement the guarded transition. Keep the existing settings preview, backup, ownership, and preservation behavior. Acceptance cases should cover fresh install, upgrade from the two-hook starter, reinstall/uninstall, preservation of other handlers, and attempted IN activation with absent or ineffective Pre registration. These are proposed checks; the passing current tests do not certify that future change.

The future registration/bundle coupling is a reason for this guard, not a reason to postpone the starter fix until all of A exists. No live settings mutation is part of this design review.

**3. I accept deciding the target behavior before substantial latency optimization. I reject both “RECORD can only ever be the lane” and “therefore performance does not bind.”**

There is no inherent requirement to finish detection synchronously merely because the system records events. Synchronous capture or durable acceptance can be separated from asynchronous matching. Conversely, the lane name alone does not determine timing. The deciding question is when the promised result must be available:

| Promised behavior | Required timing |
|---|---|
| DENY the current input or withhold output before model consumption | Matching must finish at the relevant interception boundary. |
| ADVISE before the model acts on this event | Advice must be available before that next action; this imposes a synchronous dependency. |
| Advisory report for later inspection | Matching may be asynchronous; it does not provide same-event protection. |
| RECORD with eventual findings and explicit pending/lost coverage | Matching may be asynchronous after capture. |
| Completed scan or audit certificate required before continuation | Completion is synchronous by the product contract, even if the lane is RECORD. |

“After the response is emitted” is too imprecise for IN/OUT design: distinguish before tool execution, before the result reaches the model, and before a user-facing answer. A later warning cannot retroactively prevent an earlier action. I recommend **eventual RECORD with explicit coverage status for the initial non-intervening release**, while preserving a synchronous evaluation interface for a future admitted enforcement bundle. The main tradeoff is delayed knowledge and additional delivery bookkeeping.

Your corpus argument does not establish a permanent RECORD ceiling. With 2,833 qualifying independent zero-hit trials, the upper bound is 0.105688%: insufficient for DENY but sufficient for ADVISE's 0.5% threshold. Thus the arithmetic alone does not even force RECORD on that larger corpus. The 466-trial result does force RECORD under these thresholds, but it is CFG evidence and establishes no runtime IN/OUT ceiling. Today's missing runtime evidence prevents promotion today; it does not prove runtime promotion impossible. Additional representative independent evidence is a valid task. Adding 162 files is not automatically sufficient: duplication, dependence, domain mismatch, hits, bundle changes, and selection on the same data can all defeat that arithmetic. The current hook also refuses positive-hit measurements. See [lane admission](src/agent_defs/lanes.py) and [runtime evidence validation](src/agent_defs/hooks/_claude_code_impl.py).

There is also a concrete qualification to “RECORD observes and never intervenes.” Completed RECORD findings do not advise or deny, but **incomplete RECORD scans currently inject model context and a user warning**. The fresh probe verifies that behavior. Moving matching off the path changes when those warnings can arrive. If warning the model before it consumes incompletely checked content is a requirement, that requirement retains a synchronous completion dependency. If eventual coverage reporting is acceptable, change that contract explicitly; simply setting an async flag does not preserve it.

Pairing and exit loss are delivery problems, not proofs that the matcher must block. Capture immutable event data at the boundary, including session/tool-call identity, event type, sequence or attempt identity where needed, field structure, and bundle/evaluator generation. Preserve missing results as missing; do not assume every Pre has a Post. Durable acceptance before continuation can support eventual processing after process or session exit. A volatile queue supports a weaker claim. Capturing at the boundary also avoids reconstructing different or truncated text later from a transcript.

The current log is not a complete audit ledger even with synchronous scans: clean events produce no record, supplied session/tool-call IDs are discarded, and finding writes do not request a durability flush. The probe verifies the first two; [_log and process](src/agent_defs/hooks/_claude_code_impl.py) show the third. Consequently “retain synchronous scanning to preserve today's complete session audit” would defend a guarantee the implementation does not provide. Durable replay would also require retaining the needed input bytes somewhere; today's hashes cannot reconstruct them. That adds a payload-retention decision to an asynchronous audit design.

For a complete audit, maintain capture and completion records, report gaps and pending work, bound the queue, and make overflow, shutdown, and restart behavior explicit. Publish a final coverage statement only after reconciling the expected events and completed work. Sampling is a valid cheaper product, but it cannot support a complete-session coverage claim. Even exhaustive completed matching supports only “no findings under this bundle on these captured surfaces,” not “this session contained no attack.”

Native background hooks illustrate both feasibility and limitations. Claude's documentation says async command hooks receive the same JSON input, cannot veto the completed action, and deliver context on a later turn. It also says outstanding async hooks are killed at non-interactive teardown, and ordinary async hooks no longer receive the harness timeout after backgrounding. Therefore retain the evaluator's external deadline and test delivery/lifecycle behavior on each supported harness. These are documented capabilities, not live tests performed here. [Claude Code asynchronous hooks](https://code.claude.com/docs/en/hooks#run-hooks-in-the-background).

Asynchronous matching removes its service time from the direct wait for that event; it does not remove its CPU, memory, storage, or scheduling costs. If arrivals outrun processing capacity, the backlog grows until some combination of delay, backpressure, dropped work, or sampling occurs. A record required by tomorrow's audit has a completion deadline too. Measure capture/acknowledgment latency, throughput, queue age, completion/loss rates, and interference with foreground work. Expensive matching can still justify batching or admission caching, but those choices would answer a throughput or audit-delay problem instead of a per-event interception budget.

Thus **the target lane together with its timing and coverage contract gates the expensive latency work**. A small feasibility measurement still belongs in making that decision. Under eventual RECORD, defer the full synchronous scaling campaign and evaluate capture/delivery plus sustained processing cost. Under same-event ADVISE or DENY, event-shaped latency and completion remain required. For mixed bundles, the admitted rules requiring immediate action can define the synchronous subset while RECORD-only work runs later, provided the action bundle is calibrated as deployed. Merely requesting a higher lane must never promote asynchronous results into authority over an event that already proceeded.

**The revised order I recommend is:**

1. Specify the initial lane, action deadline, audit completeness, and event-loss contract; run only the small capability checks needed to make that choice credible.
2. Make guarded starter Pre omission the first implementation change.
3. Implement minimal A: a pinned normalized bundle and a verified path from that bundle to the selected adapter's result. For eventual RECORD, acceptance means attributable capture, completed findings, and explicit gaps; enforcement canaries become required before an enforcement release.
4. Pursue IN/OUT selection and evaluation against the chosen objective. Measure synchronous event latency/completion for immediate intervention, or capture latency and processing capacity for eventual recording. Keep selection separate from final admission evidence.
5. Choose D, admission caching, a resident matcher, or a smaller bundle only when the relevant measurements justify it. Expanding calibration evidence can proceed independently.

**What you conceded too readily:** none of the concrete corrections about worker dispatch, starter Pre, the unisolated slope, cold pickle reconstruction, or the CFG/runtime evidence mismatch needs reversal. The concession **A before C** needs a scope limit. It is sensible for deployment claims and selection intended to represent the actual runtime path; it is not a prohibition on exploratory C before A, nor does it require enforcement integration before deciding whether enforcement is the product. Round 1 explicitly allowed exploratory C, but my statement that the entire proposed integration work was necessary under every viable outcome was too broad. An eventual recorder needs a different acceptance contract. You also should not surrender the descriptive affine fit along with the unsupported causal attribution; those remain separate claims.

