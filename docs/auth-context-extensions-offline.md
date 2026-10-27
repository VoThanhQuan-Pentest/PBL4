# Offline auth context extensions

This package implements four research capabilities: broader READY observations,
context confidence and drift diagnostics, a separate COLD classifier, and bounded
HTTP batching. It is not registered by `ueba-worker/app/main.py` and does not change
authentication, OTP, sessions, enforcement, or a published model release.

## Ownership and model selection

This branch owns offline code and evidence. The ASVS conversation owns runtime
integration, including `auth_shadow_contract.py`, `auth_shadow_serving.py`, worker
`main.py`, `SiemAuthShadowService.java`, and `SiemUebaGateway.java`. This package
does not modify those files. The HTTP lab contract below needs explicit mapping
to the existing runtime contract by that owner.

The fixed READY comparator is the private r2 A-42 state with SHA-256
`35b3500d0d924a244224071c74aa9127e482be61863b665070b8532fe058971f`.
It is distinct from the older published shadow model. READY challengers must
avoid regressions and strictly improve false positives or missed review cases
on the sealed evaluation set; otherwise r2 remains selected. COLD uses its own
42 numeric features, without padding to READY or using READY normal support.
COLD admission requires zero observed routine false positives, at least 90%
recall per review family, zero operational false review, and at least 95%
operational context accuracy. History strata 0, 1–9, and 10–29 are reported and
individually gated. Missing observations remain undetermined.

Each corpus has 100,000 controlled-clock lab observations. Account identities and
time ranges differ across splits. Labels stay outside extractor/model inputs.
Java re-export parity proves repeatability of the pinned extraction harness;
it does not prove equivalence with a deployed producer or production accuracy.

## Running a campaign

Use `observability/scripts/auth_context_research_classpath.py --init-job --job
<fresh-private-job>` first. All artifacts stay below
`/home/quan/.codex/research/model-capability-assessment`, outside Git.
Then execute these windows in order, one at a time:

```text
python3 -B observability/scripts/auth_context_extensions_campaign.py smoke --job <job> --allow-elk-maintenance
python3 -B observability/scripts/auth_context_extensions_campaign.py ready --job <job> --allow-elk-maintenance
python3 -B observability/scripts/auth_context_extensions_campaign.py cold --job <job> --allow-elk-maintenance
python3 -B observability/scripts/auth_context_extensions_campaign.py http --job <job> --allow-elk-maintenance
python3 -B observability/scripts/auth_context_extensions_campaign.py soak --job <job> --allow-elk-maintenance
```

The maintenance flag is only appropriate with the user's existing authorization.
The driver records original container identities and model hashes, stops only
as many of the three registered ELK containers as necessary, and restores them
between windows. An independent watchdog restores them if the driver disappears
or the 90-minute window expires. App, DB, Redis, old worker and other protected
containers must keep their original identities and start times. Recovery checks
and stage logs are durable private artifacts.

Admission needs 5.5 GiB available host RAM and 9 GiB free disk. Running jobs keep
a 3 GiB host reserve and a 4 GiB artifact quota. Capture and training use at most
2 CPUs/2 GiB; HTTP and soak use 1 CPU/512 MiB. Classifier fits are capped at four
per cohort and eight total, temperature fits at three, and normal-support fits
at zero. A reservation consumes budget even if the fit fails. Smoke fits nothing.
Failed or completed fit/evaluation windows must not be replayed or replaced to
chase a passing result. Inspect checkpoints before any continuation.

If COLD capture is sealed but RAM admission prevents parity from starting,
`cold-resume` continues with parity, selection and evaluation. It refuses a job
with an existing parity execution log, COLD result directory, or COLD fit
reservation. Every stage rechecks admission and can stop remaining registered
ELK containers; thresholds and fit budgets remain unchanged.

## HTTP lab contract

Only the isolated benchmark starts the loopback server; no host port is exposed
by Docker. `POST /lab/assess` accepts `{"snapshots": [...]}` with 1–32 schema-7
snapshots. IDs must be unique within the request and are preserved in responses.
Repeated IDs in concurrent requests are processed in separate internal batches,
so each request retains its own result even when payloads differ.
Malformed envelopes return 400; oversized bodies return 413. Invalid individual
observations return `UNDETERMINED` while valid siblings continue. Capacity is 256
pending items, with 503 on overload. Batch wait is at most 50 ms and the request
deadline is two seconds. Five inference/timeout failures open the breaker for
30 seconds, followed by one probe. Integrity failure stays unavailable.

Recommendations are `ROUTINE`, `REVIEW`, `OPS`, or `UNDETERMINED`. The response
explicitly records zero policy/hold/incident/block/session side effects.
Confidence describes the three lab contexts only. Temperature calibration and
low confidence never modify the core recommendation. Evidence includes at most
three observed numeric fields and is not a causal explanation or an attack
probability. If calibration fails its held-out gates, diagnostics use uncalibrated
softmax and identify that method.

`GET /lab/metrics` exposes only fixed-label counters and bounded histogram state.
Drift is separated by cohort and operation, requires 1,000 valid observations,
and needs two consecutive shifted windows. Coverage loss is reported separately.
The lab streaming window closes every 1,000 attempts. If any attempts lack a valid
observation, that window has fewer than 1,000 valid rows and reports insufficient
data for drift; coverage reporting still works. Runtime integration must choose
its own window policy explicitly rather than silently zero-filling missing rows.
Simulation results are functional laboratory evidence, not a production false
alarm guarantee. A nonpassing drift gate is preserved in the bundle metadata.

## Evidence and handoff

The bundle contains immutable numeric states, temperatures, drift references,
hashes, receipt identities, and producer findings. It always declares
`OFFLINE_RESEARCH_ONLY`, `runtime_integration_blocked: true`, and no automatic
enforcement. Keep rejected models private and excluded from serving. Runtime
integration additionally needs ASVS review of producer parity, trust/coverage,
contract mapping, model allowlisting, rollback and production evaluation.
HTTP qualification receipts bind their own implementation hashes separately
from the frozen model-campaign receipts. A transport fix after model evaluation
does not rerun or replace any model fit, calibration, or held-out evaluation.

Acceptance receipts cover HTTP faults, nine batch/concurrency combinations,
and a full 60-minute soak. Required gates are adapter batch-32 P95 ≤100 ms,
HTTP batch-32/concurrency-4 P95 ≤250 ms, peak process RSS ≤448 MiB, and median RSS
growth ≤5% between minutes 30–35 and 55–60, with no OOM or restart.
