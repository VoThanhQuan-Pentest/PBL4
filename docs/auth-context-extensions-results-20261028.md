# Offline extension results — 2026-10-28

Job: `/home/quan/.codex/research/model-capability-assessment/auth-extensions-20261028-r2`.
Scope: controlled-clock laboratory evidence and an offline handoff; no runtime
activation or automatic enforcement. The two continuation automations for
00:45 and 05:55 on 28 October were deleted at the user's request.

## Models and diagnostics

Both new corpora contain 100,000 observations, with separate train/calibration/
development/evaluation/control identities and time ranges. Java harness
re-export parity passed for both. Each evaluation has 20,000 routine, 3,000
review and 2,000 operational cases; each control split has 5,000 opposite-cohort
and 5,000 missing-observation cases. Source/model semantics were frozen at
`bf88f26`; no evaluation was rerun.

| Result on sealed evaluation | READY reference | READY challenger | COLD A-42 |
| --- | ---: | ---: | ---: |
| False review / 20,000 routine | 0 | 0 | 0 |
| Review detected / 3,000 | 3,000 | 3,000 | 3,000 |
| Recall for each review family | 100% | 100% | 100% |
| Correct operational context / 2,000 | 2,000 | 2,000 | 2,000 |
| Operational false review | 0 | 0 | 0 |

READY retains the r2 reference because the challenger did not strictly improve
it. COLD passes the registered laboratory gates using 42 features and no READY
normal support. All three COLD history strata (0, 1–9, 10–29) pass individually;
all covered evaluation observations are assessable. Missing controls remain
undetermined. These easy, generated cases do not establish production accuracy,
attack probability, or real-world false-positive rates.

Exactly eight new classifier fits and three scalar temperature fits were used;
normal-support fits were zero. Both selected temperatures are 0.25, and both
held-out calibration checks pass. READY Brier score changes from 1.151e-9 to
5.041e-36; COLD changes from 9.796e-10 to 2.531e-36. Such confidence applies only
to the lab's three context classes and does not alter recommendations.

For each cohort and operation, drift simulation reports 0/100 stable false alarms
and 100/100 detected reweighted shifts. This is conditional development replay,
not a production guarantee. Producer smoke/fault checks pass for both cohorts.

| Artifact | SHA-256 |
| --- | --- |
| READY selected state | `35b3500d0d924a244224071c74aa9127e482be61863b665070b8532fe058971f` |
| COLD selected state | `fd87af690027e6c186bfd7b1ec39ceaa8f7293e33dda029af0e00f30754edc34` |
| READY receipt | `935da0214e21b8b879dd98f9798f374aaea8be95902c1d0a0ea93ae5426cce9d` |
| COLD receipt | `767f246161bf1d62f0ee26869c611d30e43e36087bc9684d98a4d93509fcceff` |
| Offline bundle manifest | `345760697900bc06fab810905fbb3b7f799e3fdd7e64cee3543d71e5bd963c21` |
| Final `handoff-receipt.json` | `2337d62a77f8b0e53a1fcc805fe9d26e345fb3f30ada30b59cc07acdaea89255` |

## HTTP qualification

The separate HTTP implementation at `032b610` fixes request-local identity
isolation when concurrent envelopes reuse the same snapshot ID. A regression
test reproduced the defect before the fix. A review barrier prevented HTTP
qualification until model evaluation had completed and the fix passed tests.
This transport correction did not change a model, threshold, calibration fit,
dataset, or selection result. HTTP receipts bind their own implementation hashes.

All 13 HTTP fault scenarios pass, including repeated IDs across requests,
reordering, invalid-item isolation, overload, timeout and permanent integrity
failure. Side-effect counters remain zero. The benchmark container is verified
at 1 CPU/512 MiB, network `none`, restart policy `no`.

All nine HTTP batch/concurrency combinations passed response identity and
prediction checks, using 100 warmup and 1,000 measured requests each. The final
benchmark status is `HTTP_LAB_PASS`:

| Gate | Measured | Limit |
| --- | ---: | ---: |
| Adapter batch-32 P95 | 22.25 ms | 100 ms |
| HTTP batch-32/concurrency-4 P95 | 138.00 ms | 250 ms |
| Benchmark process peak RSS | 162.31 MiB | 448 MiB |

These timings include integrity verification, validation, inference, diagnostics
and monitoring. They measure the standalone prototype, not incremental RAM or
latency of an integrated production worker.

The soak completed with `SOAK_LAB_PASS`: 3,600.36 continuous seconds, 41,260 HTTP
requests and 721 RSS samples at approximately five-second intervals (including
the final boundary sample). Median RSS was 183.10 MiB during minutes 30–35 and
183.32 MiB during minutes 55–60: growth **0.122%**, below 5%. Peak process RSS was
186.87 MiB, below 448 MiB. There was no OOM or restart; the supervisor exited 0.
The final rolling P95 values for batches 1/8/32 were 64.18/249.31/135.91 ms.
All samples recorded a drained queue after the measured burst.

Verification passed 31 observability unit tests and 16 worker unit tests,
including the reproduced concurrent-ID regression and actual loopback HTTP
faults. No full application build, security stack rebuild, or deployment ran.

| Qualification receipt | SHA-256 |
| --- | --- |
| HTTP faults | `3ac702354df9efc7fc1a8fc20a12b5e9079e2632e152091e013c8987a7ff697d` |
| Benchmark | `aebd31f3b20edf1e0b2cc686f0d218a2989df2d5f18b60907ee26fd922b788d4` |
| Soak | `f12afbb71b3d7a0705add147130550b4988cd2dcfa2fa0f2c54a0d8d3932e9c2` |

## Resource recovery and integration

Evaluation peak process RSS: READY 188.11 MiB; COLD 178.67 MiB. Capture/training
containers were capped at 2 CPUs/2 GiB; their exact peak RSS was not recorded. The first
COLD window stopped at RAM admission before parity started. Recovery restored
ELK; the sealed corpus was reused without refitting. The continuation checks RAM
at each stage boundary and can stop only remaining registered ELK containers.
All completed model windows report original published models unchanged and
protected application/container identities unchanged within each window.
After the final soak, the original Elasticsearch, Logstash and Kibana containers
were all restored healthy. The final independent audit rechecked their identity,
the protected containers and published model hashes, and the exact fit ledger.

Measured stage wall times, excluding ELK stop/recovery overhead:

| Cohort | Capture | Parity | Selection, four fits and calibration | Evaluation |
| --- | ---: | ---: | ---: | ---: |
| READY | 1,128 s | 380 s | 56 s | 16 s |
| COLD | 594 s | 158 s | 38 s | 10 s |

The private job occupies about 967 MiB including corpora, classpath and evidence,
below its 4 GiB quota. The research bundle itself is 417,364
bytes (about 408 KiB); it remains blocked from runtime integration.

The bundle stays `OFFLINE_RESEARCH_ONLY` with `runtime_integration_blocked: true`.
ASVS owns runtime schema/routing, allowlisting, trust/coverage validation and
deployment. In particular, this branch does not edit `auth_shadow_contract.py`,
`auth_shadow_serving.py`, `main.py`, `SiemAuthShadowService.java`, or
`SiemUebaGateway.java`. Integration must validate the deployed producer against
the pinned lab extractor and map the isolated `/lab/assess` contract explicitly.
See [the implementation handoff](auth-context-extensions-offline.md).

## Changed files since the rejected committed plan

- `ueba-worker/app/auth_extensions_core.py`
- `ueba-worker/app/auth_extensions_diagnostics.py`
- `ueba-worker/app/auth_extensions_http.py`
- `ueba-worker/app/auth_extensions_research.py`
- `ueba-worker/app/auth_extensions_benchmark.py`
- `ueba-worker/tests/test_auth_extensions.py`
- `observability/scripts/auth_context_extensions_campaign.py`
- `observability/scripts/auth_context_extensions_runner.py`
- `observability/scripts/auth_context_extensions_source.py`
- `observability/scripts/auth_context_research_runner.py`
- `observability/tests/test_auth_context_extensions.py`
- `docs/auth-context-extensions-offline.md`
- `docs/auth-context-extensions-results-20261028.md`
- Deleted `docs/model-upgrade-1-4-plan-20261028.md` with a normal deletion commit.
