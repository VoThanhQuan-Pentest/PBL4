# Local SOC workspace and auth investigation

The October 24 upgrade retains `flare-otp-local`, the existing MySQL/Redis,
Elasticsearch volumes, fixed schema6 model, OTP, and signature prevention policy.
The workstation is the deployment target; no AWS resources are created.

## Investigation workspace

The five navigation entries remain unchanged. Dashboard places the priority
queue before compact distributions. Single-click selects; double-click, Enter
or Open reuses the session's one incident window. Unsaved-note Save/Discard/Cancel
and session cleanup remain in force.

The incident header shows source, destination and observed server separately.
Workflow values never overwrite or masquerade as Elasticsearch observations.
Missing fields, workflow fixtures, unavailable sources and raw-view refusal are
distinct states. Network summary is independent of the current timeline page.

The timeline merges native ELK hits, model context, notes and workflow events.
Related context is opt-in. Selecting a log opens Fields/JSON without opening an
ELK section first. Original keys, arrays, numeric values and hit metadata remain
unchanged; workflow association stays outside `_source`.

The response panel separates notes from action reasons and requires an explicit
conclusion before closure. Server RBAC, incident assignment, expected versions,
idempotency and gateway ACK remain authoritative.

## Additive API

- `GET /api/siem/investigation-queue`: existing queue filters or a bounded ID batch,
  enriched with one Elasticsearch aggregation request for the page.
- `GET /api/siem/incidents/{id}/investigation-summary`: direct evidence groups,
  workflow context, source health, time scope and current containment.
- `GET /api/siem/incidents/{id}/timeline`: typed entries, filter-bound opaque cursor,
  optional time range and related context; default50/max100.
- `GET /api/siem/investigation-metrics`: consistent open/high/L2/response counts.
- `GET /api/siem/auth-correlation/policy` and `/history`: SOC-readable policy/audit.
- `PUT /api/siem/auth-correlation/policy`: Admin-only versioned, reasoned change.
- `GET /api/siem/shadow-assessments`: bounded candidate results, clearly separate
  from the baseline guard and original ELK logs.

Old endpoints remain available. No endpoint accepts arbitrary index names or
Elasticsearch DSL. Timeline snapshots expire after two minutes, bind to the
principal/session/filter, and use bounded workflow references and memory.

## Auth investigation policy

`AUTH_INVESTIGATION_V1` covers targeted failures/success, password spraying,
login/reset-to-sensitive-action chains, session context changes, repeated OTP or
sensitive execution, and verified reuse of revoked/isolated sessions.

`OFF` disables projection; `OBSERVE` records findings; `ALERT` creates SOC cases.
Neither auth correlations nor shadow assessments produce signature strikes,
until-revoked IP blocks, account isolation or new ML holds.

Canonical auth request IDs are server-generated. Credential failures and
rate-limited requests differ. Unknown login targets use a purpose-specific HMAC;
passwords, OTPs, raw tokens and raw attempted usernames are not exported.
New OTP/session observations use `AUTH_INVESTIGATION`, visible to SOC but excluded
from the frozen baseline's behavior-window input. Sensitive execution carries
its own server event reference and application request identity, so a transport
replay does not multiply execution counts.

The new fingerprint key is task-specific and read-only mounted. Existing JWT,
mail, OTP and Elastic credentials must not be reset to run a demonstration.

## Candidate protocol and limits

Schema7 appends16 auth-context features to the existing65:81 total, not96 padded
values. Candidate output is only `PILOT_ONLY / SHADOW`. The frozen baseline's
manifest, normal component, calibration, thresholds and enforcement allowlist
are unchanged.

Online candidate observation uses the accepted project-limited decision source.
Configure its separate read-only customer allowlist within the available
baseline decision population; the currently accepted baseline population is
`e2e-customer`. Auth correlation rules extend investigation independently of
whether an account is eligible for model observations. This release does not
silently expand the baseline's enforcement population.

The fresh pilot corpus is `CONTROLLED_CLOCK_LAB`, produced through loopback HTTP
and the actual Java feature extractors. It is a synthetic feature harness,
not a corpus of real attacks or ELK detection documents. JWT/OTP/MySQL/Redis
behavior is tested separately using real HTTP integration/operational gates.
All100,000 source snapshots are re-exported for JDK21 numeric/schema/coverage
parity before fits. Actor ownership, scenario IDs and labels stay outside the
numeric vector. Prior training, validation and holdout artifacts are not opened.

The immutable protocol permits two recipes and seeds42/43: at most four new
classifier fits and zero normal-component fits. Calibration/development choose
the candidate before evaluation scoring. Failed evaluation cannot authorize a
threshold/seed retry. A rejected candidate leaves the working baseline active.

Pilot artifacts are capped at4GiB and training at2GiB/2CPU. Pre-train admission
requires5.5GiB host available; supervision preserves3GiB reserve. Only necessary
ELK services may pause, and recovery runs unconditionally. Activating a candidate
also requires offline quality plus a full-stack memory proof; an offline PASS
alone does not enable its loader.

## Operator records and recovery

Private backup, immutable image/clone receipts, deployment checkpoints, source
proofs, fit reservations and raw diagnostics are under the task's private-backup
directory. Public acceptance artifacts contain bounded summaries only.

Inspect checkpoints before resuming. Never blindly replay a deployment or fit
ledger, restore an old snapshot over the primary DB, downgrade the gateway,
remove queues/volumes, lower watermarks or seed teacher cases. Rollback keeps the
additive schema and uses OFF/OBSERVE/SHADOW_OFF while retaining the baseline.

## Verified local release

The main backend is `flare/siem-app:20261024-r3`, schema V42. Auth correlation is
ALERT (incident creation only); signature prevention remains ENFORCE. The fixed
baseline stays PROJECT_LIMITED. Candidate A-42 passed the bounded offline lab
protocol and the full-stack resource/desktop/HTTP gates, and is pinned in SHADOW
for the existing `e2e-customer` decision population. Candidate has no response
privileges. Production strict qualification is not asserted.

The exact deployed backend gate ran3,601seconds with33evaluations,44sensitive HTTP
attempts and parity across429compiled classes, with zero baseline fits. The
candidate experiment used4classifier fits and0normal fits. Read the immutable
public receipts under `audit-results/siem-workspace-20261024/` for the evaluation
population, confidence bounds and controlled-clock limitations.

Final native client path is recorded in `desktop-completion-delivery.json` in
that audit directory. Existing packages remain available. The desktop-native
login fix was validated and applied through a client-only amendment after the
backend gate; no server/model code changed for that amendment.
