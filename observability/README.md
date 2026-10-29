# Flare AWS–ELK lab runbook

This directory owns the Elastic Stack 9.4.2 lab for Nginx access data. The local path is fully executable; the Terraform/AWS path is **statically validated, not deployed in repository evidence**. None of these scripts run `terraform apply`, create AWS resources, or destroy AWS state. `verify-aws-lab.sh` is a read-only acceptance gate for a deployment created explicitly by its owner.

## Local lifecycle

Requirements: Docker Compose 2.35+, `bash`, `curl`, `jq`, `openssl`, x86_64, about 16 GB RAM and Internet access for pinned images/GeoIP data.

```bash
observability/scripts/local-lab.sh bootstrap  # PKI, password files, keystores
observability/scripts/local-lab.sh validate   # shell/JSON/Compose/Filebeat/Logstash
observability/scripts/local-lab.sh up         # ordered startup and idempotent imports
observability/scripts/local-lab.sh verify     # pipeline, queues, roles and six rules
observability/scripts/local-lab.sh evidence   # report plus 1440×900 screenshots
observability/scripts/local-lab.sh down       # preserve data, queues and secrets
```

`local-lab.sh all` runs the first five steps. Failure preserves containers, named volumes and queues; diagnostics are written to `observability/runtime/`. Purge is deliberately gated:

```bash
LOCAL_LAB_PURGE_CONFIRM=yes observability/scripts/local-lab.sh purge
```

Local published endpoints default to `127.0.0.1:8088` (Prevention Gateway/Web), `127.0.0.1:8089` (SOC recovery API) and `127.0.0.1:5601` (Kibana); use `LOCAL_LAB_WEB_PORT`, `LOCAL_LAB_RECOVERY_PORT` and `LOCAL_LAB_KIBANA_PORT` instead of stopping an existing user service when a port is occupied. The recovery listener is loopback-only and forwards only authentication/SIEM APIs; Spring Boot still enforces SOC roles. MySQL E2E and Mailpit are also loopback-only. Elasticsearch `9200/9300` and Logstash `5044` are not published. Filebeat and Logstash share the internal `observability-beats` network; mTLS verifies the `logstash` SAN.

### Local WAF, attack signatures and IP intelligence

The public Web port is served by a Go gateway using Coraza and OWASP CRS, then
the existing Nginx and Spring Boot application. The gateway enforces only
approved signatures in `PUBLISHING` or `ACTIVE`; OWASP CRS runs in detection-only mode so its
generic rules do not unexpectedly block commerce. The public request body is
bounded to 1 MiB and inspected in memory. The prevention log stores only an
event ID, trace ID, source IP, matched rule ID, policy version and action. It
does not store request bodies, cookies, tokens or raw query values.

Open **Attack signatures** in JavaFX to propose a pattern, run matching and
benign fixtures through the same Coraza build used by the gateway, then have
SOC L2/Admin activate it. A passing test does not activate a rule. The API
and JavaFX both support custom positive/benign fixtures; expand **Custom signature
test fixtures** for a SQLi/XSS/traversal rule scoped to a method or path. Use
synthetic examples only. The default test button covers unscoped rules.
The API
marks an approved rule `PUBLISHING`, and the gateway enforces it as part of the
approved policy. The UI marks it `ACTIVE` only after the gateway acknowledges
its checksum. The built-in
demo pattern `GET /.env` is safe to exercise only on the local lab:

```bash
curl -i http://127.0.0.1:8088/.env
```

After activation this returns HTTP 403 before Nginx/application. A normal API
health request remains HTTP 200. The loopback recovery origin can still reach
the authenticated SOC API when a public client IP is blocked.

Gateway rate limits start at 100 requests/second with a burst of 200 for all
HTTP and 30/second with a burst of 60 for API requests. Three active-signature
matches from one IP in 60 seconds create a 15-minute IP block. Endpoint
enumeration requires at least 20 distinct paths and 10 error responses in each
of two completed minute windows, then blocks for 10 minutes. Five failed
logins in five minutes trigger IP lookups but do not alone block the whole IP.
These are lab defaults and should be tuned from measured traffic.

Provider lookups run in a background worker, never in the request path. Cache
durations are 24 hours for IPinfo and 6 hours for AbuseIPDB; timeouts are two
seconds, concurrency is one job and the local budget is 100 attempts/provider/day.
Only a numeric public IPv4/IPv6 address is sent. IPinfo Lite supplies country
and ASN; it does not supply VPN/proxy or abuse confidence fields, so those fields
stay unavailable. AbuseIPDB confidence and report counts are shown as provider
evidence, not as a probability that this request is malicious. Missing keys,
timeouts and stale results are labelled explicitly. Rows without a successful
provider response carry `UNAVAILABLE` provenance; `REAL` requires a fresh
provider response, and local fixtures carry `DEMO_ONLY`.

`observability/scripts/local-lab.sh bootstrap` creates
`.secrets/prevention/gateway.token`, `ipinfo.token` and `abuseipdb.key`
outside Git. The two provider files may remain empty. To use real lookups,
obtain your own API keys and enter them locally in those files; do not send keys
in chat. Each file must contain only its raw token/key, not an API URL,
`token=...`, `Bearer ...` or a shell assignment. The app reports
`INVALID_CONFIG` for these pasted formats without calling the provider.
**IP intelligence** includes an Admin-only TEST-NET sample button
whose records carry `DEMO_ONLY`; it does not call either provider. The normal
lookup button only queues a request and displays each provider's status/time.

The WAF uses Redis for the short-window signature counter and rapid temporary
ban key; an allowlisted gateway event is also durably sent through Filebeat and
Logstash. Spring projects it into a `PREVENTION` L1 incident and MySQL block
history. The loopback-only management listener on 8089 permits only auth/SIEM
routes, and Spring still enforces authorization. If Redis is unavailable, the
gateway keeps its loaded signature policy and local rate limiter, reports
`DEGRADED_REDIS`; Redis signature counters cannot create rapid bans, though
persisted events can still be assessed by the backend after reaching ELK.

### Local UEBA/SOC demo

The UEBA worker stays on an internal Compose network and has no host port.
The website app records server-authored customer security events; 15-minute
account windows are aggregated in MySQL, scored by the worker when a model is
active, and displayed in the JavaFX SOC client. A missing model uses a labelled
rule-only assessment; it never blocks commerce or automatically revokes sessions.
Security-event NDJSON rotates at 64 MiB. Filebeat follows the active and rotated
names; MySQL removes only events older than 30 days that were **both** exported
and aggregated, while old scored windows use the same retention. Generated
rotated files are retained for another seven days. Unprocessed rows are never
removed by this maintenance job.

Use a **local lab only** and choose a fresh dataset ID for each demo day. The
following commands insert clearly labelled synthetic customers and events;
they do not run automatically as part of `up` or `all`. `python3`, `openssl`,
and `htpasswd` are required on the host. The default shared demo password is
`DemoOnly#2026`; set `UEBA_DEMO_PASSWORD` for a different local-only password.
If updating an already-used local lab, make a private database backup with
`observability/scripts/backup-local-db.sh` before rebuilding the app.
`local-lab.sh up` applies additive Flyway migrations and reimports stable
Kibana object IDs with overwrite enabled. Before that import, `up` exports
existing `flare-lab` dashboards and detection rules to a private backup and
refuses to overwrite when the export is incomplete.
The backup stays under ignored `observability/runtime/private-backups/` and
must never be attached as report evidence.

```bash
observability/scripts/local-lab.sh up
UEBA_DEMO_CONFIRM=yes UEBA_DEMO_DATASET_ID=ueba-20260926 \
  observability/scripts/local-lab.sh demo-normal
UEBA_DEMO_DATASET_ID=ueba-20260926 \
  observability/scripts/local-lab.sh verify-ueba normal
```

The seed is idempotent by event ID. It creates four `ueba_demo_<dataset>_N`
accounts and about 2,532 normal security events across 960 historical
15-minute windows. Allow several aggregation intervals for the backlog to
drain; the Admin's training action requires at least 600 eligible windows from
three accounts. In JavaFX, sign in as Admin, open **Settings → Train candidate
(past 14 days)**, refresh the job until `SUCCEEDED`, then explicitly activate
it. The model's `DEMO_ONLY` provenance is shown so synthetic training is never
presented as real-world validation.

Only after activation, insert the abnormal scenario:

```bash
UEBA_DEMO_CONFIRM=yes UEBA_DEMO_DATASET_ID=ueba-20260926 \
  observability/scripts/local-lab.sh demo-abnormal
UEBA_DEMO_DATASET_ID=ueba-20260926 \
  observability/scripts/local-lab.sh verify-ueba abnormal
```

This inserts 136 labelled abnormal events for demo account 1 in a past,
completed window: elevated request volume, 403 responses, failed logins, a new
IP and a different user-agent family. Check **Account watchlist** and the L1
incident queue, then claim/escalate the case to L2. L2 can manually revoke
sessions only after supplying a reason and confirming the action. Existing
JWTs then fail while a new customer login remains possible. To also show live
client–server traffic, sign in to `http://127.0.0.1:8088` with the demo account
and the selected demo password; those **real** requests are recorded without a
synthetic label. They are kept distinct from the historical fixture in the
window view and Elasticsearch (`flare.synthetic=true` for fixture events).
UEBA incident detail includes the contributing behavior windows and a paginated
security-event timeline (up to 200 events per page). That timeline exposes only
server-authored IDs, timestamps, action/outcome, IP, route group, status and
normalized user-agent family; it never returns request bodies, raw URLs,
cookies, credentials or tokens. Evidence older than the configured retention
period may no longer be available in the live event table.
For a UEBA incident, the detail view also queries its allowlisted documents in
`logs-flare.security-lab` and displays City/country/ASN when a public source IP
was enriched. Private or TEST-NET fixture IPs show their scope instead of a
fabricated location; ELK-origin incidents keep their existing Nginx-log view.

The seed wrapper refuses other Compose project names and requires
`UEBA_DEMO_CONFIRM=yes`. It does not delete or reset data. If you need a fresh
fixture, choose a new dataset ID; never point these commands at AWS or a
production database.
`verify-ueba` is read-only. It checks the labelled MySQL events and feature
windows, export/aggregation progress, Elasticsearch arrival and (after the
abnormal phase) a model-scored UEBA incident. If a queue has not drained yet,
wait and rerun it; do not reseed simply because the verifier was early.

An isolated cross-language acceptance test can be run without changing the
active lab. It requires the previously built local worker image and uses
Testcontainers for MySQL, Redis and the worker:

```bash
docker build --pull=false -t flare-ueba-worker:local ueba-worker
cd backend
RUN_LOCAL_UEBA_WORKER=true mvn -q -Dtest=UebaModelEndToEndLocalTest test
```

Targeted Docker regressions can be run without the full ELK lab:

```bash
scripts/verify-docker-runtime-regressions.sh
scripts/verify-redis-volume-migration.sh
```

Both scripts generate a unique Compose project by default and remove only the
resources created for that project.

The low-volume traffic entrypoints have an executable contract test:

```bash
observability/scripts/test-owned-traffic-contracts.sh
```

It verifies the CSRF-aware `username` login payload, query-form traversal
signal, and automatic app recovery in the AWS 5xx scenario without contacting
a real target.

### Completed r2 offline model deduplication

On 2026-10-16, 360 byte-identical cal/top model pairs in
observability/runtime/hybrid-strict-source-20261013-parallel-resume-r2/source/standard/hybrid-models
were consolidated using hard links. Both model names and their separate JSON
metadata remain present. The retired duplicate inode allocation totals
4,746,022,912 bytes. Model fitting, selection, holdout scoring and AWS were not run.

The private session observability/runtime/storage-reclamation-r2-20261016-impl2
contains the exact candidate-pairs.private.json, approval.private.json and 360
completed journal records. Independent review rehashed all 360 shared model
binaries, 360 fit artifacts and 1,800 metadata/receipt bindings; all matched.
It also checked the 50 frozen Python source pins and the JVM snapshot identity.
The independent-review-20261016.private.json and review-findings-20261016.private.json
receipts in that session retain the review evidence.

The original maintenance helper is SHA-pinned by its approval:
f851e5992fadd4cbbd4c1703bde76bc70b0a165f2c7176a6506be19d5f3da251.
Review reproduced two defects in its apply/resume path: a resumed transaction
can replace a good top artifact before checking changed canonical bytes, and
the persisted TEMP_LINK_CREATED state resumes with a missing canonical_signature
key. The 12 original fixture tests pass but do not cover these failures.
The completed live artifacts passed independent integrity checks. Preserve this
helper and the original approval/journal as historical evidence; a reviewed
successor is required before reusing apply/resume. Do not rewrite old receipts
or repin historical approval to altered helper code.

Both cal/top names now share one inode, so they are not independent backup
copies. Restoring all top files as independent copies needs about 4,743,834,239
logical bytes, filesystem overhead, the existing decimal 5 GB reserve and unit
margin. A single-file restore copies opaque canonical bytes to a private temp,
checks the pinned SHA, fsyncs and atomically replaces the target under the
campaign/worker locks; exact model paths and hashes are in the private manifest.
Keep the canonical cal files, current r2 caches, source archives, labels and
checkpoint receipts. The ML goal remains paused; follow
[the project handoff](../docs/CONVERSATION_HANDOFF_2026-10-15.md) when it is resumed.

## AWS acceptance lifecycle

The lab Terraform intentionally keeps subnet-wide automatic public addressing
off, while the two explicit EC2 resources opt into launch-time public IPv4.
This gives cloud-init Internet access before their stable EIPs are associated;
the lab has no NAT Gateway. `terraform test` locks this contract.

After an explicit, reviewed `terraform apply`, deploy Monitor before Web. Run
owned traffic from the named tester CIDR, then generate real AWS 5xx responses
with the recovery-gated script:

```bash
I_OWN_THIS_TARGET=yes WEB_HOST=ubuntu@<web-eip> \
  FLARE_LAB_TARGET=http://<web-eip> FLARE_LAB_ALLOWED_HOST=<web-eip> \
  observability/scripts/traffic-5xx-owned-aws.sh
```

When all six rule scenarios have run, collect sanitized runtime evidence:

```bash
I_OWN_THIS_TARGET=yes \
  WEB_HOST=ubuntu@<web-eip> MONITOR_HOST=ubuntu@<monitor-eip> \
  FLARE_LAB_TARGET=http://<web-eip> FLARE_LAB_ALLOWED_HOST=<web-eip> \
  observability/scripts/verify-aws-lab.sh
```

The acceptance gate requires cloud-init completion, all core containers,
Filebeat mTLS output, the Elasticsearch EBS mount, access/GeoIP documents,
three dashboards, six enabled rules and all six alert IDs. It writes only
sanitized JSON/Markdown under ignored `observability/runtime/aws-evidence-*`.
Attach AWS Console/Kibana screenshots separately and never attach `.env`,
password files, certificates with private keys, cookies or Terraform state.

## Secrets and rotation

The Elasticsearch password is the deliberate host-side exception: bootstrap sets it to `0640:root` for the pinned bind-mounted service, inside the owner-only `monitor/` directory. The Kibana export helper accepts this exact mode/group only when that parent remains `0700`; other host-only passwords stay `0600`.

`.secrets/observability` is mode `0700`. Host-only passwords and the CA key remain `0600`; private runtime files are `0640` and group-scoped to the pinned image runtime identities. The Web client key remains `0600` and owned by Filebeat's numeric identity. Elasticsearch uses `ELASTIC_PASSWORD_FILE`. Kibana stores `elasticsearch.password` and all three encryption keys in `kibana.keystore`; Logstash stores `LOGSTASH_INTERNAL_PASSWORD` in `logstash.keystore`. Compose does not load a password environment file. The analyst password remains a separate file and is mounted read-only only into the screenshot container. The Spring Boot app receives only `ca.crt` and `siem-reader.password`; `flare_siem_reader` has read/view-metadata privileges and no Kibana application privileges.

Bootstrap is idempotent for a complete set and refuses partial or conflicting state. To rotate, stop Web/Filebeat and Monitor, archive only non-secret evidence, remove the entire `.secrets/observability` directory, rerun `bootstrap`, run `up`, then distribute only `.secrets/observability/web/` to Web. Never distribute `ca.key`, product keystores or Monitor password files.

## Pipeline and recovery

Filebeat has a 1 GB disk queue; Logstash has a 1 GB persistent queue. Keep their named volumes during ordinary `down` or restarts. A Monitor outage should be handled by restoring Logstash first, observing Filebeat drain, and confirming `trace.id` counts remain one. The access data stream retains seven days; parse errors retain three days. Invalid timestamp/status/bytes/duration/IP values are quarantined in `logs-nginx.parse_error-lab` with `flare.parse_error_reason`.

Public IPs receive City and ASN enrichment. Private, loopback, link-local, TEST-NET and reserved IPv4/IPv6 ranges receive `flare.source_ip_scope` and do not run GeoIP. Query values are redacted before ingestion; bodies, cookies, authorization headers, JWTs and CSRF values are outside the Nginx log allowlist.

Web log rotation creates a host-resolvable `root:root/0640` file, changes it to
the container contract `101:1000/0640`, and only then signals Nginx. A failed
ownership change or signal fails logrotate visibly. The scheduled runtime
workflow rotates while Filebeat is active and requires the events on both sides
of the rotation to arrive exactly once.

## Logging inventory (candidate source, 2026-10-29)

This inventory describes the shipped configuration, not an inspection of the
running lab or an ASVS qualification. Operators own host permissions, Docker
logging policy and retention verification; SOC owns investigation use. A value
marked **unspecified** is an assessment gap, not unlimited retention approval.
Database workflow/history and model artifacts are not Elasticsearch evidence.

| Component / events | Format, destination and use | Access boundary | Retention in source |
| --- | --- | --- | --- |
| Nginx public/default virtual hosts: requests, status, detection signals | `flare_json`, `/var/log/nginx/access.json.log`; Filebeat → `logs-nginx.access-lab`; request/trace investigation | Writer UID101; shared logs group1000, files0640; Filebeat mount read-only; Elastic reader roles | AWS host `logrotate` daily/max10M, seven rotations; Elastic access stream7d. Host rotation is not automatically installed by local Compose. |
| Nginx native diagnostics | Fixed-code JSON, `/var/log/nginx/native-errors.json.log` and Docker stderr; operational error categories | PID1 classifies native stderr before persistence; UID101, files0640; Docker/host operators | Same AWS `*.log` rotation; Docker stderr retention **unspecified** in Compose. No Filebeat input for this file. Historical raw `error.log` is preserved, not rewritten. |
| Gateway prevention events: rule/block/limit observations | NDJSON, `PREVENTION_EVENT_FILE` (`/var/log/flare/prevention-events.ndjson` in local topology); Filebeat → `logs-flare.prevention-lab` | Gateway writer; shared log volume; Filebeat read-only; SOC/Admin API and Elastic stream privileges | Writer rotates64MiB; rotated files older than7d pruned during rotation; active file remains. Elastic stream30d. |
| Gateway operational errors | Go slog to stderr; server logger JSON, process startup logger default text; startup/policy/listener diagnosis | Docker/host operators; no prevention-event ingestion assumption | Docker retention **unspecified** in Compose. |
| Backend security events: auth, requests and sensitive actions | MySQL outbox → `security-events.ndjson`; explicit JSON export → Filebeat → `logs-flare.security-lab`; investigation and feature aggregation | App writer; files0640; Filebeat read-only; SOC/Admin APIs and limited Elastic reader | Configured minimum30d; only processed DB events/scored windows purged. Rotated export files after retention+7d; active file remains. Elastic stream30d. |
| Backend audit/security/exception diagnostics | SLF4J console, including `AuditLogService` key=value audit entries; business audit and operational diagnosis | Docker/host operators; console is not declared ELK evidence | Docker retention **unspecified**. Some unexpected exceptions include Throwable; data classification/provenance still under review. |
| SOC state: incident notes/history, actions and ingestion checkpoint | MySQL entities; workflow/audit and pipeline health. Checkpoint diagnostic is also returned in `/api/siem/status` and workspace | Server requires Admin/SOC L1/L2 for SIEM namespace; DB operators separately privileged | General notes/history/checkpoint expiry **unspecified**; no automatic deletion implied by security-event retention. |
| Parser quarantine | Logstash-normalized JSON → `logs-nginx.parse_error-lab`, `logs-flare.security_error-lab`, `logs-flare.prevention_error-lab`; failed-schema investigation | Logstash writer; limited Elastic reader roles | Template lifecycle3d; actual lifecycle application must be verified. |
| Filebeat / Logstash / Elasticsearch / Kibana operational diagnostics | Service console via Docker; transport, queue, index and UI troubleshooting | Docker/host operators; service credentials/keystores separate from browser and JavaFX | Docker retention **unspecified**; queue storage is recovery state, not a time-based log-retention guarantee. |
| MySQL / Redis service diagnostics | Default container console; database/cache availability. Audit/general-query logging is not asserted enabled | Docker/host and DB/cache operators; network/credential boundaries separate | Docker retention **unspecified**; volume lifecycle is not a log deletion policy. |
| Lab mail service | Mailpit console and test mail UI/storage; delivery diagnosis. Message bodies/OTPs are sensitive application data, not ELK evidence | Local-only lab UI binding and host/operator access; production SMTP remains outside this inventory | Console/mail-store expiry **unspecified**; do not delete protected mail/account state as log cleanup. |
| UEBA worker diagnostics and job state | Uvicorn console; worker-owned job receipts in model directory. Operational/model-job state, not fabricated ELK evidence | Worker internal service authentication; container/model-volume operator access | Console/job-receipt expiry **unspecified**. No model/training files may be deleted to implement log retention. |
| JavaFX client | No application-owned persistent log sink found in `desktop-client/src/main/java`; launch/runtime console remains possible | Local desktop/session operator | Launcher/runtime retention **unspecified**; passwords/cookies must not be persisted. |
| Operator commands / CI assessment output | Console and explicitly selected runtime/report artifacts; verification and release evidence, separate from live ELK | Operator files require private access; CI artifacts follow repository/platform access and must contain only approved synthetic or protected output | CI upload expiry follows each workflow's `retention-days`; local operator receipt expiry **unspecified**. Backups, credentials and model artifacts are not disposable logs. |

Source anchors: [Nginx configuration](../nginx/nginx.conf),
[native diagnostic boundary](../nginx/diagnostics/main.go),
[host rotation](logrotate/nginx-access), [Filebeat inputs](filebeat/filebeat.yml),
[stream templates](elasticsearch/templates/), [gateway rotation](../gateway/rotate.go),
[security-event export](../backend/src/main/java/com/flarefitness/backend/service/siem/SecurityEventExportWorker.java),
[security-event retention](../backend/src/main/java/com/flarefitness/backend/service/siem/SecurityEventRetentionWorker.java),
[audit producer](../backend/src/main/java/com/flarefitness/backend/service/AuditLogService.java)
and [base topology](../docker-compose.yml).

Queries are redacted in Nginx access JSON; raw path/User-Agent are still in that
contract and require their own classification review. Native diagnostic text
is not retained by the candidate classifier. Structured backend events export
session pseudonyms/auth fingerprints rather than bearer tokens. These controls
do not prove every producer or exception message safe. Do not send request
bodies, cookies, passwords, OTPs or authorization headers to any sink. Do not
change Docker logging/rotation on the running stack merely to satisfy this
inventory: define and test the missing operator policy before rollout.

## Redis volume migration

Redis uses the declared project volume `redis-data`; losing it invalidates live
JWT sessions, OTPs and rate-limit state even though MySQL remains intact. A Web
host that still runs Redis on a legacy volume must perform the gated maintenance
cutover before deployment continues:

```bash
cd /opt/flare
COMPOSE_PROJECT_NAME=flare observability/scripts/migrate-redis-volume.sh check
COMPOSE_PROJECT_NAME=flare REDIS_VOLUME_MIGRATION_CONFIRM=yes \
  observability/scripts/migrate-redis-volume.sh prepare
COMPOSE_PROJECT_NAME=flare observability/scripts/migrate-redis-volume.sh verify
```

`prepare` stops Nginx/app writes, saves Redis, copies the RDB to the declared
volume and a separately named rollback volume, verifies checksums and a TTL
marker, then restarts services. Neither the legacy source nor rollback volume is
deleted automatically. If rollback is required, keep the named-volume Compose
declaration and run the explicit `rollback` mode with the same confirmation
variable.

## Kibana and evidence

`export-kibana-objects.sh` only accepts a loopback HTTP Kibana origin and an output path under the ignored `observability/runtime/` tree. It writes atomically with mode `0600`; `backup-kibana-before-import.sh` keeps the saved objects and detection-rule export under a private `0700` directory.

`setup-kibana.sh` creates the `flare-lab` space and data view, imports stable IDs with `overwrite=true`, validates three non-empty dashboards and six enabled one-minute rules, then writes an official 9.4.2 saved-object export under `observability/runtime/`. Run `export-kibana-objects.sh <path>` after editing objects in Kibana; do not hand-edit an official export.

The export helper accepts only a loopback HTTP Kibana origin and destinations under the ignored `observability/runtime/` tree. It requires the Elasticsearch password file to be owner-only and publishes exports atomically with mode `0600`; for pre-import protection, `backup-kibana-before-import.sh` stores dashboards and detection rules in a mode-`0700` directory under `private-backups/`.

The `flare_analyst` role is read-only for Discover, Dashboard, Maps and Security alerts. Evidence is captured with that user by a digest-pinned Playwright container and contains synthetic data only under `docs/evidence/local-elk/`.

## Troubleshooting

- Elasticsearch unhealthy: check file ownership/mode in `.secrets/observability/monitor`, then inspect `local-lab-logs.txt`; do not publish port 9200 as a workaround.
- Logstash configuration error: run `local-lab.sh validate`; the first Ruby/filter error is normally the actionable cause.
- Filebeat TLS error: ensure Web received the current `ca.crt`, client certificate and key, and that its output host is exactly `logstash:5044` locally.
- Empty dashboard: verify the data-stream time range, then rerun `setup-kibana.sh`; the import is idempotent.
- Queue recovery: do not use `down -v`; start Elasticsearch, Logstash, then Filebeat and verify drain by `trace.id`.
