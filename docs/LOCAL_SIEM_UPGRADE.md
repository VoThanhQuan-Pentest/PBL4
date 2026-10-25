# Local SIEM upgrade — V41

The local release adds native ELK evidence, the five-entry JavaFX workspace,
versioned customer isolation and a recurrence ledger. The existing model remains
PROJECT_LIMITED with its original manifest, OTP, allowlist and 600-second bound.
This is lab integration work; strict production qualification is not asserted.

Private backup and clone receipts live under
`observability/runtime/private-backups/siem-upgrade-20261023-r1/`.
Never attach SQL backups, credentials, model state or private operator logs to a report.
The public verification summaries and live contracts are under
`audit-results/siem-upgrade-20261023/`. The original preparation summary remains
historical; final rollout status is recorded separately. Release amendments form
a hash-linked chain and preserve the original image/backup/clone receipts.

For a new cutover, prepare an immutable receipt with `siem-cutover-local.py` and the
exact application, Nginx and gateway candidate tags. Preparation requires an
exact-image V41 clone receipt and unchanged protected fingerprints. `--apply`
is the deployment step and requires the operator's approval. It stops the old
ELK writers before reusing their volumes; it never removes a data volume or
restores over the live database. The main database and serving worker are retained.

```bash
python3 observability/scripts/siem-cutover-local.py \
  --output observability/runtime/private-backups/siem-upgrade-20261023-r1 \
  --apply
```

After cutover, keep recurrence in OBSERVE and run the existing continuous HTTP
model gate through the new release wrapper:

```bash
python3 observability/scripts/siem-operational-gate.py \
  --output observability/runtime/private-backups/siem-upgrade-20261023-r1 \
  --epoch 1
```

The gate requires at least 3,600 continuous seconds and 30 HTTP evaluations,
uses disposable accounts and mocked SMTP, and records zero new fits. Also verify
live Filebeat traces within 60 seconds, City/ASN enrichment, policy ACK within
10 seconds, source-document equality and gateway restart/revoke behavior before
increasing recurrence mode from OBSERVE to TEMPORARY, then ENFORCE. An unavailable
or nondurable gateway cannot qualify an UNTIL_REVOKED response.

False-positive revocation invalidates the related strike without deleting history;
risk acceptance retains it. The new revoke API requires request ID, reason,
outcome and expected version. Legacy revocation cannot release UNTIL_REVOKED
blocks without the new reasoned workflow. Closing a confirmed incident requires
current response/recovery verification; closure does not release an IP block.

On failure, retain the new binary/schema and return recurrence to OBSERVE.
Inspect the private cutover checkpoint before resuming; never blindly replay a
partial cutover, downgrade the gateway, repair Flyway history, lower disk
watermarks, seed the live DB or restore an old snapshot over it.

## Local lab acceptance completed — 24 October 2026

The primary `flare-otp-local` stack runs schema V41 and recurrence ENFORCE, with
APPLIED gateway ACK. The exact deployed backend passed 3,605 continuous seconds,
33 HTTP evaluations and parity for all 399 compiled classes, with zero new fits.
The maximum measured execute latency was 172 ms. This is lab functional and
integration acceptance; the fixed model remains PROJECT_LIMITED and is not
qualified for all real users. OTP, the 600-second hold bound and original model
manifest/calibration/threshold remain in place.

See `audit-results/siem-upgrade-20261023/completion-summary.json` and
`exact-deployed-class-gate.json` for final outcomes. Earlier preparation and
source-only gate reports remain historical. The final desktop package passed
163 tests (five optional tests skipped), three additional live UI tests and a
native startup smoke check. Queue refresh preserves selection; Block IP has
paging and explicit expired state; incident summaries derive actor, target,
session and signal fields from the loaded ELK page.

All account credentials, OTP/mail configuration and reserved SOC-DEMO workflows
remain unchanged. Only the existing SOC-PRACTICE customer's session version was
intentionally increased once during isolation acceptance; it is released, and
old tokens remain revoked. No live database restore, reseed, training or AWS
resource creation was performed. Duplicate application/log writers are stopped,
with their volumes and history retained.

## Running the desktop client

The verified Linux image is recorded in
`audit-results/siem-upgrade-20261023/desktop-completion-delivery.json`; launch its
`bin/FlareSecurityMonitor`. The default API is `http://127.0.0.1:8089` through the
gateway recovery channel. Website traffic uses `http://127.0.0.1:8088`; Kibana
remains loopback on port 5601. Do not restart the retired `flare-local-elk` writers.

Actual live JavaFX screenshots are private because they include investigation
context. Public receipts report only test outcomes. Existing teacher/demo cases
remain reserved; acceptance creates and closes distinct `SOC-PRACTICE` cases.

Exact-number API acceptance compares the document already stored in Elasticsearch.
The controlled native fixture bypasses Filebeat's IEEE-double number parsing; this
does not claim that arbitrary producer JSON numbers retain precision through
Filebeat/Logstash. Normal producer telemetry remains the defined ECS contract.
