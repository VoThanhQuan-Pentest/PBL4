# Flare AWS–ELK lab runbook

This directory owns the Elastic Stack 9.4.2 lab for synthetic Nginx access data. The local path is fully executable; the Terraform/AWS path is **statically validated, not deployed**. None of these scripts run `terraform apply`, create AWS resources, or destroy AWS state.

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

Local published endpoints are only `127.0.0.1:8088` (Web), `127.0.0.1:5601` (Kibana), MySQL E2E on loopback, and Mailpit on loopback. Elasticsearch `9200/9300` and Logstash `5044` are not published. Filebeat and Logstash share the internal `observability-beats` network; mTLS verifies the `logstash` SAN.

## Secrets and rotation

`.secrets/observability` is mode `0700`; password, private-key and keystore files are `0600`. Elasticsearch uses `ELASTIC_PASSWORD_FILE`. Kibana stores `elasticsearch.password` and all three encryption keys in `kibana.keystore`; Logstash stores `LOGSTASH_INTERNAL_PASSWORD` in `logstash.keystore`. Compose does not load a password environment file. The analyst password remains a separate file and is mounted read-only only into the screenshot container.

Bootstrap is idempotent for a complete set and refuses partial or conflicting state. To rotate, stop Web/Filebeat and Monitor, archive only non-secret evidence, remove the entire `.secrets/observability` directory, rerun `bootstrap`, run `up`, then distribute only `.secrets/observability/web/` to Web. Never distribute `ca.key`, product keystores or Monitor password files.

## Pipeline and recovery

Filebeat has a 1 GB disk queue; Logstash has a 1 GB persistent queue. Keep their named volumes during ordinary `down` or restarts. A Monitor outage should be handled by restoring Logstash first, observing Filebeat drain, and confirming `trace.id` counts remain one. The access data stream retains seven days; parse errors retain three days. Invalid timestamp/status/bytes/duration/IP values are quarantined in `logs-nginx.parse_error-lab` with `flare.parse_error_reason`.

Public IPs receive City and ASN enrichment. Private, loopback, link-local, TEST-NET and reserved IPv4/IPv6 ranges receive `flare.source_ip_scope` and do not run GeoIP. Query values are redacted before ingestion; bodies, cookies, authorization headers, JWTs and CSRF values are outside the Nginx log allowlist.

## Kibana and evidence

`setup-kibana.sh` creates the `flare-lab` space and data view, imports stable IDs with `overwrite=true`, validates three non-empty dashboards and six enabled one-minute rules, then writes an official 9.4.2 saved-object export under `observability/runtime/`. Run `export-kibana-objects.sh <path>` after editing objects in Kibana; do not hand-edit an official export.

The `flare_analyst` role is read-only for Discover, Dashboard, Maps and Security alerts. Evidence is captured with that user by a digest-pinned Playwright container and contains synthetic data only under `docs/evidence/local-elk/`.

## Troubleshooting

- Elasticsearch unhealthy: check file ownership/mode in `.secrets/observability/monitor`, then inspect `local-lab-logs.txt`; do not publish port 9200 as a workaround.
- Logstash configuration error: run `local-lab.sh validate`; the first Ruby/filter error is normally the actionable cause.
- Filebeat TLS error: ensure Web received the current `ca.crt`, client certificate and key, and that its output host is exactly `logstash:5044` locally.
- Empty dashboard: verify the data-stream time range, then rerun `setup-kibana.sh`; the import is idempotent.
- Queue recovery: do not use `down -v`; start Elasticsearch, Logstash, then Filebeat and verify drain by `trace.id`.
