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

Local published endpoints default to `127.0.0.1:8088` (Web) and `127.0.0.1:5601` (Kibana); use `LOCAL_LAB_WEB_PORT` and `LOCAL_LAB_KIBANA_PORT` instead of stopping an existing user service when a port is occupied. MySQL E2E and Mailpit are also loopback-only. Elasticsearch `9200/9300` and Logstash `5044` are not published. Filebeat and Logstash share the internal `observability-beats` network; mTLS verifies the `logstash` SAN.

Targeted Docker regressions can be run without the full ELK lab:

```bash
scripts/verify-docker-runtime-regressions.sh
scripts/verify-redis-volume-migration.sh
```

Both scripts generate a unique Compose project by default and remove only the
resources created for that project.

## Secrets and rotation

`.secrets/observability` is mode `0700`; password, private-key and keystore files are `0600`. Elasticsearch uses `ELASTIC_PASSWORD_FILE`. Kibana stores `elasticsearch.password` and all three encryption keys in `kibana.keystore`; Logstash stores `LOGSTASH_INTERNAL_PASSWORD` in `logstash.keystore`. Compose does not load a password environment file. The analyst password remains a separate file and is mounted read-only only into the screenshot container.

Bootstrap is idempotent for a complete set and refuses partial or conflicting state. To rotate, stop Web/Filebeat and Monitor, archive only non-secret evidence, remove the entire `.secrets/observability` directory, rerun `bootstrap`, run `up`, then distribute only `.secrets/observability/web/` to Web. Never distribute `ca.key`, product keystores or Monitor password files.

## Pipeline and recovery

Filebeat has a 1 GB disk queue; Logstash has a 1 GB persistent queue. Keep their named volumes during ordinary `down` or restarts. A Monitor outage should be handled by restoring Logstash first, observing Filebeat drain, and confirming `trace.id` counts remain one. The access data stream retains seven days; parse errors retain three days. Invalid timestamp/status/bytes/duration/IP values are quarantined in `logs-nginx.parse_error-lab` with `flare.parse_error_reason`.

Public IPs receive City and ASN enrichment. Private, loopback, link-local, TEST-NET and reserved IPv4/IPv6 ranges receive `flare.source_ip_scope` and do not run GeoIP. Query values are redacted before ingestion; bodies, cookies, authorization headers, JWTs and CSRF values are outside the Nginx log allowlist.

Web log rotation creates a host-resolvable `root:root/0640` file, changes it to
the container contract `101:1000/0640`, and only then signals Nginx. A failed
ownership change or signal fails logrotate visibly. The scheduled runtime
workflow rotates while Filebeat is active and requires the events on both sides
of the rotation to arrive exactly once.

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

`setup-kibana.sh` creates the `flare-lab` space and data view, imports stable IDs with `overwrite=true`, validates three non-empty dashboards and six enabled one-minute rules, then writes an official 9.4.2 saved-object export under `observability/runtime/`. Run `export-kibana-objects.sh <path>` after editing objects in Kibana; do not hand-edit an official export.

The `flare_analyst` role is read-only for Discover, Dashboard, Maps and Security alerts. Evidence is captured with that user by a digest-pinned Playwright container and contains synthetic data only under `docs/evidence/local-elk/`.

## Troubleshooting

- Elasticsearch unhealthy: check file ownership/mode in `.secrets/observability/monitor`, then inspect `local-lab-logs.txt`; do not publish port 9200 as a workaround.
- Logstash configuration error: run `local-lab.sh validate`; the first Ruby/filter error is normally the actionable cause.
- Filebeat TLS error: ensure Web received the current `ca.crt`, client certificate and key, and that its output host is exactly `logstash:5044` locally.
- Empty dashboard: verify the data-stream time range, then rerun `setup-kibana.sh`; the import is idempotent.
- Queue recovery: do not use `down -v`; start Elasticsearch, Logstash, then Filebeat and verify drain by `trace.id`.
