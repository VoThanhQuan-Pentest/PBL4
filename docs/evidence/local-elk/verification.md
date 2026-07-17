# Flare local ELK verification

- Elastic Stack: `9.4.2`
- Scope: local/code only; AWS was statically validated and was not deployed.
- Data classification: synthetic fixtures only.
- Started: `2026-07-17T04:10:44Z`
- Finished: `2026-07-17T04:12:13Z`

## Checks

- [x] **mapping_lifecycle** — geo_point mapping, access 7d, parse-error 3d
- [x] **pipeline_latency_redaction** — arrival <=15s, XFF ignored, query redacted and body absent
- [x] **geoip_scope** — public City/ASN enrichment and TEST-NET exclusion verified
- [x] **parse_error** — malformed timestamp and numeric fields were quarantined with a reason
- [x] **deduplication** — two deliveries with the same trace.id produced one document
- [x] **queue_resilience** — Filebeat outage buffer delivered all events; Logstash restart did not duplicate them
- [x] **detection_alerts** — all six rule IDs produced alerts from localhost synthetic scenarios
- [x] **kibana_import** — saved objects and six rules imported twice with overwrite
- [x] **analyst_role** — analyst can read all dashboards; role exposes only read privileges
- [x] **container_secrets_ports** — no raw observability secret in inspect; 9200/9300 unpublished

## Dashboard evidence

Screenshots were captured at 1440×900 by the pinned Playwright 1.61.1 container while authenticated as the read-only `flare_analyst` user. No credential is included in this report.

- `overview.png`
- `geoip.png`
- `security.png`
