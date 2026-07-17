# Flare AWS–ELK Lab

Đây là runbook triển khai thay cho checklist cấp cao. Ứng dụng, REST API và
schema hiện có không thay đổi; repository chỉ mở rộng observability và AWS.

```text
tester /32 ─HTTP 80→ Web Elastic IP → EC2 Web: Nginx, Spring, MySQL, Redis, Filebeat
                                         │ mTLS TCP 5044 → 10.20.10.20
admin /32 ─SSH──────→ Monitor Elastic IP → EC2 Monitor: Logstash, Elasticsearch, Kibana
                                                        └─ 127.0.0.1:5601 via SSH tunnel
```

## Artefact và kiểm tra

| Mục tiêu | Artefact | Validation |
| --- | --- | --- |
| JSON/ECS log, anti-spoof IP, request ID, redaction | `nginx/nginx.conf`, `nginx/test-hardening.sh` | `sh nginx/test-hardening.sh` |
| Filebeat disk queue/mTLS | `observability/filebeat/filebeat.yml` | `validate-config.sh` |
| Logstash ECS/GeoIP/heuristic/parse error | `observability/logstash/` | `logstash -t` |
| ES/Kibana/Logstash Monitor | `observability/docker-compose.monitor.yml` | healthchecks |
| templates, lifecycle and least privilege | `observability/elasticsearch/`, `setup-elastic.sh` | `_data_stream/*/_lifecycle` |
| Space, data view, saved objects, six rules | `observability/kibana/`, `setup-kibana.sh` | Space `Flare Lab` |
| VPC, EIP, SG, IAM, EBS, Budget | `terraform/` | `terraform fmt/init/validate` |
| deploy, logrotate, owned traffic scripts | `observability/scripts/` | theo runbook bên dưới |

## Thiết kế chốt

- Region `ap-southeast-1`; VPC `10.20.0.0/16`; public subnet
  `10.20.10.0/24`; Web `10.20.10.10`; Monitor `10.20.10.20`.
- Web `t3.medium`, root encrypted gp3 40 GB. Monitor `t3.large`, root 20 GB,
  Elasticsearch data encrypted gp3 80 GB. Đây là lab một AZ, không HA.
- Elastic Stack cùng phiên bản `9.4.2`, image digest linux/amd64. ES 1 primary,
  0 replica, heap 3 GB; Logstash heap 768 MB và persistent queue 1 GB.
- Web SG: 80 từ `tester_cidrs`, 22 từ `admin_cidrs`. Monitor SG: 22 từ admin,
  5044 từ Web SG. Không có inbound 5601/9200/9300/3306/6379.

## Local validation

```sh
./observability/scripts/bootstrap-secrets.sh
./observability/scripts/validate-config.sh
```

PKI/password chỉ được sinh ở `.secrets/observability` (0700/0600), không được
commit. Script từ chối ghi đè secret cũ. Sau local test có thể xóa thư mục này.

## Provision AWS

```sh
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Điền admin/tester CIDR, SSH public key và budget email; không dùng private key.
terraform init
terraform plan
terraform apply
```

Review port, IAM và cost trước `apply`. State local không có app password/PKI;
backup state được mã hóa ngoài Git. Sau khi chấm, export evidence, chạy
`terraform destroy`, rồi xác nhận hai EIP và EBS data đã bị xóa.

## Deploy theo thứ tự

1. Tạo `/opt/flare/.env` trên Web từ `.env.aws.example`, thay tất cả
   placeholder. Dùng fixture `dev` chỉ cho HTTP lab: CORS đúng
   `http://<web-eip>`, `NGINX_PUBLIC_SERVER_NAME=<web-eip>`, Secure cookie false.
2. `MONITOR_HOST=ubuntu@<monitor-eip> ./observability/scripts/deploy-monitor.sh`.
3. Copy **chỉ** `.secrets/observability/web/` theo lệnh script in ra; không copy
   CA key, server key hay `monitor.env` sang Web.
4. `WEB_HOST=ubuntu@<web-eip> ./observability/scripts/deploy-web.sh`.
5. `ssh -L 5601:127.0.0.1:5601 ubuntu@<monitor-eip>` rồi mở Kibana local.

Rollback bằng cấu hình/image trước đó và `docker compose up -d`; không dùng
`down -v` vì sẽ xóa queue/data.

## Acceptance and demo

- `curl -i http://<web-eip>/api/health`; request phải xuất hiện trong Discover
  `logs-nginx.access-lab` trong khoảng 15 giây, có `trace.id`, real `source.ip`,
  duration nanoseconds và URL/HTTP ECS fields.
- IP public có `source.geo.*`, `source.as.*`, `source.geo.location`; IP private
  được `flare.source_ip_scope`, không coi là lỗi pipeline. Access retention 7d,
  parse-error retention 3d.
- Mọi query có giá trị đều là `[REDACTED]`, nên không thể lộ PII/credential kể
  cả khi tên key URL-encode. Nginx phân loại SQLi/XSS/traversal trước khi che;
  log không có body, cookie, JWT, Authorization hoặc CSRF header.

```sh
FLARE_LAB_TARGET=http://<web-eip> ./observability/scripts/traffic-normal.sh
I_OWN_THIS_TARGET=yes FLARE_LAB_TARGET=http://<web-eip> \
  FLARE_LAB_ALLOWED_HOST=<web-eip> ./observability/scripts/traffic-abnormal-owned-lab.sh
LOCAL_FIXTURE_CONFIRM=yes ./observability/scripts/replay-5xx-fixture.sh
```

Kịch bản có ≥100 request/IP, ≥20 403/404/IP, ≥5 login 401/429/IP, ≥5 5xx
fixture local, SQLi/XSS/traversal signal và scanner User-Agent. Alerts chỉ là
tín hiệu triage; dùng traffic sở hữu và chờ rule interval một phút.

## Linux/AWS/ELK troubleshooting

| Symptom | Check đầu tiên | Resolution |
| --- | --- | --- |
| Filebeat TLS error | cert path/mode, `openssl s_client` | Copy đúng web bundle, giữ verification mode full |
| Logstash parse error | `flare.parse_error_reason` | Sửa JSON contract, không dừng pipeline |
| GeoIP empty | `source.ip`, `flare.source_ip_scope` | Private/test-net bị skip có chủ ý; test NAT public |
| Kibana remote fail | Đây là expected | Dùng SSH tunnel, không mở SG/port 5601 |
| ES bootstrap fail | `sysctl`, `findmnt /srv/elastic`, health | Check cloud-init, volume mount, RAM |
| Rule không fire | time picker, lookback/index | Chờ interval, dùng index exact và fixture 5xx |
