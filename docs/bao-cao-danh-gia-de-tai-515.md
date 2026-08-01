# Báo cáo đánh giá mức độ hoàn thiện đề tài 515

Ngày kiểm tra: 29/07/2026  
Phạm vi: source code và môi trường local/lab do chủ dự án sở hữu  
Kết luận ngắn: **đủ để bảo vệ theo kịch bản local/lab; chưa có bằng chứng triển khai AWS thật**

## A. Tóm tắt kết quả kiểm tra

Flare Fitness có kiến trúc rõ ràng và phù hợp đề tài 515:

- Frontend: HTML/CSS/JavaScript, đóng gói bằng Vite 6.4.3 và phục vụ qua Nginx.
- Backend: Java 21, Spring Boot 3.5.16, Maven, Spring Security, Spring Data JPA,
  Flyway, Redis và structured audit logging.
- Database: MySQL 8.4; Flyway là nguồn quản lý schema duy nhất.
- Runtime: Docker Compose gồm Nginx, backend, MySQL, Redis và Mailpit cho lab.
- Observability: Nginx JSON/ECS → Filebeat mTLS → Logstash persistent queue →
  Elasticsearch data stream → Kibana Discover/Dashboard/Maps/Detection.
- Hạ tầng: Terraform mô tả hai EC2 Web/Monitor và các bootstrap template; chỉ
  được kiểm tra tĩnh, không `apply` lên AWS.

Các module tìm thấy trong source gồm authentication/OTP, profile, catalog,
search/filter, cart, order, review, voucher/promotion, support chat, analytics
và vùng quản trị theo role. Cấu trúc `backend`, `frontend`, `nginx`,
`observability`, `terraform`, `scripts` và tài liệu được tách tương đối rõ.

Trong lượt hoàn thiện này, lỗi runtime Nginx trên named volume cũ đã được sửa:
container chạy UID 101 trước đây không mở được file log `root:root`. Service
khởi tạo một lần nay chuẩn hóa owner/mode trước khi Nginx và Filebeat chạy.

Không có thao tác deploy AWS, scan public, xóa volume, reset hoặc truncate
database. Tất cả payload SQLi/XSS/traversal/scanner đều là dữ liệu tổng hợp gửi
vào lab local.

## B. Điểm hoàn thiện tổng thể /100

| Nhóm | Điểm | Nhận xét |
|---|---:|---|
| Website/backend/frontend/database | 19/20 | Chức năng chính và phân quyền hoạt động; chưa chạy luồng OTP email thật trong lần kiểm tra này. |
| Deploy readiness Linux/EC2/Nginx/Docker | 12/15 | Docker và Terraform validate tốt; chưa có `terraform apply`, TLS/ACM và smoke test AWS thật. |
| Logging/access log/error log | 15/15 | JSON/ECS, correlation ID, latency, redaction và quarantine đầy đủ cho mục tiêu lab. |
| ELK/Filebeat/Logstash/Elasticsearch/Kibana | 20/20 | Stack 9.4.2 chạy thật và qua toàn bộ 11 kiểm tra runtime. |
| GeoIP/dashboard/visualization | 10/10 | City, ASN, map và ba dashboard đã có ảnh bằng tài khoản analyst read-only. |
| Detection rule/alert/anomaly | 9/10 | Sáu rule sinh alert; còn nên bổ sung rule admin trái phép chuyên biệt và correlation cho automation UA. |
| Test/báo cáo/demo readiness | 9/10 | Unit, integration, E2E, config và evidence tốt; thiếu bằng chứng AWS/HTTPS và OTP SMTP thật. |
| **Tổng** | **94/100** | **Rất tốt** |

Phần mạnh nhất là pipeline quan sát có thể chạy lặp lại, dữ liệu minh chứng rõ,
queue có kiểm tra phục hồi và quyền analyst chỉ đọc. Điểm bị trừ chủ yếu là
những nội dung không thể xác nhận nếu không có môi trường AWS/TLS và SMTP thật.

## C. Các chức năng website đã kiểm tra

Kết quả từ unit/integration test và Playwright trên image build từ working tree:

- Guest duyệt, tìm kiếm và lọc catalog; lỗi API không tạo dữ liệu sản phẩm giả.
- API catalog trả 401 không tạo vòng lặp request vô hạn.
- Đăng nhập customer/staff/admin và hiển thị đúng vùng chức năng theo role.
- Cookie authentication, CSRF và CORS same-origin hoạt động.
- Customer thêm sản phẩm vào giỏ hàng.
- Đăng xuất thu hồi session; đăng xuất lỗi không làm UI giả vờ đã thoát.
- Các race condition bootstrap/login/logout giữa nhiều tab không xóa session mới.
- Dữ liệu sản phẩm riêng của admin và support state được xóa khi logout.
- Quản lý sản phẩm admin và phân quyền staff/admin được kiểm tra bằng E2E.
- Service order, review, voucher, sync state, support và analytics có unit test.
- Error semantics 400/401/403/404 và database constraint được kiểm tra ở
  controller/security/exception tests; response không trả stack trace nội bộ.
- Flyway được integration-test từ schema trống và qua các mốc nâng cấp đến V11.

Chưa kiểm tra được trong lượt này:

- Gửi/nhận OTP qua SMTP thật cho đăng ký, đổi email hoặc đặt lại mật khẩu.
- Thanh toán qua cổng bên thứ ba, vì source không có integration thanh toán thật.
- UI trên Safari/Firefox; E2E hiện dùng Chromium desktop và mobile.

## D. Kết quả build/test

| Gate | Kết quả |
|---|---|
| `mvn -B verify` | PASS — 111 test, 0 fail/error/skip, package thành công |
| JaCoCo baseline | PASS — tất cả coverage check trong `pom.xml` đạt |
| Frontend unit | PASS — 26/26 test |
| Frontend coverage | PASS — statements 85.88%, branches 87.35%, functions 95.23%, lines 85.71% |
| Frontend production build | PASS — JS 407.66 kB, gzip 103.06 kB |
| Playwright E2E | PASS — 24/24, 12 scenario × desktop/mobile |
| `npm audit --audit-level=high` | PASS — 0 vulnerability |
| Nginx hardening test | PASS |
| Compose/deployment hardening | PASS |
| Observability config validation | PASS — shell, JSON/NDJSON, Compose, Filebeat, Logstash |
| Terraform fmt/init/validate | PASS — provider AWS 6.54.0, không tạo state AWS |
| Trivy Terraform config | PASS — 0 HIGH/CRITICAL misconfiguration |
| `git diff --check` | PASS |

Vitest và coverage đã được nâng đồng bộ lên 4.1.10, PostCSS lên 8.5.24 sau khi
audit registry mới báo dependency cũ có lỗ hổng High. Test, coverage và build
đều được chạy lại sau nâng cấp.

Lưu ý runtime: stack có sẵn tên `flare-e2e` tại cổng 8088 đang dùng image cũ nên
không phản ánh working tree. Stack cô lập `flare-e2e-final` build từ source hiện
tại tại cổng 18088 đã qua 24/24; sau test đã được `down` nhưng giữ volume.

## E. Kết quả kiểm tra logging

Nginx ghi JSON theo field gần ECS, gồm:

- `@timestamp`, `trace.id`, `source.ip`
- `http.request.method`, request bytes
- `url.path`, query đã redaction, URL tổng hợp an toàn
- `http.response.status_code`, response bytes
- `user_agent.original`, referrer
- request time và upstream response time

Backend có audit log cho action/outcome, actor/subject/resource và `traceId`.
Authentication success/failure, rate limit và exception được ghi theo hướng
phục vụ điều tra nhưng không log password, OTP, JWT, cookie, CSRF token hoặc body.
Global exception handler chỉ log loại lỗi/correlation ID và trả response chuẩn,
không lộ stack trace cho client.

Logstash:

- parse và ép kiểu timestamp/status/bytes/duration/IP;
- đưa event lỗi vào `logs-nginx.parse_error-lab` kèm lý do;
- redaction query value trước khi lưu;
- dùng fingerprint/`trace.id` để chống duplicate;
- chạy user-agent parser, GeoIP City/ASN và heuristic detection.

Log rotation Nginx và retention đã cấu hình: access data stream 7 ngày,
parse-error 3 ngày. Filebeat disk queue và Logstash persistent queue đều 1 GB.

## F. Kết quả kiểm tra ELK

Elastic Stack 9.4.2 đã chạy thật trong Compose local. Báo cáo runtime từ
11:21:35Z đến 11:23:25Z ngày 29/07/2026 đạt **11/11**:

1. mapping và lifecycle;
2. pipeline latency/redaction;
3. scanner enrichment;
4. GeoIP scope;
5. parse-error quarantine;
6. deduplication;
7. queue resilience;
8. detection alerts;
9. Kibana import idempotent;
10. analyst role read-only;
11. secret/port isolation.

Elasticsearch 9200/9300 và Logstash 5044 không publish ra host. Filebeat kết nối
Logstash bằng mTLS và xác minh SAN. Secret nằm trong file/keystore với quyền hạn
chế, không được nạp thô thành environment variable của container quan sát.

Evidence máy đọc được:

- [verification.json](evidence/local-elk/verification.json)
- [verification.md](evidence/local-elk/verification.md)

## G. Kết quả kiểm tra GeoIP

Pipeline lấy IP chuẩn từ `source.ip`. Public IP tổng hợp hợp lệ nhận:

- `source.geo.country_name`, city và location kiểu `geo_point`;
- thông tin Autonomous System/ASN.

Private, loopback, link-local, reserved và TEST-NET được gắn scope nhưng không
chạy GeoIP, tránh map sai. Runtime test đã xác nhận cả City/ASN public và trường
hợp TEST-NET bị loại. Dashboard evidence hiển thị dữ liệu public lab ở Ipswich,
United Kingdom và ASN tương ứng:

- [geoip.png](evidence/local-elk/geoip.png)

## H. Kết quả kiểm tra dashboard

Ba dashboard được import idempotent và đã kiểm tra có dữ liệu:

- [Overview](evidence/local-elk/overview.png): tổng request, timeline,
  phân bố status, P50/P95 latency, top path/method/source IP/user-agent.
- [GeoIP](evidence/local-elk/geoip.png): map, top country, city và ASN.
- [Security](evidence/local-elk/security.png): failed login, 401/403/404/429/5xx,
  loại/mức heuristic và bảng alert gần nhất.

Ảnh 1440×900 được chụp bằng Playwright 1.61.1 đã pin digest, đăng nhập tài khoản
`flare_analyst` chỉ đọc. Không có credential trong evidence. Bộ dashboard đủ rõ
để demo luồng request → log → enrichment → visualization → alert của đề tài 515.

## I. Kết quả kiểm tra detection rule/alert

Sáu rule enabled, interval một phút, đã sinh alert từ fixture local:

| Rule ID | Nội dung | Mức |
|---|---|---|
| `flare-lab-high-request-rate` | ≥100 request/source IP | Medium |
| `flare-lab-web-scan-404` | ≥20 response 403/404/source IP | Medium |
| `flare-lab-auth-bruteforce` | ≥5 login 401/429/source IP | High |
| `flare-lab-server-errors` | ≥5 response 5xx | High |
| `flare-lab-high-web-heuristic` | SQLi/XSS/path traversal signal | High |
| `flare-lab-scanner-user-agent` | sqlmap/Nikto/nmap/masscan/gobuster/ffuf/dirb… | Medium |

Các rule có `false_positives` và mô tả rõ đây là tín hiệu triage, không phải bằng
chứng khai thác. Script runtime kiểm tra Nikto, ffuf và dirb sau enrichment.
Generic `curl`/`python-requests` không tự động bị coi là scanner vì có false
positive cao; nên correlation với rate/status/path trước khi tạo alert. Truy cập
admin trái phép hiện được thấy qua 403/404 rule nhưng chưa có rule chuyên biệt.

## J. Kết quả kiểm tra bảo mật cơ bản

- Không tìm thấy AWS access key hoặc private key pattern trong source được track.
- `.env`/secret runtime được ignore; observability dùng file secret và keystore.
- Password người dùng dùng BCrypt-SHA256; migration V9 vô hiệu credential legacy
  không phải BCrypt và buộc quy trình reset qua OTP.
- JWT nằm trong HttpOnly cookie; CSRF token được gửi riêng cho mutation.
- Logout thu hồi allowlist token phía server và tránh race xóa cookie session mới.
- Backend fail-fast ở profile production nếu JWT, cookie, CORS, datasource,
  Redis, SMTP hoặc trusted proxy cấu hình yếu.
- Admin endpoint được bảo vệ theo role; E2E xác nhận staff/admin thấy đúng control.
- JPA/repository và validation giảm nguy cơ SQLi; không tìm thấy nối chuỗi SQL từ
  input trong phần code đã kiểm tra.
- DOM helper và regression test hạn chế unsafe HTML/XSS ở frontend.
- Nginx có security header, không tin X-Forwarded-* tùy ý và chạy non-root,
  read-only, drop capability.
- App không publish trực tiếp; MySQL chỉ bind loopback; Elasticsearch/Logstash
  không publish ra host.
- Terraform/Compose image quan trọng được pin và Trivy config scan sạch.

Điểm chưa xác nhận: IAM/Security Group thực tế, ACM/TLS, encryption/backup RDS,
domain public và credential rotation trên AWS. Đây là trạng thái bên ngoài source.

## K. Danh sách lỗi cần sửa ngay

Không còn lỗi Critical/High đã xác nhận trong source/local gate.

Trước buổi demo:

1. Không dùng stack `flare-e2e` cũ ở cổng 8088 làm bằng chứng; rebuild từ commit
   chuẩn hoặc dùng một project name/cổng sạch như quy trình trong mục N.
2. Nếu tuyên bố “đã deploy AWS”, phải bổ sung bằng chứng thật về URL HTTPS,
   health, Security Group, IAM và log từ Web EC2 đến Monitor. Hiện tại chỉ được
   phép nói “AWS path đã validate tĩnh”.
3. Không đưa lab HTTP ra Internet. Phải terminate TLS ở ALB/reverse proxy, dùng
   cookie Secure và giới hạn inbound bằng Security Group trước khi public.

## L. Danh sách lỗi nên sửa sau

1. Thêm E2E cho đăng ký/đổi email/reset password qua Mailpit và test OTP timeout,
   retry, replay.
2. Tách nhỏ `frontend/src/legacy/main.js`; bundle hiện khoảng 408 kB trước gzip.
3. Thêm rule riêng cho endpoint `/api/admin/**` bị 401/403 và correlation
   user-agent automation + request rate + status để giảm false positive.
4. Đặt threshold theo baseline traffic thật thay vì chỉ dùng ngưỡng lab cố định.
5. Thêm Firefox/WebKit vào nightly E2E nếu tài nguyên CI cho phép.
6. Sửa dần warning SQL MySQL 8.4 trong migration cũ: integer display width và
   `VALUES(col)` deprecated. Không sửa migration đã phát hành; tạo migration mới
   hoặc chỉ sửa generator/source cho schema mới.
7. Thực hiện restore drill cho backup database trước mọi migration production.
8. Với máy 16 GB chạy đồng thời nhiều stack, chụp dashboard sau khi dừng service
   lab không cần thiết hoặc chạy capture riêng để tránh Chromium bị OOM.

## M. Các file cần chỉnh sửa và lý do

Các nhóm file đã được hoàn thiện:

- `backend/src/main/...`: production validator, logout semantics, error response
  và các service tránh trả dữ liệu giả/nuốt lỗi.
- `backend/src/test/...`: bổ sung controller, exception, auth, order, review,
  promotion, sync và support regression tests.
- `frontend/src/core/*`, `frontend/src/legacy/main.js`: CSRF/auth sequencing,
  cache/private-state cleanup, error state và race-condition hardening.
- `frontend/tests/e2e/storefront.spec.js`: 12 scenario chạy desktop/mobile.
- `frontend/package*.json`: cập nhật dependency test/coverage/PostCSS đã vá.
- `nginx/*`, `docker-compose.yml`: non-root/read-only hardening và init quyền cho
  named volume log cũ.
- `observability/*`: pipeline validation/redaction, queue, monitor/deploy script,
  runtime verifier và evidence.
- `terraform/templates/*`: bootstrap/deployment hardening.
- `.github/workflows/ci.yml`, `scripts/verify-compose-hardening.sh`: tăng quality
  gate CI.
- `README.md`: lệnh dừng mặc định giữ volume và liên kết báo cáo.

File evidence được cập nhật dưới `docs/evidence/local-elk/`. Không có file nào bị
xóa và không có database/volume nào bị purge.

## N. Lệnh test đề xuất

Các lệnh dưới đây chỉ dùng local/lab. Thay `PROJECT`/port để tránh đụng stack khác.

```bash
# Backend: unit + integration + package + JaCoCo
cd backend
mvn -B verify

# Frontend: dependency, unit, coverage và production build
cd ../frontend
npm ci
npm test -- --run
npm run test:coverage
npm run build
npm audit --audit-level=high

# Cấu hình và hardening
cd ..
docker compose --env-file .env.example config --quiet
bash scripts/verify-compose-hardening.sh
bash nginx/test-hardening.sh
bash observability/scripts/validate-config.sh

# Terraform: KHÔNG apply
docker run --rm -v "$PWD/terraform:/work" -w /work \
  hashicorp/terraform:1.15.0 fmt -check -recursive
docker run --rm -v "$PWD/terraform:/work" -w /work \
  hashicorp/terraform:1.15.0 init -backend=false -lockfile=readonly
docker run --rm -v "$PWD/terraform:/work" -w /work \
  hashicorp/terraform:1.15.0 validate

# Full ELK local: sinh traffic tổng hợp, alert và ảnh dashboard
COMPOSE_PROJECT_NAME=flare-local-elk LOCAL_LAB_WEB_PORT=18089 \
  observability/scripts/local-lab.sh all
COMPOSE_PROJECT_NAME=flare-local-elk LOCAL_LAB_WEB_PORT=18089 \
  observability/scripts/local-lab.sh down
```

Smoke test thủ công an toàn khi stack local đang chạy:

```bash
curl -fsS http://127.0.0.1:18089/api/health
curl -fsS http://127.0.0.1:18089/api/products/query

# Chỉ dùng script fixture đối với lab local do mình sở hữu.
TARGET=http://127.0.0.1:18089 \
  observability/scripts/traffic-abnormal-owned-lab.sh
```

Không chạy `terraform apply`, không đổi `TARGET` sang host public và không dùng
`down -v` nếu chưa backup/xác nhận chủ động xóa dữ liệu.

## O. Checklist demo bảo vệ đề tài

- [ ] Checkout đúng commit/tag và ghi SHA vào slide.
- [ ] Xác nhận đủ RAM/disk; không chạy đồng thời nhiều stack không cần thiết.
- [ ] Chạy `local-lab.sh bootstrap` và `validate` trước ngày demo.
- [ ] Khởi động stack theo thứ tự bằng `local-lab.sh up`.
- [ ] Mở health website và Kibana bằng cổng loopback/lab.
- [ ] Trình bày Nginx JSON log và các field ECS quan trọng.
- [ ] Gửi một request bình thường, tìm theo `trace.id` trong Discover.
- [ ] Chạy fixture SQLi, XSS, traversal, scanner, 404, brute force và request rate.
- [ ] Chờ interval rule, mở Security dashboard và bảng alert.
- [ ] Mở GeoIP map; giải thích vì sao private/TEST-NET không được geolocate.
- [ ] Dừng Filebeat/Logstash theo verifier để trình bày disk/PQ resilience nếu đủ
  thời gian; không xóa volume.
- [ ] Đăng nhập `flare_analyst`, chứng minh dashboard đọc được nhưng không có quyền
  sửa/xóa saved object.
- [ ] Mở ba ảnh evidence dự phòng nếu trình duyệt/Kibana gặp sự cố.
- [ ] Nêu rõ dữ liệu là synthetic, không phải log người dùng thật.
- [ ] Trình bày sáu rule, threshold, severity và false-positive trade-off.
- [ ] Trình bày security boundary: chỉ Nginx publish; Elastic internal; mTLS;
  secret keystore; retention 7/3 ngày.
- [ ] Nếu có AWS thật, dùng URL/ảnh/health/log của môi trường đó; nếu chưa có,
  nói chính xác Terraform đã validate nhưng chưa apply.
- [ ] Kết thúc bằng `local-lab.sh down`, không dùng `down -v`.

## P. Kết luận: project đã đủ để bảo vệ đề tài 515 chưa

**Có, nếu bảo vệ theo mô hình local/lab hoặc môi trường tương đương và trình bày
đúng phạm vi.** Project chứng minh được toàn bộ chuỗi trọng tâm: website hoạt
động, Nginx tạo access log có cấu trúc, Filebeat/Logstash vận chuyển và xử lý,
Elasticsearch lưu trữ, GeoIP enrich, Kibana trực quan hóa và detection rule sinh
alert. Evidence và test tự động đủ tốt để demo lặp lại.

**Chưa đủ để khẳng định đã triển khai production trên AWS.** Muốn đưa tuyên bố đó
vào báo cáo/slide, cần một lượt triển khai được chủ dự án phê duyệt và bằng chứng
TLS, Security Group/IAM, health, log shipping, backup/restore. Việc này không
được thực hiện trong lần kiểm tra vì yêu cầu an toàn cấm deploy AWS khi chưa hỏi.

Các điểm phù hợp CV hướng SOC/SIEM:

- Thiết kế pipeline ECS Nginx → Filebeat mTLS → Logstash PQ → Elasticsearch.
- GeoIP City/ASN, data stream lifecycle và parse-error quarantine.
- Kibana dashboard/Maps/Security và RBAC analyst read-only.
- Sáu detection rule với threshold, severity và false-positive notes.
- Test queue resilience, deduplication, latency, secret/port isolation.
- Infrastructure as Code bằng Terraform cùng CI security/config gates.
