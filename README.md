# Flare Fitness

Flare Fitness chay doc lap bang Docker: Nginx phuc vu frontend Vite da build va reverse proxy `/api`; Spring Boot ket noi MySQL va Redis tren Docker network.

## Chạy Docker

Yeu cau: Docker Desktop hoac Docker Engine co Compose v2.

```sh
cp .env.example .env
# Điền APP_MAIL_* trong .env nếu cần gửi OTP qua SMTP.
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Sau khi health check thanh cong:

- Frontend: `http://localhost`
- API health: `http://localhost/api/health`
- MySQL (chi loopback): `localhost:3307`

Dừng và xóa dữ liệu phát triển:

```sh
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
```

`docker-compose.dev.yml` kích hoạt profile Spring `dev`; các tài khoản và sản phẩm
demo được nạp bằng repeatable Flyway migration, không phải MySQL init script:

- `dev_admin` / `DevAdmin#2026!`
- `dev_customer` / `DevCustomer#2026!`

Lệnh `docker compose up --build` không có profile fixture: database mới chỉ nhận
schema Flyway và không tạo tài khoản, PII, đơn hàng hay sản phẩm demo. Đây là
chế độ phù hợp để kiểm tra cấu hình production-like. Các file cũ trong `db-init/`
không còn được base Compose mount hay thực thi.

## Phat trien frontend

Yeu cau Node.js 22 va backend dang chay o cong `8080` (hoac dat `VITE_API_PROXY_TARGET`).

```sh
cd frontend
npm ci
npm run dev
```

Vite proxy `/api` den backend, vi vay cookie xac thuc va CSRF duoc kiem thu trong cung origin. Build production duoc Dockerfile `nginx/Dockerfile` thuc hien bang `npm ci && npm run build`.

## Kiem thu

Backend dung Testcontainers (MySQL va Redis), khong phu thuoc dich vu local:

```sh
cd backend
./mvnw test
```

E2E dùng stack tách biệt, Mailpit và fixture chỉ được nạp sau schema Flyway khi
profile `e2e` hoạt động:

```sh
docker compose -p flare-e2e --env-file .env.e2e.example \
  -f docker-compose.yml -f docker-compose.e2e.yml up -d --build

cd frontend
npm ci
npx playwright install chromium
E2E_BASE_URL=http://127.0.0.1:8088 npm run test:e2e

cd ..
docker compose -p flare-e2e --env-file .env.e2e.example \
  -f docker-compose.yml -f docker-compose.e2e.yml down -v
```

Playwright mac dinh dung Chromium do Playwright quan ly, khong phu thuoc
`/usr/bin/chromium`. Tren Linux runner moi, dung `npx playwright install --with-deps chromium`.
Video duoc tat mac dinh de E2E khong phu thuoc FFmpeg; bat khi can bang
`PLAYWRIGHT_VIDEO=1` sau khi cai dat browser/FFmpeg tuong ung.

Kiem tra nhanh frontend va asset:

```sh
cd frontend
npm run test
npm run test:coverage
npm run build
npm run assets:verify
```

Kiem tra Nginx sau khi sua proxy/header (can Docker va `curl`):

```sh
sh nginx/test-hardening.sh
sh scripts/verify-compose-hardening.sh
```

Script `assets:optimize` chuyen JPG/JPEG/PNG sang WebP va gioi han moi file 500 KB; `assets:migrate` cap nhat cac tham chieu frontend va seed SQL.

## OTP SMTP

- Cau hinh `APP_MAIL_USERNAME`, `APP_MAIL_FROM`, `APP_MAIL_PASSWORD` trong `.env`.
- Voi Gmail, dung App Password thay vi mat khau dang nhap thuong.
- Khi mail chua duoc cau hinh, API OTP tra loi loi cau hinh thay vi tao tai khoan hoac dat lai mat khau khi khong the gui email.

## AWS–ELK lab

Hai EC2, Filebeat mTLS, Elasticsearch/Logstash/Kibana, GeoIP và detection rules
được triển khai theo [PLAN_AWS_ELK.md](PLAN_AWS_ELK.md). Đây là HTTP lab bị giới
hạn bằng CIDR; không thay thế production có TLS.

## Production

- Dat `SPRING_PROFILES_ACTIVE=prod`. Backend se dung fail-fast neu cookie, JWT, CORS, datasource, database/Redis credential hoac trusted-proxy CIDR khong an toan; `.env.example` chi danh cho local development.
- Dat `APP_AUTH_COOKIE_SECURE=true` va ket thuc TLS tai load balancer/reverse proxy phia truoc Nginx.
- Chi cho phep Security Group cua ALB/reverse proxy truy cap port HTTP cua EC2/Docker host; khong mo port nay truc tiep cho Internet. Listener HTTP cong khai phai redirect sang HTTPS va certificate/TLS duoc quan ly tai ALB hoac edge proxy.
- Mac dinh Nginx **khong** tin `X-Forwarded-*` tu client. Chi dat `NGINX_TRUSTED_PROXY_CIDR` thanh **mot CIDR** private cua TLS terminator ngay truoc Nginx (ALB/reverse proxy); khong dung `0.0.0.0/0`, CIDR cua client hay danh sach phan cach bang dau phay. Backend co `server.forward-headers-strategy=none`, vi vay app container cung khong tu dien giai header forwarded do caller gui truc tiep.
- Tao gia tri ngau nhien rieng (toi thieu 16 ky tu) cho MySQL va Redis, va JWT toi thieu 32 ky tu; khong dung gia tri mau. `SPRING_DATASOURCE_USERNAME` phai la tai khoan khong phai `root`, co quyen toi thieu.
- Dat `APP_CORS_ALLOWED_ORIGINS` thanh danh sach origin HTTPS chinh xac, khong dung wildcard khi API gui cookie.
- Voi RDS/database nam ngoai Docker network, dat `SPRING_DATASOURCE_URL` co `sslMode=VERIFY_IDENTITY`; khong dung `useSSL=false`. URL MySQL `db` mac dinh chi dung cho private Compose network.
- `FLARE_INTERNAL_SUBNET` phai la subnet Docker rieng cho moi Compose project. Mac dinh `APP_TRUSTED_PROXY_CIDRS` tu dong bao gom subnet nay; neu override bien nay, phai giu subnet do trong danh sach de backend chi tin forwarding do Nginx chuyen tiep.
- Khong expose service `app` truc tiep: Compose chi publish Nginx, app chay non-root, read-only va khong co Linux capability. Chay `sh scripts/verify-compose-hardening.sh` trong CI/deploy review de kiem tra tat ca Compose variant khong mount `docker-entrypoint-initdb.d`/`db-init` va tat ca image da pin digest.
- Kiem tra AWS ngoai repository: Security Group/IAM least privilege, ACM/TLS certificate, RDS encryption-at-rest/in-transit, backup ma hoa bang KMS va restore drill. Cac cau hinh nay khong the duoc xac nhan chi bang Docker source.
- Flyway là nguồn schema duy nhất. Database hiện có phải được backup và thử restore
  trước khi nâng cấp; môi trường mới không cần hay không được import `schema_full.sql`.
- Sau migration V7, kiểm tra các hồ sơ chưa xử lý trong
  `tbl_kiem_toan_lien_ket_khach_hang` (`resolved_at IS NULL`). Chỉ liên kết thủ
  công khi có bằng chứng email/số điện thoại đã xác minh; không dùng họ tên.
- Migration V9 ghi các credential không phải BCrypt vào
  `tbl_tai_khoan_can_dat_lai_mat_khau` rồi xóa giá trị cũ bằng marker ngẫu nhiên.
  Thông báo người dùng đặt lại mật khẩu qua OTP; tài khoản không có email đã xác
  minh phải được xử lý qua quy trình xác minh thủ công, không khôi phục mật khẩu cũ.
