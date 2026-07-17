# Công nghệ Nginx

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 10. Công nghệ Nginx

### 10.1. Khái niệm

Nginx là web server và reverse proxy. Trong project này, Nginx là điểm vào đầu tiên của website: trình duyệt không truy cập trực tiếp Spring Boot mà gửi request đến Nginx qua cổng `80`.

- **Web server**: đọc và trả các file tĩnh như HTML, JavaScript, CSS và ảnh.
- **Reverse proxy**: nhận request API từ người dùng rồi chuyển tiếp vào backend.
- **Gateway bảo vệ ban đầu**: giới hạn tốc độ request và xử lý CORS preflight trước khi request tới Java.

### 10.2. Nginx được cấu hình ở đâu

- `docker-compose.yml`: tạo container `flare-fitness-nginx`, publish `80:80`.
- `docker-compose.yml`: mount `Front end/` vào `/usr/share/nginx/html`.
- `docker-compose.yml`: mount `nginx/nginx.conf` vào container.
- `nginx/nginx.conf`: định nghĩa domain, static root, proxy API, rate limit và SPA fallback.

```text
Trình duyệt
   ↓ http://domain hoặc http://localhost
Nginx :80
   ├── /api/*  → Spring Boot app:8080
   └── URL khác → file trong Front end/
```

### 10.3. Cách Nginx được áp dụng trong chương trình

#### Phục vụ frontend

```nginx
root /usr/share/nginx/html;
index index.html;

location / {
    try_files $uri $uri/ /index.html;
}
```

Khi trình duyệt yêu cầu `/assets/main.js` hoặc ảnh sản phẩm, Nginx trả file trực tiếp mà không gọi Spring Boot. `try_files ... /index.html` giúp các URL giao diện không tìm thấy file vật lý vẫn quay về trang chính.

#### Chuyển tiếp API

```nginx
location /api/ {
    set $app_upstream http://app:8080;
    proxy_pass $app_upstream;
}
```

Hostname `app` là tên service Docker Compose. Docker DNS tự phân giải `app` thành IP nội bộ của container Spring Boot.

Ví dụ:

```text
GET http://localhost/api/products
→ Nginx nhận ở cổng 80
→ chuyển sang http://app:8080/api/products
→ ProductController xử lý
```

#### Chuyển thông tin request gốc

Nginx gửi các header:

- `Host`: domain người dùng truy cập.
- `X-Real-IP`: IP kết nối tới Nginx.
- `X-Forwarded-For`: IP được chuyển cho backend.
- `X-Forwarded-Proto`: giao thức HTTP/HTTPS ban đầu.

Backend dùng thông tin IP cho rate limit đăng nhập. Code chỉ tin forwarded header khi request đi qua proxy đáng tin cậy được cấu hình trong `APP_TRUSTED_PROXY_CIDRS`.

#### Giới hạn tốc độ API

```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=30r/s;
limit_req zone=api_limit burst=60 nodelay;
```

- Mỗi IP được duy trì trung bình `10 request/giây`.
- Cho phép burst ngắn tối đa `20` request.
- Khi vượt giới hạn, Nginx có thể trả HTTP `429` trước khi request tới backend.

Đây là rate limit chung cho `/api/`. Ngoài ra backend còn có rate limit đăng nhập sai bằng Redis, tối đa mặc định `5` lần/phút/IP.

### 10.4. Tác dụng thực tế

- Spring Boot tập trung xử lý JSON/API, không tốn tài nguyên phục vụ ảnh và file frontend.
- Người dùng chỉ cần một domain/cổng duy nhất; không cần biết backend chạy ở `8080`.
- Chặn một phần request quá nhanh trước khi chúng chiếm thread Java hoặc connection MySQL.
- Có thể thêm HTTPS, cache static, nén gzip hoặc load balancing sau này mà không cần sửa nghiệp vụ backend.

### 10.5. Hiệu năng, ưu điểm và giới hạn

Route lookup và kiểm tra rate-limit theo IP có chi phí gần O(1) cho mỗi request. Nginx rất phù hợp cho static file và reverse proxy vì dùng mô hình xử lý sự kiện nhẹ.

Ưu điểm:

- Phục vụ static file nhanh.
- Tách cổng public khỏi backend nội bộ.
- Có rate limit và retry khi backend trả `502`, `503`, `504`.
- Dễ thêm SSL/TLS cho domain khi deploy.

Giới hạn:

- Nginx hiện là một container duy nhất; nếu container này dừng, website mất điểm vào.
- Chưa cấu hình load balancing nhiều backend.
- Cần cấu hình HTTPS/chứng chỉ riêng khi deploy production.
