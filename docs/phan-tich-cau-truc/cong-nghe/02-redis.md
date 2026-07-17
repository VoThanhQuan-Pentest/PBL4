# Công nghệ Redis

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 11. Công nghệ Redis

### 11.1. Khái niệm

Redis là kho dữ liệu key-value chạy chủ yếu trong RAM. Redis phù hợp với dữ liệu cần đọc/ghi rất nhanh, tồn tại tạm thời hoặc cần tự hết hạn bằng TTL.

Redis **không thay thế MySQL** trong project:

- MySQL lưu dữ liệu lâu dài: tài khoản, sản phẩm, đơn hàng, đánh giá.
- Redis lưu dữ liệu tạm/cache: token, OTP, bộ đếm đăng nhập, cache sản phẩm và recommendation.

### 11.2. Redis được kết nối như thế nào

```text
Spring Boot app
   ↓ StringRedisTemplate
RedisConnectionFactory
   ↓ redis:6379 trong Docker network
flare-fitness-redis
```

- `docker-compose.yml` tạo service Redis bằng image `redis:7-alpine`.
- Backend nhận hostname `redis` qua `SPRING_DATA_REDIS_HOST`.
- `RedisConfig` tạo bean `StringRedisTemplate`.
- Các service inject `StringRedisTemplate` để thực hiện `GET`, `SET`, `INCREMENT`, `EXPIRE`, `DELETE`.
- `spring.data.redis.repositories.enabled=false` vì chương trình dùng Redis như key-value/cache qua template, không ánh xạ Redis thành repository/entity.
- Redis chạy với `--save 20 1`, tạo snapshot RDB khi có thay đổi; Redis vẫn được xem là tầng dữ liệu tạm, không phải nguồn dữ liệu nghiệp vụ chính.
- Redis không publish cổng ra host/public, chỉ các container trong Docker network truy cập được.

### 11.3. Redis được áp dụng vào đâu

| Chức năng | Key/prefix | TTL mặc định | Code sử dụng |
| --- | --- | ---: | --- |
| Token đăng nhập hợp lệ | `auth:token:<jwt>` | Theo thời hạn JWT, mặc định 24 giờ | `RedisTokenStore`, `JwtAuthenticationFilter`, `AuthService` |
| Số lần đăng nhập sai theo IP | `auth:login-attempt:<ip>` | 1 phút | `IpRateLimitService` |
| OTP email | `auth:otp:<purpose>:<email>` | 300 giây | `EmailOtpService` |
| Cooldown gửi lại OTP | `auth:otp:cooldown:<purpose>:<email>` | 60 giây | `EmailOtpService` |
| Cache một sản phẩm | `cache:product:<id>` | 300 giây | `ProductService` |
| Cache toàn bộ danh sách sản phẩm | `cache:products:all` | 300 giây | `ProductService` |
| Cache recommendation | `cache:recommendation:<context>` | 900 giây | `BehaviorAnalyticsService` |
| Cache popularity recommendation | `cache:recommendation:popularity` | 300 giây | `BehaviorAnalyticsService` |

### 11.4. Các luồng Redis quan trọng

#### Token đăng nhập và logout

```text
Đăng nhập đúng
→ backend tạo JWT
→ RedisTokenStore.save(token, username, TTL)
→ mỗi request: JwtAuthenticationFilter kiểm tra token có trong Redis
→ logout: RedisTokenStore.revoke(token)
```

JWT thông thường vẫn hợp lệ đến khi hết hạn. Việc lưu token trong Redis giúp chương trình thu hồi token ngay khi logout.

#### Rate limit đăng nhập sai

```text
Đăng nhập sai
→ INCREMENT auth:login-attempt:<ip>
→ lần đầu đặt EXPIRE 1 phút
→ nếu counter >= 5, backend trả HTTP 429
→ đăng nhập đúng thì xóa counter
```

Counter Redis phù hợp vì `INCREMENT` là thao tác atomic; nhiều request đồng thời không làm mất số đếm.

#### OTP có thời hạn

```text
Gửi OTP
→ lưu mã OTP với TTL 300 giây
→ lưu cooldown 60 giây
→ xác minh: GET OTP
→ đúng thì DELETE OTP và cooldown
→ hết TTL thì Redis tự xóa
```

Không cần job nền để xóa OTP hết hạn và không làm bảng MySQL tăng liên tục.

#### Cache-aside sản phẩm

```text
GET sản phẩm
→ kiểm tra Redis
   ├── cache hit: parse JSON và trả ngay
   └── cache miss: query MySQL → ghi Redis → trả response

Thêm/sửa/xóa sản phẩm
→ cập nhật MySQL
→ xóa cache liên quan
→ request tiếp theo nạp dữ liệu mới
```

#### Cache recommendation

Recommendation cần đọc hành vi và chấm điểm nhiều sản phẩm. Sau lần tính đầu tiên, kết quả được lưu Redis theo user/session/context. Request lặp lại trong TTL có thể trả cache mà không tính lại.

### 11.5. Tác dụng thực tế

- Giảm số lần truy vấn MySQL cho dữ liệu đọc nhiều.
- Cho phép logout JWT có hiệu lực ngay.
- Chặn brute-force đăng nhập theo IP.
- Tự động hết hạn OTP, token và cache.
- Chia sẻ cache/token giữa nhiều backend instance nếu hệ thống mở rộng.

### 11.6. Hiệu năng, ưu điểm và giới hạn

Các thao tác key đơn như `GET`, `SET`, `DELETE`, `EXISTS`, `INCREMENT` thường gần O(1). Tuy nhiên, dữ liệu JSON lớn vẫn cần O(n) để serialize/parse theo kích thước payload.

Ưu điểm:

- Tốc độ cao do dữ liệu chủ yếu nằm trong RAM.
- TTL và counter atomic phù hợp OTP/rate-limit/token.
- Giảm tải MySQL và giảm thời gian phản hồi.

Giới hạn:

- Nếu Redis mất dữ liệu, token đang hoạt động, OTP và cache tạm thời có thể mất; dữ liệu đơn hàng/sản phẩm trong MySQL không mất.
- Cache cần được xóa đúng lúc sau khi dữ liệu gốc thay đổi.
- Redis dùng RAM, vì vậy không nên lưu payload không giới hạn.
