# Công nghệ HikariCP

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 12. Công nghệ HikariCP

### 12.1. Khái niệm

HikariCP là connection pool cho database. Một connection MySQL là kết nối mạng có trạng thái giữa backend và MySQL; tạo mới connection cho mọi request sẽ tốn thời gian và tài nguyên.

HikariCP giữ sẵn một nhóm connection:

- Request cần database thì mượn connection.
- Query xong thì trả connection về pool.
- Request sau tái sử dụng connection đó.

Spring Boot/JPA tự tích hợp HikariCP. Service và repository không gọi HikariCP trực tiếp.

### 12.2. Vị trí của HikariCP trong chương trình

```text
Controller
→ Service
→ Spring Data JPA Repository
→ Hibernate
→ HikariCP
→ MySQL
```

Ví dụ `ProductRepository.searchProducts()` cần truy vấn MySQL. Hibernate xin connection từ `FlareFitnessHikariPool`, chạy query, sau đó trả connection về pool.

### 12.3. Cấu hình hiện tại

Các giá trị nằm trong `backend/src/main/resources/application.properties`:

| Cấu hình | Giá trị | Ý nghĩa |
| --- | ---: | --- |
| `pool-name` | `FlareFitnessHikariPool` | Tên pool xuất hiện trong log. |
| `maximum-pool-size` | `50` | Tối đa 50 connection được pool quản lý. |
| `minimum-idle` | `10` | Cố gắng duy trì ít nhất 10 connection rảnh. |
| `connection-timeout` | `30000ms` | Chờ tối đa 30 giây để mượn connection trước khi báo lỗi. |
| `idle-timeout` | `600000ms` | Connection rảnh có thể được đóng sau 10 phút. |
| `max-lifetime` | `1800000ms` | Connection được thay mới sau tối đa khoảng 30 phút. |

Log runtime xác nhận pool đang hoạt động:

```text
FlareFitnessHikariPool - Starting...
FlareFitnessHikariPool - Added connection ...
FlareFitnessHikariPool - Start completed.
```

### 12.4. Luồng hoạt động thực tế

```text
Nhiều request API đến đồng thời
→ mỗi request chạy service/repository
→ repository cần connection MySQL
→ HikariCP:
   ├── có connection rảnh: cấp ngay
   ├── chưa đạt maximum: có thể tạo thêm
   └── pool đang bận: request chờ tối đa connection-timeout
→ query hoàn thành
→ connection được trả lại pool
```

Ví dụ khi nhiều người đồng thời:

- xem sản phẩm;
- đặt đơn hàng;
- xem đơn hàng;
- gửi đánh giá;
- đăng nhập;

các request có thể dùng các connection khác nhau trong pool thay vì phải lần lượt dùng một connection hoặc mở connection mới liên tục.

### 12.5. Tác dụng thực tế

- Giảm độ trễ khi truy vấn vì phần lớn connection đã được tạo sẵn.
- Giới hạn số connection backend được phép tạo, tránh MySQL bị mở connection không kiểm soát.
- Hỗ trợ transaction của Spring trong các service như tạo đơn hàng.
- Khi database bận, request chờ có giới hạn thay vì chờ vô thời hạn.
- Giúp các API phân trang, tìm kiếm và đặt hàng hoạt động ổn định hơn khi có nhiều request đồng thời.

### 12.6. Điều HikariCP không làm

HikariCP chỉ quản lý connection. Nó không:

- làm một câu SQL chậm trở thành nhanh;
- thay thế index;
- cache kết quả query;
- thay thế Redis;
- thay thế transaction/logic nghiệp vụ.

Muốn query nhanh vẫn cần index, pagination và truy vấn hợp lý. HikariCP chỉ giảm chi phí lấy connection để chạy query đó.

### 12.7. Hiệu năng, ưu điểm và giới hạn

Mượn/trả connection trong pool thường gần O(1). Chi phí lớn vẫn nằm ở SQL, số dòng đọc và thời gian MySQL xử lý.

Ưu điểm:

- Tái sử dụng connection nhanh.
- Kiểm soát concurrency tới MySQL.
- Có timeout và vòng đời connection rõ ràng.
- Được Spring Boot hỗ trợ trực tiếp.

Giới hạn:

- `maximum-pool-size=50` và `minimum-idle=10` có thể khá cao đối với VPS nhỏ; cần theo dõi CPU, RAM, số connection MySQL và tải thực tế.
- Pool quá nhỏ làm request phải chờ; pool quá lớn có thể làm MySQL quá tải.
- Nếu query giữ connection quá lâu, các request khác vẫn phải chờ dù pool được cấu hình tốt.

### 12.8. Phân biệt Nginx, Redis và HikariCP

| Công nghệ | Nằm ở đâu trong luồng | Quản lý cái gì | Không dùng để làm gì |
| --- | --- | --- | --- |
| Nginx | Trước backend | HTTP request, static file, reverse proxy, rate limit chung | Không lưu đơn hàng và không chạy nghiệp vụ Java |
| Redis | Bên cạnh backend/MySQL | Token, OTP, counter, cache và dữ liệu có TTL | Không phải database nghiệp vụ chính |
| HikariCP | Giữa JPA/Hibernate và MySQL | Connection MySQL đang mở | Không cache dữ liệu và không tự tối ưu SQL |

Ví dụ một request xem sản phẩm có thể đi qua cả ba:

```text
Trình duyệt
→ Nginx chuyển /api/products vào backend
→ ProductService kiểm tra Redis cache
→ nếu cache miss, Repository mượn connection từ HikariCP để query MySQL
→ ProductService ghi kết quả vào Redis
→ response quay lại qua Nginx
```
