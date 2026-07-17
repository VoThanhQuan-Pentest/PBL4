# Bốn tính chất hướng đối tượng

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 2. Bốn tính chất hướng đối tượng trong chương trình

### 2.1. Đóng gói

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/entity/Product.java:11`: `Product extends BaseEntity`.
- `backend/src/main/java/com/flarefitness/backend/entity/Product.java:15` đến `Product.java:54`: các field sản phẩm là `private`.
- `backend/src/main/java/com/flarefitness/backend/entity/Order.java:16` đến `Order.java:64`: các field đơn hàng là `private`.
- `backend/src/main/java/com/flarefitness/backend/service/ProductService.java:24`: service đóng gói nghiệp vụ sản phẩm.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:46`: service đóng gói nghiệp vụ đơn hàng.
- `backend/src/main/java/com/flarefitness/backend/service/ProductReviewService.java:27`: service đóng gói nghiệp vụ đánh giá.

**Cách thể hiện**

Entity không để controller/frontend thao tác trực tiếp vào database. Controller nhận request, gọi service; service kiểm tra rule, thao tác repository rồi trả DTO. Ví dụ:

- `ProductService.createProduct()` kiểm tra SKU trùng và validate URL ảnh trước khi lưu ở `backend/src/main/java/com/flarefitness/backend/service/ProductService.java:83`.
- `OrderService.createOrder()` tự tính tiền, gắn customer, lưu địa chỉ snapshot, lưu order item ở `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:97`.
- `ProductReviewService.createReview()` kiểm tra đơn đã giao và chưa đánh giá trùng ở `backend/src/main/java/com/flarefitness/backend/service/ProductReviewService.java:68`.

**Tác dụng**

- Bảo vệ trạng thái của entity: code bên ngoài không thay đổi trực tiếp các field `private` mà phải đi qua phương thức hoặc service phù hợp.
- Gom toàn bộ luật nghiệp vụ vào một nơi. Ví dụ mọi cách tạo đánh giá đều phải đi qua `ProductReviewService.createReview()`, nên không thể bỏ qua kiểm tra đơn đã giao hoặc kiểm tra đánh giá trùng.
- Giữ dữ liệu đơn hàng nhất quán: `OrderService.createOrder()` chịu trách nhiệm tính tiền, gắn khách hàng, lưu địa chỉ snapshot và order item trong cùng luồng nghiệp vụ.
- Giảm rủi ro bảo mật và dữ liệu sai vì controller không được gọi repository để ghi dữ liệu tùy ý.
- Dễ sửa và kiểm thử: khi thay đổi quy tắc URL ảnh, hủy đơn hoặc đổi trả, chỉ cần sửa service sở hữu nghiệp vụ thay vì tìm nhiều controller/frontend khác nhau.

### 2.2. Kế thừa

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/entity/BaseEntity.java:8`: `BaseEntity`.
- `backend/src/main/java/com/flarefitness/backend/entity/BaseEntity.java:11`: field chung `createdAt`.
- `backend/src/main/java/com/flarefitness/backend/entity/Product.java:11`: `Product extends BaseEntity`.
- `backend/src/main/java/com/flarefitness/backend/entity/Order.java:12`: `Order extends BaseEntity`.
- `backend/src/main/java/com/flarefitness/backend/entity/ProductReview.java:10`: `ProductReview extends BaseEntity`.
- `backend/src/main/java/com/flarefitness/backend/entity/Customer.java:14`: `Customer extends BaseEntity`.

**Cách thể hiện**

Các entity dùng chung thời điểm tạo bản ghi từ `BaseEntity`, tránh khai báo lặp lại cùng một field trong từng entity.

**Tác dụng**

- Tái sử dụng thuộc tính chung `createdAt` cho sản phẩm, đơn hàng, khách hàng, đánh giá và các entity khác.
- Bảo đảm các entity có cách ánh xạ ngày tạo thống nhất, giúp sắp xếp sản phẩm mới, đơn hàng mới và đánh giá mới theo cùng một quy ước.
- Khi cần thay đổi cách lưu hoặc ánh xạ thuộc tính chung, chỉ cần sửa `BaseEntity`, giảm nguy cơ mỗi entity khai báo khác nhau.
- Giảm số dòng code lặp lại và làm entity con tập trung vào dữ liệu nghiệp vụ riêng.

**Ưu điểm**

- Giảm trùng lặp code.
- Nếu cần mở rộng metadata chung cho entity, có thể thêm ở lớp cha.

**Nhược điểm**

- Nếu entity nào không cần field chung vẫn bị kế thừa.
- Nếu lớp cha phình to, các entity con bị phụ thuộc không cần thiết.

### 2.3. Đa hình

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/repository/ProductRepository.java:8`: `ProductRepository extends JpaRepository<Product, String>`.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderRepository.java:10`: `OrderRepository extends JpaRepository<Order, String>`.
- `backend/src/main/java/com/flarefitness/backend/repository/ProductReviewRepository.java:7`: `ProductReviewRepository extends JpaRepository<ProductReview, String>`.
- `backend/src/main/java/com/flarefitness/backend/repository/CustomerRepository.java:9`: `CustomerRepository extends JpaRepository<Customer, String>`.

**Cách thể hiện**

Service chỉ phụ thuộc vào interface repository. Spring Data JPA sinh implementation runtime. Ví dụ `ProductService` gọi `productRepository.findAllByOrderByCreatedAtDesc()` ở `backend/src/main/java/com/flarefitness/backend/service/ProductService.java:59` mà không cần biết implementation SQL cụ thể được tạo như thế nào.

**Tác dụng**

- Service gọi cùng một tập phương thức repository nhưng Spring Data JPA cung cấp implementation phù hợp cho từng entity tại runtime.
- `JpaRepository<Product, String>`, `JpaRepository<Order, String>` và `JpaRepository<ProductReview, String>` cùng hỗ trợ các thao tác như `findById`, `save`, `saveAll` và `deleteById`, nhưng mỗi repository xử lý đúng kiểu entity của nó.
- Có thể thay đổi từ derived query sang JPQL/native query hoặc thêm index mà phần lớn code service không phải thay đổi.
- Dễ mock repository khi viết unit test cho service vì service phụ thuộc interface thay vì một implementation SQL cụ thể.
- Giảm phụ thuộc trực tiếp vào MySQL trong lớp nghiệp vụ và giúp code dễ mở rộng hơn khi thêm entity hoặc truy vấn mới.

### 2.4. Trừu tượng hóa

**Vị trí code**

- DTO request/response trong `backend/src/main/java/com/flarefitness/backend/dto/`.
- Controller gọi service, service gọi repository.
- `StringRedisTemplate` được cấu hình ở `backend/src/main/java/com/flarefitness/backend/config/RedisConfig.java`.
- `JpaRepository` được dùng qua các repository interface.

**Cách thể hiện**

Frontend/backend không trao đổi trực tiếp entity database. API dùng DTO. Backend không tự viết JDBC thô cho phần CRUD chính mà dùng Spring Data JPA để trừu tượng hóa truy vấn.

**Tác dụng**

- Controller chỉ cần biết service cung cấp chức năng gì, không cần biết cách validate, cache hoặc truy vấn database bên trong.
- Service chỉ cần gọi repository và `StringRedisTemplate`, không cần tự quản lý JDBC connection hoặc tự cài đặt giao thức Redis.
- Repository che giấu SQL/JPA implementation; entity che giấu chi tiết tên bảng và tên cột khỏi controller/frontend.
- DTO chỉ công khai dữ liệu API cần thiết, tránh trả trực tiếp toàn bộ entity hoặc các field nhạy cảm như password.
- Có thể thay đổi implementation nội bộ, ví dụ tối ưu query, thêm Redis cache hoặc đổi cấu hình HikariCP, mà vẫn giữ API response ổn định cho frontend.
- Phân chia trách nhiệm rõ ràng giúp tìm lỗi nhanh hơn: lỗi HTTP ở controller, lỗi nghiệp vụ ở service, lỗi query ở repository và lỗi ánh xạ ở entity.
