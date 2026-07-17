# Thuật toán truy vấn cơ sở dữ liệu

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 8. Thuật toán truy vấn cơ sở dữ liệu

### 8.1. Repository query bằng Spring Data JPA

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/repository/ProductRepository.java:10`: `findAllByOrderByCreatedAtDesc()`.
- `backend/src/main/java/com/flarefitness/backend/repository/ProductRepository.java:12`: `findBySkuIgnoreCase(String sku)`.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderRepository.java:12`: query lấy tất cả đơn chưa xóa, sort mới nhất.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderRepository.java:15`: query đơn theo `userId`.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderRepository.java:18`: query đơn theo `customerId`.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderRepository.java:24`: query đơn theo `maDon`.
- `backend/src/main/java/com/flarefitness/backend/repository/ProductReviewRepository.java:13`: query review theo product/status sort mới nhất.

**Thuật toán / cơ chế**

Project dùng Spring Data JPA:

- Query method tự sinh SQL từ tên hàm, ví dụ `findBySkuIgnoreCase`.
- JPQL `@Query` cho điều kiện soft delete và sort.
- MySQL xử lý lọc/sort bằng B-tree index nếu phù hợp.

**Độ phức tạp**

Phụ thuộc query planner và index MySQL:

- Lookup theo primary key/unique index như SKU hoặc mã đơn: thường O(log n).
- Lọc theo index như `customer_id`, `user_id`, `status`: thường O(log n + r), với `r` là số dòng trả về.
- Sort theo cột có index có thể gần O(r); nếu không tận dụng được index có thể O(r log r).
- Scan toàn bảng khi thiếu index hoặc dùng `lower(column)` không có functional index: O(n).

**Tại sao chọn JPA Repository**

CRUD chính rõ ràng, ít SQL thủ công. Project vẫn dùng JPQL ở nơi cần điều kiện mềm như `deleted = false`.

**Ưu điểm**

- Code ngắn, dễ đọc.
- Tích hợp entity/transaction của Spring Boot.
- Ít lỗi mapping thủ công hơn JDBC thuần.

**Nhược điểm**

- Cần hiểu SQL sinh ra để tối ưu khi dữ liệu lớn.
- Một số query ignore-case dùng `lower(column)` có thể khó tận dụng index thường.

### 8.2. Cache sản phẩm bằng Redis

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/service/ProductService.java:49`: `getAllProducts()`.
- `backend/src/main/java/com/flarefitness/backend/service/ProductService.java:67`: `getProductById(String id)`.
- `backend/src/main/java/com/flarefitness/backend/service/ProductService.java:215`: `evictProductCaches(String id)`.
- `backend/src/main/resources/application.properties:55`: `app.cache.product-prefix`.
- `backend/src/main/resources/application.properties:56`: `app.cache.product-list-key`.
- `backend/src/main/resources/application.properties:57`: TTL cache sản phẩm.

**Thuật toán**

Cache-aside:

1. Khi đọc danh sách/sản phẩm, backend thử đọc Redis trước.
2. Nếu cache hit, parse JSON và trả về.
3. Nếu cache miss hoặc parse lỗi, query MySQL.
4. Map entity sang response, ghi JSON vào Redis với TTL.
5. Khi create/update/delete sản phẩm, xóa cache list và cache item liên quan.

**Độ phức tạp**

- Cache hit sản phẩm đơn: O(1) network Redis + O(size JSON).
- Cache hit danh sách: O(1) network Redis + O(n) parse JSON.
- Cache miss: DB query + O(n) map response.
- Evict cache: O(1) theo key.

**Tại sao chọn Redis cache-aside**

Danh sách sản phẩm được đọc nhiều hơn ghi. Cache-aside đơn giản, phù hợp với dữ liệu catalog, không cần thay đổi nhiều kiến trúc.

**Ưu điểm**

- Giảm tải MySQL cho API sản phẩm.
- TTL giúp cache tự hết hạn.
- Evict khi ghi giúp dữ liệu mới nhanh xuất hiện.

**Nhược điểm**

- Cache list lớn vẫn phải parse JSON toàn bộ.
- Nếu evict thiếu key, có thể hiển thị dữ liệu cũ đến khi TTL hết hạn.

### 8.3. Đồng bộ address-book/local state

**Vị trí code**

- `Front end/assets/main.js:5346`: `scheduleSyncStatePush(scope, key, value, options)`.
- `Front end/assets/main.js:5386`: `pushCurrentUserSyncState(key, value, options)`.
- `Front end/assets/main.js:5397`: `syncScopedArrayFromApi(syncKey, storageKey, fallback)`.
- `Front end/assets/main.js:6168`: `saveAddressBook(...)` push `address-book`.
- `Front end/assets/main.js:8242`: `removeAddress(addressId)`.
- `Front end/assets/main.js:6530`: `ensureCheckoutAddressSelection()`.

**Thuật toán**

- Khi login/sync, frontend pull state từ `/sync/me/{key}`.
- Nếu server có array, server được coi là nguồn chính và localStorage được ghi theo server.
- Nếu server chưa có payload nhưng localStorage có dữ liệu, local được push lên server.
- Khi xóa địa chỉ, frontend xóa trong localStorage, nếu địa chỉ đó đang được checkout chọn thì clear `currentCheckoutAddressId`, sau đó push `address-book` lên server ngay.

**Độ phức tạp**

Với `a` là số địa chỉ:

- Normalize/lưu address book: O(a).
- Xóa địa chỉ bằng filter: O(a).
- Tìm địa chỉ mặc định: O(a).

**Tại sao chọn cách này**

Frontend cũ dùng nhiều localStorage. Sync state giúp giữ trải nghiệm offline/local nhưng vẫn có server làm nguồn chính sau khi đăng nhập.

**Ưu điểm**

- Ít thay đổi API nghiệp vụ đơn hàng.
- Dữ liệu address-book theo tài khoản được giữ giữa trình duyệt/phiên đăng nhập.

**Nhược điểm**

- Conflict sync phức tạp hơn database chuẩn hóa.
- Nếu push thất bại, local và server có thể lệch tạm thời.
