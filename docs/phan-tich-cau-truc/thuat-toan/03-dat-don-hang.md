# Thuật toán đặt đơn hàng

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 5. Thuật toán đặt đơn hàng

### 5.1. Checkout phía frontend

**Vị trí code**

- `Front end/assets/main.js:6530`: `ensureCheckoutAddressSelection()`.
- `Front end/assets/main.js:13818`: `placeOrder()`, phiên bản có hiệu lực hiện tại.
- `Front end/assets/main.js:9820`: `createOrderToApi(order)`.

**Thuật toán**

1. Lấy các item trong giỏ hàng đã được chọn.
2. Kiểm tra người dùng đã đăng nhập customer.
3. Lấy địa chỉ checkout hiện tại bằng `ensureCheckoutAddressSelection()`. Nếu chưa chọn thì lấy địa chỉ mặc định.
4. Tính `subtotal` bằng `reduce`.
5. Áp voucher nếu có, tính discount, shipping và total.
6. Tạo object order local gồm:
   - mã đơn,
   - trạng thái chờ xác nhận,
   - snapshot địa chỉ,
   - snapshot customer,
   - snapshot item: productId, SKU, tên, ảnh, size, giá, số lượng.
7. Gửi API tạo đơn bằng `createOrderToApi()`.
8. Nếu backend trả về đơn thành công, lưu đơn vào lịch sử local, tiêu thụ voucher, ghi behavior event `PURCHASE`, xóa item đã mua khỏi giỏ.

**Độ phức tạp**

Với `k` là số item được chọn:

- Lọc item được chọn: O(k).
- Tính tổng bằng `reduce`: O(k).
- Tạo snapshot item: O(k).
- Xóa item đã mua khỏi giỏ: O(c), với `c` là tổng item trong giỏ.

Tổng frontend xấp xỉ O(k + c).

**Tại sao chọn thuật toán này**

Checkout cần snapshot dữ liệu tại thời điểm đặt hàng. Nếu sau này sản phẩm đổi tên, đổi giá hoặc địa chỉ mặc định bị thay đổi, đơn cũ vẫn hiển thị đúng thông tin đã đặt.

**Ưu điểm**

- Luồng dễ hiểu.
- Snapshot bảo vệ lịch sử đơn hàng.
- Giảm phụ thuộc vào dữ liệu sản phẩm hiện tại khi xem đơn cũ.

**Nhược điểm**

- Một phần logic tính tiền có ở frontend nên backend vẫn phải là nguồn kiểm soát cuối cùng.
- Nếu voucher/giá thay đổi phức tạp, nên gom rule giá về backend nhiều hơn.

### 5.2. Tạo đơn hàng phía backend

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:97`: `createOrder(Authentication, OrderRequest)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:229`: `saveOrderItems(Order, List<OrderItemPayload>, LocalDateTime)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:365`: `findOrCreateCustomer(User, OrderAddressPayload)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:519`: `buildAddressText(OrderAddressPayload, Customer)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:531`: `buildOrderCode(LocalDateTime)`.

**Thuật toán**

1. Lấy user từ authentication.
2. Kiểm tra danh sách item không rỗng.
3. Chống tạo trùng bằng idempotency:
   - Nếu request gửi `id` đã tồn tại thì trả lại đơn cũ.
   - Nếu request gửi `code` đã tồn tại thì trả lại đơn cũ.
4. Tìm hoặc tạo customer bằng user/email/tên.
5. Tính tiền:
   - `subtotal = total - shipping + discount` nếu request không gửi subtotal.
   - Chuẩn hóa shipping, discount, total về `BigDecimal`.
6. Tạo `Order`, lưu địa chỉ giao bằng `buildAddressText()`.
7. Lưu order.
8. `saveOrderItems()`:
   - Lấy danh sách productId distinct.
   - Query một lần `productRepository.findAllById(productIds)`.
   - Đưa sản phẩm vào `HashMap`.
   - Duyệt từng payload item, validate product tồn tại, tính line total, saveAll.
9. Trả `OrderResponse` đã map kèm item.

**Độ phức tạp**

Với `k` là số dòng sản phẩm trong đơn:

- Lấy distinct productId: O(k).
- Query sản phẩm theo danh sách id: phụ thuộc database, thường O(k log n) với index primary key.
- Tạo `HashMap`: O(k).
- Duyệt item và tính line total: O(k).
- Tổng xử lý trong app: O(k).

**Tại sao chọn thuật toán này**

Backend query sản phẩm theo batch rồi tra bằng `HashMap`, tránh query từng item. Nếu query từng item, số truy vấn là O(k); cách hiện tại gom thành một truy vấn sản phẩm và một lần `saveAll`.

**Ưu điểm**

- Giảm N+1 query khi tạo order item.
- Dễ đảm bảo snapshot dòng đơn hàng.
- Có idempotency để giảm lỗi double-click hoặc retry API.

**Nhược điểm**

- Chưa thấy cơ chế trừ tồn kho transaction rõ trong đoạn hiện tại.
- Nếu đơn hàng rất lớn, cần phân batch save item.

### 5.3. Hiển thị danh sách đơn hàng và tránh N+1 query

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:83`: `getCurrentCustomerOrders(Authentication)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:271`: `toResponses(List<Order>)`.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderItemRepository.java:10`: `findByOrderIdIn(Collection<String> orderIds)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:99`: keyset page cho admin/staff.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:112`: keyset page cho khách hàng.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderRepository.java:44`: query cursor chung.
- `backend/src/main/java/com/flarefitness/backend/repository/OrderRepository.java:59`: query cursor theo user/customer.

**Thuật toán**

`getCurrentCustomerOrders()` lấy đơn theo `userId`, sau đó lấy thêm đơn theo `customerId` nếu tìm được customer. Hai danh sách được gộp và loại trùng bằng map theo `Order.id`, rồi sort theo `createdAt desc`.

`toResponses()` gom response theo batch:

1. Lấy toàn bộ orderId.
2. Query tất cả order item bằng `findByOrderIdIn(orderIds)`.
3. Group item theo orderId.
4. Lấy product/customer liên quan theo batch.
5. Map từng order sang response.

Các endpoint `/api/orders/page` và `/api/orders/me/page` dùng keyset cursor `(createdAt, id)` thay vì offset. Mỗi request chỉ lấy `limit + 1` bản ghi để xác định còn trang tiếp theo hay không.

**Độ phức tạp**

- Gộp và loại trùng đơn: O(o), với `o` là số đơn.
- Sort đơn: O(o log o).
- Group item: O(i), với `i` là số dòng item.
- Map response: O(o + i).

**Tại sao chọn thuật toán này**

Batch query và group bằng map tránh lỗi N+1 query khi danh sách đơn có nhiều item.

**Ưu điểm**

- Ít query hơn.
- Response vẫn có đủ item, product, customer.

**Nhược điểm**

- Endpoint cũ vẫn trả toàn bộ danh sách để tương thích; màn hình dữ liệu lớn nên dùng endpoint cursor mới.
