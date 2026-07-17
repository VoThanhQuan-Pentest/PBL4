# Thuật toán hủy đơn và đổi trả

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 6. Thuật toán hủy đơn và đổi trả

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:188`: `requestCancellation(...)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:209`: `requestReturn(...)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:472`: `canCustomerRequestCancellation(String status)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:481`: `canCustomerRequestReturn(String status)`.
- `backend/src/main/java/com/flarefitness/backend/service/OrderService.java:519`: `buildAddressText(...)`.
- `Front end/assets/main.js:9863`: `requestOrderSupportToApi(orderId, action, note)`.
- `Front end/assets/main.js:9964`: `canCustomerRequestCancel(order)`.
- `Front end/assets/main.js:9968`: `canCustomerRequestReturn(order)`.

**Thuật toán**

- Hủy đơn:
  1. Kiểm tra người dùng sở hữu đơn.
  2. Chuẩn hóa trạng thái đơn bằng hàm normalize.
  3. Chỉ cho tạo yêu cầu nếu đơn chưa ở các trạng thái đang giao, đã giao, hoàn thành, đã hủy.
  4. Kiểm tra metadata đơn để không tạo yêu cầu trùng.
  5. Lưu yêu cầu hủy vào metadata trong `ghiChu`.

- Đổi trả:
  1. Kiểm tra người dùng sở hữu đơn.
  2. Chỉ cho yêu cầu khi trạng thái đã giao/hoàn thành.
  3. Kiểm tra không tạo yêu cầu đổi trả trùng.
  4. Lưu yêu cầu đổi trả vào metadata.

**Độ phức tạp**

Với metadata hỗ trợ có kích thước nhỏ:

- Normalize trạng thái: O(s), với `s` là độ dài chuỗi trạng thái.
- Kiểm tra request trùng trong metadata: O(r), với `r` là số request hỗ trợ lưu trong metadata.
- Tổng gần O(s + r).

**Tại sao chọn thuật toán này**

Chức năng hủy/đổi trả đang được thêm nhỏ vào kiến trúc hiện tại, nên lưu metadata trong `ghiChu` giúp không phải thay đổi schema lớn.

**Ưu điểm**

- Ít thay đổi database.
- Dễ hiển thị cho staff/admin cùng với đơn hàng.
- Không làm vỡ API cũ.

**Nhược điểm**

- Metadata JSON trong cột ghi chú khó query/report hơn bảng riêng.
- Nếu workflow hỗ trợ phức tạp hơn, nên tách bảng `order_support_request`.
