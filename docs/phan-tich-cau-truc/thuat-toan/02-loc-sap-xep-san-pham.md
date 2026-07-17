# Thuật toán lọc và sắp xếp sản phẩm

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 4. Thuật toán lọc và sắp xếp sản phẩm

### 4.1. Lọc catalog phía khách hàng

**Vị trí code**

- `Front end/assets/main.js:2988`: `getBaseProducts()`.
- `Front end/assets/main.js:3699`: `matchesPriceRange(price, range)`.
- `Front end/assets/main.js:3716`: `sortProducts(products)`.
- `Front end/assets/main.js:3921`: `getFilteredProducts(baseProducts = getBaseProducts())`.

**Thuật toán**

`getFilteredProducts()` duyệt toàn bộ danh sách sản phẩm nền bằng `Array.filter`. Các giá trị filter được chuẩn hóa một lần và thông tin chuẩn hóa của từng sản phẩm được lấy từ search index. Với mỗi sản phẩm, code kiểm tra lần lượt:

- Môn thể thao/danh mục hiện tại.
- Rule menu đang chọn.
- Thương hiệu.
- Loại sản phẩm.
- Size.
- Khoảng giá.
- Query tìm kiếm đang nhập.

Sau khi lọc, danh sách được đưa vào `sortProducts()` để sắp xếp theo option hiện tại.

**Độ phức tạp**

- Lọc: O(n) sau khi search index đã được tạo; lookup dữ liệu chuẩn hóa của mỗi sản phẩm gần O(1).
- Sắp xếp: O(r log r), trong đó `r` là số sản phẩm sau lọc.
- Tổng: O(n + r log r). Nếu chỉ dùng thứ tự mặc định thì phần lọc là O(n).

**Tại sao chọn thuật toán này**

Filter theo nhiều điều kiện động trên UI. Duyệt mảng một lần bằng predicate là cách đơn giản, ít bug, dễ thêm điều kiện mới.

**So với lựa chọn khác**

- So với gọi API mỗi lần đổi filter: giảm round-trip, UI nhanh hơn khi dữ liệu đã có.
- So với index nhiều chiều phía frontend: ít phức tạp hơn. Với catalog vừa phải, lợi ích của index chưa đủ lớn.

**Ưu điểm**

- Code rõ, dễ bảo trì.
- Dễ thêm filter mới.
- Không phụ thuộc backend cho từng thao tác UI.

**Nhược điểm**

- Không phù hợp nếu catalog lên hàng chục/hàng trăm nghìn sản phẩm.
- Mỗi lần đổi filter đều tính lại từ danh sách gốc.

### 4.2. Sắp xếp và ưu tiên bộ sưu tập

**Vị trí code**

- `Front end/assets/main.js:2992`: `buildCollectionProducts(collectionId)`.
- `Front end/assets/main.js:3004`: `sortProductList(products, sortOption = 'featured')`.
- `Front end/assets/main.js:3054`: `mergeUniqueProducts(...)`.
- `Front end/assets/main.js:3063`: `getWorldCup2026KitProducts()`.
- `Front end/assets/main.js:3076`: `getProductSoldQuantityMap()`.

**Thuật toán**

- `buildCollectionProducts()` dùng danh sách SKU ưu tiên cho collection, tạo `Map` từ SKU sang vị trí ưu tiên, sau đó lọc và sort theo vị trí trong map.
- `mergeUniqueProducts()` dùng `Map` để loại trùng sản phẩm theo id.
- `getWorldCup2026KitProducts()` lọc các SKU WorldCup và sort theo thứ tự đã định.
- `getProductSoldQuantityMap()` duyệt đơn hàng để cộng dồn số lượng bán theo productId.
- `getHomeShowcaseProducts()` dùng min-heap top-K để chỉ giữ các sản phẩm giảm giá, bán chạy và tồn kho tốt nhất.

**Độ phức tạp**

- Tạo map thứ tự SKU: O(k), với `k` là số SKU ưu tiên.
- Lọc sản phẩm: O(n).
- Sort kết quả: O(r log r).
- De-duplicate bằng `Map`: O(n).
- Cộng dồn đã bán: O(t), với `t` là tổng số dòng item trong đơn hàng.
- Chọn top-K trang chủ: O(n log k), gần O(n) vì `k = 12`.

**Tại sao chọn thuật toán này**

Các bộ sưu tập như WorldCup cần thứ tự thủ công. `Map` cho phép tra vị trí ưu tiên O(1), tốt hơn việc dùng `indexOf` trên mảng SKU trong lúc sort.

**Ưu điểm**

- Giữ được thứ tự marketing mong muốn.
- Loại trùng nhanh.
- Dễ điều chỉnh thứ tự bằng danh sách SKU.

**Nhược điểm**

- Thứ tự ưu tiên đang hard-code trong frontend.
- Nếu dữ liệu marketing thay đổi thường xuyên, nên đưa cấu hình này lên backend/admin.

### 4.3. Lọc sản phẩm trong màn quản trị

**Vị trí code**

- `Front end/assets/main.js:17834`: `getFilteredAdminProducts(products = allProducts)`.
- `Front end/assets/main.js:17933`: `filterStaffOrders(orders = [])`.
- `Front end/assets/main.js:18036`: `filterStaffReviews(reviews = [])`.

**Thuật toán**

Các màn admin/staff cũng dùng mô hình `filter + sort`:

- Quản lý sản phẩm: lọc keyword, brand, category, giá, tồn kho, rồi sort.
- Quản lý đơn hàng: lọc keyword, trạng thái, ngày, rồi sort mới nhất.
- Quản lý đánh giá: lọc keyword, category, type, rating, status, rồi sort mới nhất.

**Độ phức tạp**

O(n * q + r log r), tương tự catalog khách hàng.

**Tại sao chọn thuật toán này**

Dữ liệu quản trị đang được load về frontend để thao tác nhanh. Cách lọc mảng phù hợp với quy mô hiện tại và tránh tạo nhiều API filter riêng.

**Nhược điểm**

Backend hiện đã có endpoint phân trang cho sản phẩm, đơn hàng và đánh giá. Frontend hiện tại vẫn giữ endpoint danh sách cũ để tương thích với workspace/localStorage; các màn hình mới có thể chuyển dần sang endpoint page.
