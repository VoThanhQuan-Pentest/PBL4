# Thuật toán tìm kiếm sản phẩm

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 3. Thuật toán tìm kiếm sản phẩm

### 3.1. Tìm kiếm gợi ý bằng chấm điểm chuỗi

**Vị trí code**

- `Front end/assets/main.js:6570`: `getSearchableProductText(product)`.
- `Front end/assets/main.js:6580`: `createCharacterBigrams(value)`.
- `Front end/assets/main.js:6583`: `rebuildProductSearchIndex(products)`.
- `Front end/assets/main.js:6633`: `getDiceCoefficientFromBigrams(leftBigrams, rightBigrams)`.
- `Front end/assets/main.js:6671`: `scoreProductAgainstQuery(product, queryContext)`.
- `Front end/assets/main.js:6719`: `getSearchSuggestions(query, sourceProducts, limit)`.
- `Front end/assets/main.js:6741`: `scheduleSearchSuggestions(query)`.
- `Front end/assets/main.js:18458`: `applySearchQuery(nextQuery)`, phiên bản có hiệu lực hiện tại.

**Thuật toán**

1. Chuẩn hóa query và text sản phẩm bằng `normalizeText`.
2. Ghép các trường có thể tìm kiếm: tên sản phẩm, thương hiệu, danh mục, SKU, nhóm sản phẩm.
3. Tạo search index một lần sau khi tải sản phẩm, lưu text chuẩn hóa và bigram trong `WeakMap`.
4. Chấm điểm theo nhiều tiêu chí:
   - Tên trùng hoàn toàn query: điểm cao nhất.
   - Tên bắt đầu bằng query.
   - Tên hoặc text tìm kiếm chứa query.
   - Thương hiệu chứa query.
   - Từng token trong query xuất hiện trong tên/text.
   - Độ giống nhau bằng character bigram và hệ số Dice.
5. Dice dùng `Map` tần suất bigram thay cho `indexOf/splice`.
6. Khi đã có kết quả chứa trực tiếp, bỏ qua Dice để giảm phép tính.
7. Chỉ giữ top-K gợi ý trong lúc duyệt thay vì sort toàn bộ ứng viên.
8. Lọc sản phẩm có điểm lớn hơn ngưỡng.
9. Input tìm kiếm được debounce 220ms để không tính lại sau mọi phím bấm liên tiếp.

**Độ phức tạp**

Ký hiệu:

- `n`: số sản phẩm.
- `m`: độ dài chuỗi tìm kiếm/text đã chuẩn hóa.

Search index và `productById` được tạo O(n * m) một lần sau khi tải sản phẩm. Tra sản phẩm theo ID sau đó là O(1), thay vì `Array.find` O(n). Với mỗi lần tìm, Dice dùng `Map` nên tính giao bigram O(m), thay vì O(m²). Min-heap top-K có chi phí O(n log k); vì `k` nhỏ và cố định nên gần O(n), thay vì sort toàn bộ O(n log n).

**Tại sao chọn thuật toán này**

Catalog của project được load về frontend và số lượng sản phẩm hiện không quá lớn. Cách chấm điểm tuyến tính qua danh sách dễ cài, không cần server search riêng, vẫn hỗ trợ tìm gần đúng nhờ bigram.

**So với lựa chọn khác**

- So với tìm `includes` đơn giản: kết quả linh hoạt hơn vì có điểm, token, bigram.
- So với Trie: không chỉ tìm prefix mà còn tìm theo thương hiệu, danh mục, SKU và lỗi nhập gần đúng.
- So với MySQL full-text / Elasticsearch: nhẹ hơn, không cần thêm hạ tầng, phù hợp website demo/sản phẩm vừa phải.

**Ưu điểm**

- Dễ hiểu, dễ chỉnh trọng số.
- Chạy ngay trên frontend, phản hồi nhanh với dữ liệu đã load.
- Hỗ trợ tiếng Việt tốt hơn nhờ chuẩn hóa text.
- Không chuẩn hóa lại toàn bộ dữ liệu sau mỗi lần gõ.

**Nhược điểm**

- Khi số sản phẩm lớn, phải quét toàn bộ mảng.
- Vẫn phải duyệt catalog local; catalog rất lớn nên dùng API full-text phân trang.

### 3.2. Tìm kiếm và lọc sản phẩm phía backend

**Vị trí code**

- `backend/src/main/java/com/flarefitness/backend/controller/ProductController.java:31`: endpoint `GET /api/products/query`.
- `backend/src/main/java/com/flarefitness/backend/service/ProductService.java:92`: chuẩn hóa tham số và giới hạn page size.
- `backend/src/main/java/com/flarefitness/backend/repository/ProductRepository.java:45`: full-text search có phân trang.
- `backend/src/main/java/com/flarefitness/backend/repository/ProductRepository.java:90`: LIKE fallback nếu database chưa có full-text index.
- `db-init/schema_full.sql:84`: composite filter index.
- `db-init/schema_full.sql:85`: full-text search index.

**Thuật toán**

API nhận query, category, brand, status, min/max price, in-stock, page và size. Query text được chuyển thành MySQL boolean full-text query. Database lọc bằng index và chỉ trả tối đa 100 sản phẩm mỗi page. Nếu full-text index chưa tồn tại, service fallback sang LIKE để API vẫn hoạt động.

**Độ phức tạp**

Full-text search dùng inverted index, tránh quét toàn bộ bảng cho mỗi query. Filter theo composite/B-tree index thường gần O(log n + r), trong đó `r` là số bản ghi trả về. Phân trang giới hạn chi phí truyền dữ liệu và mapping ở O(pageSize).
