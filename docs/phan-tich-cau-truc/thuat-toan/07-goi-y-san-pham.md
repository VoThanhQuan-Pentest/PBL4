# Thuật toán gợi ý sản phẩm

> Tách từ docs/phan-tich-cau-truc-thuat-toan-cong-nghe.md để dễ đọc và tra cứu theo từng phần.

## 9. Thuật toán gợi ý sản phẩm

**Vị trí code**

- `backend/src/main/resources/application.properties:58` đến `:61`: Redis recommendation/popularity cache.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:83`: `trackEvent(...)`.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:131`: `rebuildUserProfile(String userId)`.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:173`: `getRecommendations(...)`.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:395`: `buildSnapshot(List<UserBehaviorEvent>)`.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:461`: `resolveEventWeight(UserBehaviorEvent)`.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:478`: `buildWeightedProductMap(...)`.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:503`: `buildWeightedStringMap(...)`.
- `backend/src/main/java/com/flarefitness/backend/service/analytics/BehaviorAnalyticsService.java:609`: `toOrderedMap(...)`.
- `backend/src/main/java/com/flarefitness/backend/repository/analytics/UserBehaviorEventRepository.java:10`: lấy top 300 event theo user.
- `backend/src/main/java/com/flarefitness/backend/repository/analytics/UserBehaviorEventRepository.java:16`: lấy top 1500 event gần đây.

**Thuật toán**

Đây là scoring rule-based recommendation:

1. Ghi event hành vi: xem sản phẩm, tìm kiếm, click category, thêm giỏ, mua hàng, review.
2. Khi cần gợi ý, lấy snapshot hành vi gần đây của user/session.
3. Lấy popularity score từ event 30 ngày gần nhất.
4. Duyệt danh sách sản phẩm.
5. Bỏ qua sản phẩm hết hàng, sản phẩm đã exclude hoặc không phù hợp context.
6. Tính điểm:
   - Điểm phổ biến.
   - Trùng danh mục yêu thích.
   - Trùng thương hiệu yêu thích.
   - Trùng bucket giá.
   - Bonus theo context như home/detail/cart.
7. Sort sản phẩm theo score giảm dần và createdAt mới hơn.
8. Chỉ giữ top-K trong `PriorityQueue`, không sort toàn bộ sản phẩm có điểm.
9. Cache kết quả recommendation và popularity trong Redis.

**Độ phức tạp**

Ký hiệu:

- `e`: số event được đọc.
- `p`: số sản phẩm.
- `s`: số sản phẩm có score dương.

Tạo snapshot: O(e). Map số lượng category/brand trong giỏ được tạo O(c), sau đó mỗi sản phẩm lookup O(1), thay cho duyệt lại giỏ O(p * c). Duyệt sản phẩm và giữ top-K: O(p log k), với `k <= 16`. Tổng: O(e + c + p log k), gần tuyến tính vì `k` rất nhỏ.

**Tại sao chọn thuật toán này**

Project chưa có hệ thống machine learning riêng. Rule-based scoring đủ dùng cho demo/sản phẩm vừa phải, dễ giải thích, dễ điều chỉnh trọng số.

**So với lựa chọn khác**

- So với collaborative filtering: không cần dữ liệu lớn và ma trận user-item.
- So với model ML: không cần training/deploy model.
- So với chỉ bán chạy: cá nhân hóa tốt hơn vì có category/brand/price của user.

**Ưu điểm**

- Dễ debug vì điểm số dựa trên rule rõ ràng.
- Có thể chạy trực tiếp trong backend.
- Redis cache dùng chung được giữa nhiều instance backend.
- Top-K tránh sort toàn bộ danh sách sản phẩm.

**Nhược điểm**

- Chất lượng phụ thuộc trọng số thủ công.
- Không học được pattern phức tạp như model ML.
- Khi số sản phẩm/event rất lớn cần tối ưu hoặc chuyển sang batch/offline.
