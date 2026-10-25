# Hai kịch bản SOC: practice và demo chính

Hệ thống local: website/API `http://127.0.0.1:8088`, app **Flare Security Monitor**. Có đúng hai ca HIGH theo cùng luồng **L1 nhận ca → leo thang → L2 nhận ca → cô lập phiên khách hàng → đóng ca**.

Các ca có nhãn `DEMO_ONLY_WORKFLOW_FIXTURE`: được tạo để thực hành quy trình, phân quyền và thu hồi phiên qua API/database thật. Khi trình bày, nêu rõ nguồn fixture. Phần model và policy có hướng dẫn riêng tại [LOCAL_POSTLOGIN_PROJECT.md](LOCAL_POSTLOGIN_PROJECT.md).

## 1. Tài khoản

Thông tin đăng nhập được tập trung trong [TAI_KHOAN_DANG_NHAP.local.md](../TAI_KHOAN_DANG_NHAP.local.md), file local chỉ chủ máy đọc được.

Đây là credential công khai của tài khoản local dùng riêng cho đồ án. Cô lập bằng cách thu hồi phiên chỉ tác động đúng khách của ca đã chọn. Tài khoản `e2e_customer` giữ thông tin riêng của chủ máy và không dùng cho bài thu hồi phiên này.

## 2. Khởi động

```bash
cd '/home/quan/PBL4(UpdateFromPBL3)'
docker info >/dev/null
python3 observability/scripts/postlogin_project_site.py start
python3 observability/scripts/local-soc-demo.py status
mvn -f desktop-client/pom.xml compile javafx:run
```

Giữ terminal chạy JavaFX mở. Trong app, **Server origin** là `http://127.0.0.1:8088`, không thêm `/api`. Mở website bằng đúng host `127.0.0.1` trong cả buổi để dùng nhất quán cookie.

Trạng thái/pointer của hai ca hiện tại nằm tại:

- Demo chính: `observability/runtime/local-soc-demo-20261022/latest-case.private.json`.
- Practice: `observability/runtime/local-soc-demo-20261022/latest-practice.private.json`.

Không cần chạy `prepare`, `practice` hoặc `rehearse` trước khi sử dụng bộ ca đang có. Lệnh `status` chỉ đọc trạng thái.

## 3. Chọn kịch bản

| Bộ ca | Tìm title | Khách đăng nhập website | Target phải kiểm tra |
|---|---|---|---|
| Practice — làm trước để quen | `SOC-PRACTICE-L2` | `practice_soc_customer` | `soc-practice-customer` |
| Demo chính — dành cho giảng viên | `SOC-DEMO-L2` | `demo_soc_customer` | `soc-demo-customer` |

Mỗi bộ chỉ có một ca HIGH. Làm đầy đủ các bước sau với **practice** trước. Sau đó lặp lại với **demo chính**, thay đúng tài khoản khách và title; lịch sử hai ca độc lập.

## 4. Mở phiên khách hàng

1. Trên website, đăng nhập khách tương ứng trong bảng trên.
2. Giữ phiên này mở đến khi L2 cô lập, chưa đăng xuất.
3. Mở F12 → Console, chạy lệnh chỉ in mã trạng thái:

```javascript
fetch('/api/auth/me', {credentials: 'include'})
  .then(r => console.log(r.status))
```

Kết quả ban đầu cần là **200**. Không in cookie hoặc token.

## 5. L1 nhận và leo thang

1. Đăng nhập app bằng `demo_soc_l1`.
2. Vào **Incident queue → Clear filters**.
3. Queue **SOC L1/My tier**, status **Open**, source **All sources**; bỏ **Assigned to me** để tìm ca chưa có người nhận.
4. Tìm đúng title trong bảng. Nếu không thấy, mở rộng khoảng thời gian để bao gồm ngày tạo ca.
5. Chọn ca rồi nhấp đúp, Enter hoặc **Mở xử lý**. Trong cửa sổ riêng cần thấy **HIGH / L1 / NEW**, đúng target khách. Mở **Xử lý và cô lập** để dùng các action.
6. Bấm **Claim**. Kết quả: **L1 / IN_PROGRESS**, được gán cho L1 hiện tại.
7. Nhập ghi chú ít nhất 10 ký tự, ví dụ: `L1 đã kiểm tra ca mô phỏng và chuyển L2 để đánh giá, cô lập phiên thử nghiệm.`
8. Bấm **Escalate to L2**.

Kết quả cần là **L2 / NEW / chưa có người nhận**. Ca có thể biến mất khỏi bộ lọc L1. L1 không được tự đóng ca HIGH hoặc cô lập phiên.

## 6. L2 nhận và cô lập

1. **Sign out**, đăng nhập app bằng `demo_soc_l2`.
2. Vào **Incident queue → Clear filters**, queue **SOC L2/My tier**, status **Open**; bỏ **Assigned to me** khi tìm ca mới.
3. Tìm ca vừa chuyển → **Claim**.
4. Xác nhận **L2 / IN_PROGRESS**, được gán đúng L2 hiện tại.
5. Đọc **NOTES** và **WORKFLOW HISTORY**; kiểm tra đúng target trong bảng.
6. Bấm **Revoke customer sessions**.
7. Nhập lý do ít nhất 10 ký tự: `Cô lập có kiểm soát: thu hồi phiên của khách thử nghiệm thuộc ca đang xử lý.`
8. Trong hộp thoại **Confirm SOC L2 response**, kiểm tra lại target rồi bấm **OK**.
9. Đợi thông báo thành công. Lịch sử cần có **CUSTOMER_SESSIONS_REVOKED**.

Cô lập ở đây là làm mất hiệu lực các phiên đăng nhập cũ của đúng khách đó; mật khẩu và khả năng đăng nhập lại được giữ nguyên.

## 7. Chứng minh kết quả và đóng ca

1. Quay lại website đang giữ phiên khách cũ.
2. Chạy lại `fetch('/api/auth/me', ...)`: cần nhận **401**.
3. Đăng nhập mới bằng cùng tài khoản khách: kiểm tra lại cần nhận **200**.
4. Trở lại app L2, ghi kết luận: `Đã hoàn tất cô lập phiên trong kịch bản mô phỏng và kiểm tra phiên cũ bị từ chối.`
5. Chọn **TRUE_POSITIVE → Close** theo nhãn đã định trước của bài mô phỏng.
6. Lọc **Closed**, mở lại ca và kiểm tra lịch sử: **CLAIM(L1), ESCALATE(L1), CLAIM(L2), CUSTOMER_SESSIONS_REVOKED(L2), CLOSE(L2)**.

## 8. Làm lại từ đầu

Khi muốn xóa các ca/log/lịch sử demo–practice cũ và tạo lại đúng hai ca, chạy lệnh reset riêng:

```bash
python3 observability/scripts/reset_local_soc_scenarios.py
```

Lệnh này giới hạn vào fixture `soc-demo-*`/`soc-practice-*`, các sự kiện và window của hai khách thử nghiệm; dừng app ngắn để dọn file log nhất quán, rồi khởi động lại. Có bản sao cục bộ riêng để khôi phục khi cần. Tài khoản, mật khẩu, policy model và các ca ngoài phạm vi được giữ nguyên.

Không chạy reset giữa buổi trình diễn. Để luyện tập, chỉ chọn `SOC-PRACTICE-L2` và khách practice; giữ ca `SOC-DEMO-L2` ở NEW/L1 cho giảng viên.

## 9. Lỗi thường gặp

| Hiện tượng | Cách xử lý |
|---|---|
| Không thấy ca | Clear filters, bỏ Assigned to me, đúng tier/status và khoảng thời gian; bấm Search/Refresh. |
| Ca mất khỏi L1 sau leo thang | Đăng nhập L2, tìm trong queue L2. |
| L2 không thấy nút cô lập | Claim ca trước; phải là L2/IN_PROGRESS và đúng assignee. |
| Báo version đã đổi | Refresh, đọc lại trạng thái rồi thao tác lại. |
| Website vẫn hiện trang sau cô lập | Gọi `/api/auth/me` để kiểm tra; trang HTML đang mở không tự chứng minh phiên còn hợp lệ. |
| Đăng nhập bị giới hạn | Chờ hết thời hạn, không bấm lặp hoặc giảm rate limit. |

### Local upgrade acceptance — 24 October 2026

The final lab stack uses `flare-otp-local`, website port 8088 and authenticated
SOC/recovery port 8089. Launch the Linux client recorded in
`audit-results/siem-upgrade-20261023/desktop-completion-delivery.json`.
L1/L2 start in their queue. Select a row, then double-click, press Enter or use
Open to investigate in the reusable incident window. ELK documents are shown
separately from workflow notes/actions and model context. Recurrence is ENFORCE;
account isolation remains an authorized L2/Admin response. Acceptance used only
SOC-PRACTICE cases; reserved SOC-DEMO cases and credentials remain unchanged.
See `completion-summary.json` in the same audit directory for measured gates and
lab/model limitations. Do not reseed the main database or restart retired ELK
writers to recreate a demonstration.

### Current workspace/auth release — 25 October 2026

Use the client in `audit-results/siem-workspace-20261024/desktop-completion-delivery.json`.
Incidents now use an always-visible summary, unified timeline and separate response
panel. Source/destination/server and actor/target retain their provenance. Raw ELK
Fields/JSON remains native. Auth correlation is ALERT (investigation only); the
new81-feature candidate is PILOT_ONLY/SHADOW for the existing limited observation
population. No teacher case or credential was reset. See the same directory's
`completion-summary.json` and `docs/LOCAL_SOC_WORKSPACE_AUTH_PILOT.md` for measured
acceptance, memory and controlled-clock limitations. Do not replay source capture,
pilot fits or deployment checkpoints to recreate the demonstration.
