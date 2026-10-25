# Kết quả nghiên cứu và nghiệm thu OTP local lab — 20/10/2026

Kết luận theo nhánh đã được duyệt: **nghiên cứu hoàn tất với STOP_NO_IMPROVEMENT; OTP đạt gate lab và đã được chạy trên allowlist local**. Model chưa qualify; chưa chứng minh sản phẩm trên người dùng thực. Không mở holdout, adoption, shadow hoặc bật chặn UEBA. Không thay AWS hoặc bật OTP toàn bộ tài khoản.

## Source và model

Đã sinh/audit 35.000 dòng DEMO_ONLY: FIT4.000, calibration normal10.000, validation20.000normal+1.000positive (200/family). Schema6/recipe5 giữ57 chiều cũ và thêm8 tổng hợp quan sát trước thao tác. Bản mở rộng được chốt trước fit sau khi Java xác minh ba blind pairs. Không dùng proof, kết quả thao tác hiện tại, danh tính fixture hoặc ý định ẩn làm feature.

COLD có3 cửa sổ quá khứ nhưng chưa đủ30 để lập baseline; READY/UNSEEN_READY có48. Audit ban đầu đã dừng vì nhầm COLD phải không có lịch sử; bản sửa kiểm tra đúng generator, không sửa dữ liệu. Lỗi chọn account-hour gần đầy được sửa trước fit;239batch/7.648dòng cũ được giữ nguyên qua lineage manifest. Chronology/gap>14ngày, isolation, UNSEEN, raw-reference/Java parity và dữ liệu thiếu association đều có kiểm chứng.

| Validation pilot | Baseline37 | Candidate65 |
|---|---:|---:|
| TP/FN | 769/231 | 985/15 |
| FP/TN | 1/19.999 | 2/19.998 |
| Precision | 99,8701% | 99,7974% |
| Recall | 76,9% | 98,5% |
| FPR | 0,005% | 0,010% |

Candidate giảm FN216 nhưng tăng FP1, vi phạm non-regression. Vì vậy **STOP_NO_IMPROVEMENT**, không mở P4/strict hoặc thử thêm threshold/seed. Đã fit2composite/4component, save/load parity9probe/model và calibration được đọc lại. 15FN còn lại thuộc request_burst:7sai phân loại bối cảnh,8bỏ qua bởi ngưỡng anomaly cố định.

Ma trận phân loại ba lớp của candidate, hàng là nhãn tham chiếu, cột là Routine/Behavior/Operational:

| Nhãn | Routine | Behavior | Operational |
|---|---:|---:|---:|
| Routine | 19.988 | 12 | 0 |
| Behavior | 7 | 793 | 0 |
| Operational | 0 | 0 | 200 |

Đây là classifier-context, khác quyết định alert sau fusion/calibration ở bảng đầu. Operational bị chuyển nhầm sang Behavior: baseline3/200, candidate0/200. Trên cùng validation với nhãn planned cũ, baseline TP393/FN107/FP377/TN20.123; candidate TP493/FN7/FP494/TN20.006. Nhãn cũ không phải ownership độc lập và không dùng chọn model;494alert trên planned-normal cũ cho thấy không được gọi đây là detector chiếm quyền đã đạt chuẩn. Rule tham chiếu khớp hoàn toàn vì chính rubric định nghĩa nhãn, không phải bằng chứng ngoài lab. SIEM_FINAL cho schema6 chưa được nghiệm thu.

## OTP và gate lab

Mọi EMAIL_CHANGE/PASSWORD_CHANGE của account thuộc allowlist cần proof riêng, kể cả model rủi ro thấp. Challenge gắn account/session/authVersion/payload/đích/contact/policy; OTP một lần≤5phút, cooldown≥60giây, tối đa5lần sai theo account, gửi lại không reset budget. Đổi email cần hai proof riêng: email hiện tại và email đích. Mật khẩu chỉ lưu dạng hash trong pending. Mutation/COMMITTED/scrub nhất quán trong DB; audit thành công sau commit. Endpoint cũ từ chối bỏ qua OTP khi policy bật.

Lượt đầy đủ: **14.004trial,14.004account/session riêng**, mail giả, HTTP/JWT/CSRF/MySQL/Redis thật, hai CPU cố định. Có10.000trial hợp lệ,4.000trial proof không hợp lệ và4đối chứng. Đọc lại DB sau mỗi execute/replay. Gate/counts/CI được chốt trước kết quả; một trial sai sẽ làm lượt thất bại, không chọn lại sample để PASS.

| Gate lab riêng mỗi thao tác | EMAIL_CHANGE | PASSWORD_CHANGE |
|---|---:|---:|
| Hợp lệ đủ proof / chặn nhầm | 5.000/0 | 5.000/0 |
| Proof không hợp lệ / mutation trái phép | 2.000/0 | 2.000/0 |
| Replay hợp lệ / mutation thêm | 5.000/0 | 5.000/0 |
| Cận trên chặn nhầm, CI một phía95% | 0,095704% | 0,095704% |
| Cận dưới ngăn proof không hợp lệ, CI một phía95% | 99,760912% | 99,760912% |

**LAB_ACTION_GATE_PASS**: cận trên<0,1% và cận dưới>99%. CI dùng Bonferroni6so sánh để bảo vệ95% family-wise; zero-error upper bound=1−(0,05/6)^(1/n), dưới giả định trial lab độc lập trong protocol cố định. Mẫu dùng account mới, phiên riêng và rate bucket riêng; không chứng minh tỷ lệ lỗi người dùng thực, khi SMTP gián đoạn hoặc trong mọi tình huống DoS.

Bốn nhóm invalid: sai mã, sai phiên, hết hạn, authVersion thay đổi;500ca/nhóm/mỗi thao tác. Đối chứng chính chủ thiếu mã bị từ chối đúng policy; người chiếm cả session/credential/mailbox có proof đúng được chấp nhận ngoài giả định bảo vệ. Không xóa các đối chứng này hoặc gán thiếu proof thành nhãn tấn công. Tỷ lệ hoàn thành của các trial proof-eligible là100%; các timeouts/lỗi gửi mail trong lượt fake-mail bằng0, không suy ra độ tin cậy Gmail ngoài thực tế.

## SMTP thật, lỗi và tích hợp

Gmail TLS1.3/auth PASS. Một email scoped-OTP được người dùng nhập và kiểm chứng qua production service/Redis. Sau đó4email thật xác minh mailbox→EMAIL_CHANGE với hai proof→PASSWORD_CHANGE qua HTTP/JWT/CSRF/MySQL/Redis. Có đúng1thay đổi email,1thay đổi mật khẩu của account lab; phiên cũ bị thu hồi. Không đổi mật khẩu Gmail. Các container và listener human-lab đã dừng.

Cấu hình production đã bổ sung kiểm tra hostname SMTP, có test auto-configuration offline. File credential của người dùng không bị sửa/copy vào snapshot, không đưa password/OTP/JWT vào báo cáo. Email không phải MFA; không bảo vệ khi mailbox cũng bị chiếm.

Các kiểm chứng chính:

- 22case browser desktop/mobile trên component và form HTML/JS production,7unit tests, build production PASS. Nhánh legacy được sửa fixture theo HTTP204 thật và chạy lại trên cả hai viewport. Đã sửa sai wire format snake_case, submit trùng và xử lý đóng form trước response prepare.
- Ma trận8test HTTP/DB/Redis cho sai account/đích, actual failure budget, lỗi Redis/SMTP/telemetry, DB rollback, request body bị cắt và response mất sau commit. Replay sau lost response không ghi mutation lần hai.
- Acceptance4test sau gate dùng policy từ runtime environment, không từ test properties: allowlist bắt buộc OTP, account ngoài danh sách giữ endpoint cũ. Chỉ account lab dùng một lần, không cấu hình account có sẵn của người dùng.
- Flyway upgradeV39 giữ contact legacy chưa xác minh, vô hiệu pending chưa bind policy, cho nhiều phone rỗng nhưng vẫn chặn trùng số thật/+84. Không xóa dữ liệu để PASS.
- SIGKILL giữa các bước publication, reuse bytes, corruption/binding/writer/timeout/quota checks và source resume đã được kiểm chứng. Không hứa giữ RAM của fit đang dở khi mất điện.

Độ trễ trong receipt lab là wall-time của HTTP execute kèm CSRF trên loopback, không phải CPU time riêng của server; không gồm SMTP/prepare/người dùng. Quantiles đầy đủ nằm trong lab-action-gate-result-v1.

## Bàn giao và giới hạn

[Runbook vận hành/phục hồi](LOCAL_OTP_RUNBOOK.md) mô tả config, bật/tắt allowlist, đọc receipt, resume và cách xử lý proof bị tiêu thụ trước DB rollback. Source, models, data manifests và receipts nằm tại `/home/quan/PBL4(UpdateFromPBL3)/observability/runtime/postlogin-risk-context-20261020-r1/`; snapshot cuối là implementation-snapshot-v5, audit là approved-plan-completion-audit-v1. Giữ toàn bộ kết quả cũ và failed receipts.

Trần tích lũy28.800giây, pilot7.200giây; ledger tính cả job lỗi, kế thừa và kiểm thử. Chỉ quota5h≥97% dừng mở unit mới, quota tuần không dùng làm stop. Không dùng hết cap chỉ để lặp test hoặc fit.

Đã hoàn tất nhánh nghiên cứu âm tính và nghiệm thu OTP local lab theo kế hoạch. Detection/strict/proof/shadow không mở vì admission thất bại. Qualification trên người dùng thực và deployment/AWS là các phạm vi chưa đạt/chưa thực hiện, không suy ra từ PASS trong lab.
