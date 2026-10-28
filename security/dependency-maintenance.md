# Bảo trì dependency — candidate lab

Chính sách này xác định yêu cầu bảo trì cho candidate trong repository Flare
Fitness/SOC, bao gồm thư viện runtime, build/test tool, JavaFX, worker Python,
base image, GitHub Actions và provider IaC. Đây là các mốc do dự án đặt cho
phạm vi lab; OWASP ASVS không quy định các con số cụ thể dưới đây. Việc ghi
chính sách không chứng minh các dependency hiện tại đã đáp ứng thời hạn,
không xác nhận qualification production và không tự triển khai vào stack live.

## Phân loại và thời hạn

Tính theo giờ/ngày lịch, dùng timestamp UTC. `known_at` là lúc sớm nhất dự án
nhận được cảnh báo từ scanner, advisory chính thức hoặc báo cáo hợp lệ; không
đổi mốc này khi chạy lại CI, đổi nhánh hoặc đổi tên finding. Khi mức rủi ro tăng,
hạn mới là hạn sớm hơn giữa hạn cũ và thời điểm xác nhận tăng mức cộng mốc mới.

| Mức | Điều kiện | Triage tối đa | Khắc phục tối đa từ `known_at` |
|---|---|---|---|
| Khẩn | Có bằng chứng khai thác đang diễn ra và thành phần/đường dùng bị ảnh hưởng; hoặc package được xác nhận độc hại | 4 giờ | Kiềm chế trong 24 giờ; bản sửa hoặc loại bỏ đường bị ảnh hưởng trong 72 giờ |
| Critical | CVSS ≥ 9 hoặc tác động tương đương sau phân tích đường dùng | 24 giờ | 7 ngày |
| High | CVSS 7–8,9 hoặc tác động tương đương | 2 ngày | 14 ngày |
| Medium | CVSS 4–6,9 | 7 ngày | 30 ngày |
| Low | CVSS < 4 | 14 ngày | 90 ngày |

Thiếu CVSS không có nghĩa là Low: phân tích quyền truy cập, dữ liệu, exposure,
đường chạy và tác động; để trạng thái chờ phân loại và chặn release khi có khả
năng ảnh hưởng nghiêm trọng. Thành phần build/test và CI cũng được xem xét vì
có thể tiếp cận source, artifact hoặc secret. Chỉ hạ mức khi có bằng chứng và
người duyệt; hạn cũ không tự được kéo dài.

Trong thời hạn trên, finding vẫn có thể chặn release ngay. Giữ gate đang có:
Dependency Review chặn High mới, npm audit mức High, Maven Dependency-Check
CVSS ≥ 7 và Trivy HIGH/CRITICAL. Thời hạn xử lý không phải quyền bỏ qua gate.
Nếu chưa có bản vá, dùng biện pháp giảm thiểu đã kiểm chứng hoặc loại bỏ đường
bị ảnh hưởng; không đóng finding chỉ vì nhà cung cấp chưa phát hành bản sửa.

## Trách nhiệm và hồ sơ

Maintainer phụ trách thành phần chịu trách nhiệm triage, bản sửa và bằng chứng;
maintainer duyệt release kiểm tra kết luận. Mỗi finding cần có: ID/advisory,
component và phiên bản, đường dùng, severity/exposure, `known_at`, owner,
`triage_due_at`, `remediation_due_at`, trạng thái, biện pháp giảm thiểu và commit/
receipt kiểm chứng. Hồ sơ chứa chi tiết nhạy cảm được lưu private; không đưa
credential, token, raw session hoặc dữ liệu khách hàng vào issue công khai.

Ngoại lệ phải được người phụ trách release duyệt rõ: lý do, đường dùng đã phân
tích, kiểm soát bù, rủi ro còn lại, owner và `expires_at`. Không tự gia hạn khi
chạy lại scanner. Ngoại lệ tối đa 7 ngày cho Khẩn/Critical/High, 30 ngày cho
Medium/Low; hết hạn phải đánh giá lại và chặn release nếu chưa giải quyết.
Ngoại lệ được duyệt không tự thay đổi suppression hoặc cấu hình CI; thay đổi
những kiểm soát đó phải có review và bằng chứng riêng.

## Cập nhật định kỳ và kiểm chứng

- Mỗi 7 ngày, maintainer rà soát advisory, Renovate dashboard và lockfile/image
  đang dùng; rà soát sớm khi có cảnh báo. Khi không thể rà soát đúng hạn, ghi
  quá hạn và người xử lý; không ghi như đã hoàn tất.
- Mỗi 30 ngày, đánh giá cập nhật bản vá/minor dù chưa có advisory. Quyết định
  giữ phiên bản phải có lý do và mốc rà soát tiếp theo không quá 30 ngày.
- Mỗi 90 ngày, rà soát hỗ trợ/EOL và nhu cầu nâng major. Phiên bản gần EOL cần
  kế hoạch hoàn tất trước ngày hết hỗ trợ; quá hạn không tự được chấp nhận.
- Dùng upstream/repository tin cậy, giữ lockfile và digest pin. Đối chiếu SBOM
  với artifact/commit thực tế, xem script cài đặt và transitive dependency.
- Chạy kiểm tra hẹp của phần thay đổi trước, sau đó gate package/CI có liên
  quan; lưu commit, phiên bản trước/sau và kết quả. Không coi scanner xanh là
  bằng chứng duy nhất rằng đường khai thác đã được sửa.
- Với worker/model, kiểm tra schema, calibration, threshold, manifest và parity.
  Chính sách cập nhật không cấp phép training, mở holdout hoặc thay model.
  Khi bản sửa không qua parity, chặn chuyển candidate và đánh giá giảm thiểu;
  không âm thầm giảm kiểm soát hoặc giữ lỗ hổng quá hạn.

Không reset dữ liệu, tài khoản, OTP/mail hoặc credential để đáp ứng chính sách.
Deploy, merge main và thay đổi hạ tầng vẫn cần thẩm quyền đã quy định. ASVS
15.1.1 đánh giá việc định nghĩa thời hạn; 15.2.1 cần thêm hồ sơ finding, tuổi
phiên bản/advisory và bằng chứng thực thi để kết luận tuân thủ thời hạn.
