# Kiểm soát đăng nhập và giới hạn tự động

Phạm vi: hành vi hiện có của backend/gateway và cấu hình ASVS riêng. Không thay
đổi cấu hình local đang chạy hoặc chứng nhận model, môi trường production.

## Cấu hình và tác dụng

Backend đọc các biến sau qua [application.properties](../backend/src/main/resources/application.properties).
Biến phải có trong môi trường backend; khai báo trong `.env` của host không tự
chuyển biến vào container nếu Compose không có trường `environment` tương ứng.

| Biến backend | Mặc định | Tác dụng |
| --- | --- | --- |
| `APP_SECURITY_LOGIN_MAX_ATTEMPTS_PER_MINUTE` | 5 | Đặt chỗ mỗi lần thử theo IP trước khi kiểm tra mật khẩu. |
| `APP_SECURITY_LOGIN_MAX_ACCOUNT_ATTEMPTS_PER_MINUTE` | 5 | Bộ đếm độc lập theo tên đăng nhập chuẩn hóa, hạn chế đổi IP để dò một tài khoản. |
| `APP_OTP_MAX_VERIFICATION_ATTEMPTS` | 5 | Giới hạn xác minh OTP chung; OTP đăng nhập cố định năm lần/300 giây, xác nhận thao tác cũng chặn tối đa năm lần. |
| `APP_OTP_COOLDOWN_SECONDS` | 60 | Khoảng cách gửi OTP chung; đăng nhập và xác nhận thao tác giữ tối thiểu 60 giây. |
| `APP_OTP_MAX_REQUESTS_PER_EMAIL_PER_HOUR` | 5 | Quota gửi theo mục đích và email trong một giờ. |
| `APP_OTP_MAX_REQUESTS_PER_IP_PER_HOUR` | 20 | Quota gửi theo mục đích và IP trong một giờ. |
| `APP_OTP_MAX_REQUESTS_PER_EMAIL_PER_DAY` | 20 | Quota email dùng chung giữa các mục đích trong một ngày. |
| `APP_OTP_MAX_REQUESTS_PER_IP_PER_DAY` | 80 | Quota IP dùng chung giữa các mục đích trong một ngày. |

[Nginx](../docs/phan-tich-cau-truc/cong-nghe/01-nginx.md#giới-hạn-tốc-độ-api)
giới hạn `/api/` ở 30 request/giây/IP, burst 60. Backend vẫn áp dụng hai bộ
đếm đăng nhập khi client đi trực tiếp hoặc qua cổng phục hồi; header IP chỉ
được tin khi peer thuộc proxy đã cấu hình. Quota gửi hạn chế tự động hóa và
lạm dụng SMTP; ngân sách xác minh hạn chế dò mã sau khi challenge được cấp.

## Giới hạn tạm thời và chống khóa tài khoản ác ý

Lua đặt TTL 60 giây khi tạo bộ đếm đăng nhập, không kéo dài TTL theo từng lần
thử tiếp theo. Đăng nhập thành công chỉ xóa bộ đếm tài khoản, giữ bộ đếm IP.
Các bộ đếm này không tự đổi trạng thái tài khoản thành khóa/vô hiệu vĩnh viễn.
Challenge OTP đăng nhập chỉ được tạo sau khi mật khẩu đúng; gửi lại không xóa
ngân sách sai OTP theo tài khoản trong 300 giây. Không reset Redis/counter hoặc
giảm giới hạn chỉ để một bài demo đăng nhập được.

Tấn công liên tục vẫn có thể làm người dùng hợp lệ chạm quota, kể cả quota
email. TTL hữu hạn không bảo đảm loại bỏ mọi từ chối dịch vụ có chủ đích. SOC
cần đối chiếu IP do server quan sát và audit trước khi dùng quyền xử lý hiện
có; không coi một lần bị throttle là bằng chứng tài khoản bị chiếm.

## Phản ứng thích nghi

[Auth investigation](../docs/LOCAL_SOC_WORKSPACE_AUTH_PILOT.md#auth-investigation-policy)
ở `OBSERVE` chỉ ghi nhận, `ALERT` tạo case; correlation/shadow không tự cô lập
tài khoản, chặn IP đến khi thu hồi hoặc tạo ML hold. [Policy lab sau đăng nhập](../docs/LOCAL_POSTLOGIN_PROJECT.md#các-quyết-định)
giữ OTP/rate limit, chỉ cho hold có phạm vi tài khoản/phiên/thao tác và tối đa
600 giây khi đủ các gate đã công bố. COLD/thiếu coverage/lỗi worker không tạo
hold mới từ ML. Giải phóng hold không tắt OTP. Các bằng chứng vận hành và
model vẫn phải đánh giá riêng; tài liệu này không yêu cầu chạy model hoặc rollout.
