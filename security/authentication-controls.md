# Kiểm soát đăng nhập và giới hạn tự động

Phạm vi: hành vi hiện có của backend/gateway và cấu hình ASVS riêng. Không thay
đổi cấu hình local đang chạy hoặc chứng nhận model, môi trường production.

## Đường xác thực và ranh giới quyền

| Đường vào ứng dụng | Bằng chứng và kiểm soát |
| --- | --- |
| Web/API qua Nginx hoặc trực tiếp backend | Cấu hình ASVS yêu cầu mật khẩu rồi OTP email qua `/api/auth/login` và `/api/auth/login/otp`; CSRF vẫn bắt buộc. Cookie và Bearer JWT dùng cùng bộ kiểm tra chữ ký, Redis allowlist, ID tài khoản, `auth_version`, trạng thái và quyền. |
| JavaFX | Gọi cùng API mật khẩu/OTP, giữ cookie và CSRF; không có bộ kiểm tra mật khẩu riêng hoặc bước xác thực local thay thế. |
| Gateway phục hồi `8089` | Publish loopback trong overlay; whitelist auth/SIEM, giữ lỗi xác thực và kiểm tra quyền SOC của backend. Không cấp JWT tại gateway. |
| Gateway ↔ backend prevention | Ba route policy/ack/test và token máy `X-Flare-Service-Token` được mô tả ở [README](../README.md#các-kênh-xác-thực-của-gateway-và-backend). Route test dùng chung listener công khai; không dựa vào tiền tố `/internal/` để bảo vệ. |
| Backend → UEBA worker | Backend đọc `SIEM_UEBA_SERVICE_TOKEN_FILE`, gửi `X-UEBA-Token` tới worker; worker đọc `UEBA_SERVICE_TOKEN_FILE`, yêu cầu token ít nhất 32 ký tự và so sánh bằng `secrets.compare_digest`. Thiếu/sai token trả `403`, không đọc được tệp trả `503`. Token máy không cấp phiên người dùng. |
| CLI bootstrap AWS | Công cụ SSH riêng `AwsLabBootstrap`, yêu cầu `FLARE_ENVIRONMENT=aws-lab` và quyền DB để tạo admin khi chưa có admin hoạt động. Không phải API HTTP, không được gọi bởi entrypoint backend mặc định. Vòng đời mật khẩu khởi tạo chưa được tài liệu này chứng nhận. |

Đăng ký vẫn cần mật khẩu tự chọn và OTP email; khôi phục chỉ cấp grant đặt lại
mật khẩu gắn tài khoản sau OTP, không tự cấp phiên đăng nhập. Chế độ local
tương thích tắt OTP được công bố nhưng không nằm trong kết luận nhiều yếu tố
của cấu hình ASVS.

Khi `APP_LOGIN_OTP_ENABLED=true`, đổi email đăng nhập bắt buộc xác nhận email
hiện tại, độc lập với allowlist thử nghiệm xác nhận thao tác. Đổi mật khẩu cũng
cần mật khẩu hiện tại và OTP email hiện tại; phạm vi thử nghiệm ML vẫn dùng
allowlist hiện có. Web hỏi
`GET /api/profile/action-confirmations/policy?operation=EMAIL_CHANGE` hoặc
`PASSWORD_CHANGE`; bỏ tham số giữ phản hồi chính sách thử nghiệm cũ, cùng ba
trường JSON `required`, `contact_available`, `policy_id`.

Chuẩn bị đổi email phải có `current_password` đúng trước khi lưu challenge hay
gửi mã tới email hiện tại. Challenge gắn tài khoản, phiên, phiên bản xác thực,
email hiện tại và nội dung thay đổi; thời hạn tối đa 300 giây. Thực hiện cần
cả mã email hiện tại và mã sở hữu email đích. Mật khẩu hiện tại chỉ nằm trong
yêu cầu chuẩn bị, không được lưu trong bản ghi challenge. Các challenge đổi
email theo policy cũ bị từ chối; phải chuẩn bị lại với policy
`password-and-current-email-otp-v2`. Tài khoản thiếu bằng chứng xác minh email
hiện tại bị chặn cho tới khi có quy trình xác minh hợp lệ. Luồng PUT trực tiếp
trả `409 ACTION_CONFIRMATION_REQUIRED` khi chính sách yêu cầu xác nhận; client
cần dùng các endpoint chuẩn bị/thực hiện hiện có. Khi tắt MFA và không thuộc
allowlist, đổi email trực tiếp vẫn cần mật khẩu hiện tại và OTP email đích.
Quản trị viên đổi email của chính mình cũng phải dùng hồ sơ cá nhân; API quản
lý người dùng từ chối tự đổi/xóa email và tự đặt mật khẩu để tránh bỏ qua bước
xác thực lại. Mật khẩu trống hoặc bỏ qua trong yêu cầu quản lý giữ mật khẩu cũ;
đặt lại mật khẩu cho tài khoản khác vẫn theo quyền quản trị hiện hữu. Challenge
đổi mật khẩu v1 đã kiểm tra mật khẩu hiện tại nên vẫn giữ policy ID và TTL cũ.

Với hai hostname công khai `flarefitness.site` và `www.flarefitness.site`,
yêu cầu HTTP tới namespace `/api`, `/internal`, `/actuator` trả 400, không có
`Location`; client phải gọi HTTPS ngay từ đầu. Quy tắc dùng URI đã chuẩn hóa,
chạy trước chuyển hướng trang và chọn location. Trang dành cho người dùng vẫn
chuyển hướng 301. HTTP local và HTTPS đã được proxy tin cậy xác nhận giữ luồng
hiện hữu. Việc từ chối không thể thu hồi dữ liệu mà client đã gửi qua HTTP.
Phản hồi chuyển hướng 301 giữ nguyên `Location` và dùng nội dung HTML cố định
với `text/html; charset=utf-8`; không đưa dữ liệu yêu cầu vào HTML. CSS, XML và
SVG do Nginx phục vụ cũng khai báo UTF-8. Điều này không chứng nhận toàn bộ
phản hồi của backend, gateway và các tích hợp khác.

Backend chỉ giữ `X-Request-ID` hợp lệ khi TCP peer trực tiếp thuộc CIDR proxy
đã cấu hình; caller khác nhận UUID mới dù gửi thêm header IP giả. Header phản
hồi, MDC và `traceId` trong lỗi API dùng cùng mã đã được quyết định ở filter.
UUID yêu cầu của sự kiện xác thực vẫn được server tạo độc lập cho mọi request.
Client trực tiếp backend cần dùng mã phản hồi để tra cứu lỗi; không dựa vào mã
do chính client gửi để xác định yêu cầu đã được hệ thống tin cậy.

Gateway mặc định dùng IP TCP trực tiếp và bỏ qua header IP do caller gửi.
Khi có terminator tin cậy, chỉ cấu hình `PREVENTION_TRUSTED_PROXY_CIDRS` bằng
CIDR số chuẩn của peer trực tiếp; không có DNS, không cho phép CIDR toàn mạng.
Peer đó phải thay `X-Forwarded-For` bằng đúng một IP client số. Header thiếu,
trùng, chuỗi nhiều hop, hostname, port, zone hoặc quá dài bị từ chối; caller
không tin cậy vẫn bị bỏ qua header. IP quyết định một lần trước chặn, rate limit,
CRS, log và chuyển tiếp. Listener quản trị phục hồi vẫn chỉ dùng IP TCP trực tiếp.
Profile TLS CI dành riêng đặt edge ở `172.31.0.51` và chỉ tin `/32` đó. Nếu đổi
subnet CI, đặt rõ `ASVS_TLS_EDGE_PRIVATE_IP` vào địa chỉ IPv4 còn trống trong
subnet, cùng cấu hình gateway hiện có. Base/local/AWS không tự bật chế độ này.
IP phục vụ tín hiệu mạng, không phải định danh tài khoản; NAT/VPN có thể dùng
chung IP và thay đổi IP. Không thay credential, model hoặc stack live để kiểm tra.

Mọi route `/internal/v1/*` của UEBA worker có dependency `require_token`;
`GET /health` công khai để kiểm tra trạng thái. Các overlay local/AWS đặt worker
trên mạng `ueba-internal`, không publish cổng host, và mount token ngoài Git chỉ
đọc. Khi overlay post-login đặt `UEBA_POSTLOGIN_SERVING_ONLY=true`, middleware
chỉ cho `/health`, `/internal/v1/postlogin/score` và
`/internal/v1/postlogin/shadow-score`; các route train/evaluate/activate/adopt/job
khác trả `404` trước endpoint. Đây là mô tả quyền hiện có, không phải yêu cầu
chạy các API đó. Bảo vệ đường truyền, cấp/xoay/thu hồi token và xác minh cấu hình
đang triển khai phải đánh giá riêng; không suy ra từ quyền truy cập model volume.

## Chính sách phiên đồng thời

Web và JavaFX dùng cùng chính sách backend: một tài khoản được phép có nhiều
phiên hợp lệ đồng thời, **không đặt giới hạn hữu hạn theo số lượng phiên**.
Backend không đếm số phiên để từ chối đăng nhập mới hoặc tự loại thiết bị cũ.
Vì không có ngưỡng tối đa hữu hạn, không có nhánh xử lý khi chạm trần số phiên.

Mỗi lần xác thực thành công cấp JWT có ID phiên mới. Backend thu hồi riêng
phiên đã được xác thực và gửi kèm yêu cầu đăng nhập thành công; phiên trên các
thiết bị khác tiếp tục theo thời hạn riêng. Mật khẩu đang chờ OTP hoặc OTP sai
không xoay/thu hồi phiên đang dùng. Giới hạn thử đăng nhập và quota OTP dưới
đây vẫn áp dụng khi cấp phiên, độc lập với chính sách số phiên đồng thời.

Phiên kết thúc theo timeout/thời hạn tuyệt đối đã nêu trong [README](../README.md),
thu hồi một phiên, thu hồi toàn bộ hoặc kiểm tra trạng thái/phiên bản xác thực
tài khoản ở backend. Số phiên được cho phép không thay thế các kiểm soát này.
Hiệu lực của từng luồng thu hồi được đánh giá riêng.
Chính sách này mô tả hành vi hiện có của [AuthController](../backend/src/main/java/com/flarefitness/backend/controller/AuthController.java)
và [RedisTokenStore](../backend/src/main/java/com/flarefitness/backend/security/RedisTokenStore.java).

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
