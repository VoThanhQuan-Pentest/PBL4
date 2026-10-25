# Model cũ và chặn có kiểm soát trong lab

Phạm vi nghiệm thu đã chọn: **lab/đồ án, PROJECT_LIMITED, giữ OTP**. Model factorial fold3 được tái sử dụng nguyên trạng; không fit lại, không đổi calibration/ngưỡng và không mở holdout. Provenance: `DEMO_ONLY_RULE_DISTILLATION`. Kết quả mô phỏng trước đây: 0 FP / 1 FN trên 40.000 normal và 2.000 positive. Nghiệm thu hiện tại kiểm tra tích hợp và chính sách trong lab; dữ liệu người dùng thực vẫn cần đánh giá riêng.

## Trạng thái và các bước tự động

Checkpoint nằm tại `observability/runtime/postlogin-legacy-reuse-20261022-r1/implementation-state.private.json`. Chỉ xem hoàn tất khi có commit hợp lệ `implementation-result-v1.commit.private.json` và receipt `PROJECT_LIMITED_IMPLEMENTATION_COMPLETE`.

Luồng còn lại sau code/test: OBSERVE liên tục 3.600 giây với ít nhất 30 đánh giá HTTP bằng model cố định → kiểm thử rollback/bảo vệ khi lỗi → nâng cấp bản sao MySQL riêng → triển khai đúng image đã kiểm chứng → kiểm tra OTP/SOC/tài khoản/ca dành cho giảng viên → bật `ENFORCE_LIMITED` cho duy nhất `e2e-customer`. Mỗi bước có receipt và ngân sách; lỗi giữ runtime ở OBSERVE để chẩn đoán. Không có yêu cầu OTP thật tự động.

Gửi **“tạm dừng”** trong chat để dừng an toàn. Gửi **“Tiếp tục đi”** để kiểm tra checkpoint và tiếp tục. Phiên OBSERVE bị ngắt được giữ lại; phiên đạt chuẩn phải là một giờ liên tục mới. Không phát lại yêu cầu nhạy cảm chưa xác định kết quả.

## Khởi động sau khi rollout lần đầu hoàn tất

```bash
cd '/home/quan/PBL4(UpdateFromPBL3)'
docker info >/dev/null
python3 observability/scripts/postlogin_project_site.py start
python3 observability/scripts/postlogin_project_site.py status
mvn -f desktop-client/pom.xml compile javafx:run
```

Mở website tại `http://localhost:8088`. Lệnh `start` yêu cầu receipt rollout hợp lệ, dùng lại cấu hình SMTP/private site có sẵn, giữ database và seed đã có. Không reset mật khẩu hoặc nạp lại fixture E2E. Các dịch vụ gồm MySQL, Redis, app, Nginx và worker chỉ chấm điểm. Worker không mở cổng host; API training/adoption bị vô hiệu trong chế độ serving-only.

Nếu chưa có receipt rollout, lệnh này từ chối; theo dõi checkpoint và chờ bộ điều phối hoàn tất các gate. Bộ ca luyện tập và ca dành cho giảng viên dùng hướng dẫn [LOCAL_SOC_DEMO_L1_L2.md](LOCAL_SOC_DEMO_L1_L2.md). Các ca workflow cũ và tài khoản demo được giữ nguyên.

## Các quyết định

| Quyết định | Ứng xử |
|---|---|
| NORMAL | Tiếp tục kiểm tra auth, OTP và các ràng buộc hiện có. |
| STEP_UP | Giữ yêu cầu OTP; chờ SOC xem xét nếu cần. Tài khoản COLD không tự bị giữ bởi ML. |
| TEMP_HOLD | Tạm từ chối thao tác trước ghi dữ liệu; cùng tài khoản + phiên + loại thao tác, tối đa 600 giây. |
| OPS_ALERT | Chuyển dấu hiệu lỗi dịch vụ tới SOC; lỗi 5xx đơn thuần không gây chặn khách hàng. |
| UNDETERMINED | Thiếu coverage hoặc worker không sẵn sàng: giữ OTP/rate limit, không tạo hold mới từ ML. Hold đã có giữ thời hạn ban đầu. |

TEMP_HOLD cần đồng thời coverage hợp lệ, READY với ≥30 window tin cậy, vượt ngưỡng cố định và context `BEHAVIOR_REVIEW_CONTEXT`, cộng một trong hai bằng chứng:

- Ít nhất ba lần sai OTP xác nhận trong cùng tài khoản/phiên/thao tác/15 phút. Gửi lại cùng request ID không tính thêm lần sai.
- Cùng IP do server xác định có ≥50 HTTP request, ≥7 loại endpoint, ≥45% lỗi 4xx; cache AbuseIPDB `REAL/FRESH`, chưa hết hạn, score ≥80, ≥3 reports và ≥2 reporters.

Cache mô phỏng, thiếu hoặc hết hạn không đủ điều kiện bổ sung. Không gọi provider trong luồng ghi dữ liệu. IP reputation là bằng chứng bổ sung ở policy, không phải feature mới để fit model. Ngưỡng READY/COLD vẫn là 99,99/99,9995 percentile; percentile không phải xác suất tài khoản bị chiếm.

## SOC L1 → L2

Đăng nhập app bằng tài khoản lab trong hướng dẫn demo. Vào **Post-login decisions**, bấm **Refresh**, chọn một quyết định để đọc reason, coverage, model/policy version, snapshot và trạng thái hold. **Open linked incident** đưa về incident tương ứng.

L1 có thể đọc và ghi chú trong incident. Để L2 xử lý: L1 Claim → ghi lý do → Escalate to L2 → L2 đăng nhập và Claim incident → mở **Inspect action decision / temporary hold** hoặc **Post-login decisions**. L2 phải được gán incident ở trạng thái `L2 / IN_PROGRESS`; Admin cũng được xử lý.

**Release temporary hold** cần lý do 10–1.000 ký tự và đúng version hiện tại. **Save review** ghi `LEGITIMATE`, `CONFIRMED_ABUSE` hoặc `UNDETERMINED`; lịch sử được thêm mới, không tự đổi nhãn/training. Khi có lỗi version, Refresh và đọc lại trước khi gửi. Giải phóng hold vẫn giữ OTP.

Trên website, hold hiển thị thời gian chờ và mã quyết định. Hết hạn, gửi lại biểu mẫu để tạo challenge/OTP mới; trình duyệt không tự gửi lại thao tác. Nếu DB lỗi sau khi OTP đã được tiêu thụ, dữ liệu tài khoản rollback; cần kiểm tra kết quả và tạo xác nhận mới.

## Quay về quan sát và xử lý lỗi

Khóa mở job mới và đưa runtime về quan sát ngay:

```bash
python3 observability/scripts/postlogin_impl_control.py hold
```

Đặt policy về quan sát với cùng binary/schema đã nâng cấp:

```bash
python3 observability/scripts/postlogin_project_site.py observe
```

`off` tắt policy bổ sung; OTP hiện có vẫn giữ. Giữ audit/decision/hold/review và database. Không dùng Flyway repair, không phục hồi đè DB, không quay về image cũ trên schema mới. Nếu fingerprint model/source/image khác, giữ runtime hold và kiểm tra checkpoint/log riêng trước khi tiếp tục.

Các job nền cần máy đang bật. Tắt máy/ngắt phiên một giờ không tạo kết quả PASS; kiểm tra lại checkpoint sau khi bật máy. `tạm dừng` trong chat bao gồm việc xác minh job đã dừng trước khi xác nhận với bạn.
