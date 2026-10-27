# Kế hoạch chức năng model 1–4 — tiếp tục ngày 28/10/2026

## Checkpoint và lịch tiếp tục

- Trạng thái hiện tại: **PLANNED**, chưa triển khai bốn chức năng mới.
- Hai lịch một lần trong cùng chat, giờ Việt Nam: **28/10/2026 00:45** và **28/10/2026 05:55**.
- Prompt của cả hai lịch: `Tiếp tục từ phần bị ngắt do hết quota`.
- Khi được đánh thức: đọc kế hoạch và checkpoint riêng, xác minh Git/resource/process,
  lấy khóa một tiến trình, rồi tiếp tục phase chưa hoàn thành đầu tiên. Không mở
  campaign mới khi campaign trước còn chạy hoặc còn reservation chưa đối soát.
- Worktree: `/home/quan/.codex/worktrees/model-capability-assessment/PBL4(UpdateFromPBL3)`;
  branch `codex/model-capability-assessment`. Không sử dụng hai worktree ASVS.
- User đã chốt: **chat này chỉ làm offline và gói bàn giao; ASVS tích hợp runtime**.
  Không sửa serving/backend dùng chung trong các lượt hẹn.
- Checkpoint thực thi riêng:
  `/home/quan/.codex/research/model-capability-assessment/upgrade-1-4-20261028/checkpoint.json`.

## Nền và phạm vi

Giữ nguyên candidate READY A-42 của job `auth-context-v2-20261027-r2`, state SHA
`35b3500d0d924a244224071c74aa9127e482be61863b665070b8532fe058971f`.
Candidate này mới đạt offline; không tự coi receipt nghiên cứu là admission runtime.
Model đang chạy, ngưỡng, calibration và corpus cũ tiếp tục được bảo toàn.

Thứ tự thực hiện: **P0 → P1 → P2 → P3 → P4 → P5**. Không mở rộng sang nghiệp vụ
hoàn tiền/hủy đơn, GPU, thêm thuật toán ML hoặc production qualification.

## P0 — Protocol, nguồn mới và resume

- Tái sử dụng runner/classpath/codec/harness hiện có; thêm adapter nghiên cứu,
  không dựng một serving stack song song. Pin commit, image, feature order, generator,
  protocol, reference model và mọi artifact bằng SHA-256 trước khi chạy dữ liệu.
- Tạo thư mục mới ngoài Git cho từng campaign; không ghi đè job r1/r2 đã tồn tại.
- Checkpoint atomic gồm phase, trạng thái, source/protocol/model SHA, PID/container
  thuộc job, ledger reservation/completion, kết quả, lỗi và đường dẫn receipt.
- Khóa theo job; reservation được ghi trước fit/evaluation. Một fit đã bắt đầu
  tiêu thụ slot, kể cả lỗi. Resume đối soát kết quả đã có, không thử lại để chọn PASS.
- Ngân sách mới: **0 READY-classifier fits, tối đa 4 COLD-classifier fits,
  tối đa 2 temperature-calibrator fits** (mỗi cohort một lần).

Hai corpus mới, account/session/episode tách biệt giữa split và giữa corpus,
ít nhất 256 nhóm tài khoản/split, lịch thời gian có gap ít nhất 14 ngày:

| Corpus | Train | Calibration | Development | Evaluation | Controls |
|---|---:|---:|---:|---:|---:|
| A — READY robustness/confidence | 0 | 10.000 | 10.000 | 20.000 | 10.000 |
| B — COLD | 40.000 | 15.000 | 10.000 | 25.000 | 10.000 |

A: các split có nhãn dùng tỷ lệ routine/review/operations 80/12/8%; controls gồm
5.000 thiếu coverage và 5.000 COLD. B dùng quota lớp của campaign r2; controls
gồm 5.000 thiếu coverage và 5.000 READY để kiểm tra router. Mọi nhãn được chốt
từ kịch bản, nằm ngoài vector; chỉ dữ liệu trước thao tác được dùng làm feature.
Không đọc lại evaluation r2 để chọn model/ngưỡng mới.

## P1 — Độ bền dữ liệu và drift monitor

- Corpus A bổ sung đổi IP/UA đồng thời hợp lệ, hai thiết bị, retry, burst hợp lệ,
  lỗi dịch vụ và các trường hợp gần ranh giới ba lớp. Phân phối không chỉ lặp lại
  một tập tham số cố định của generator r2.
- Kiểm tra hoán vị sự kiện, trùng ID, đến chậm, thiếu quan sát, timestamp tương lai,
  sai phiên/schema, NaN và giá trị ngoài miền. Không tự biến dữ liệu thiếu thành 0.
  Chỗ extractor hiện tại không đáp ứng được ghi thành finding để ASVS xử lý;
  adapter không che lỗi bằng cách thay đổi ý nghĩa đầu vào.
- Monitor offline chỉ giữ counter/histogram, không lưu raw token, OTP hoặc PII.
  Thống kê theo cohort/operation: coverage, lý do UND, score, context, lỗi và latency.
- Reference histogram tạo từ toàn bộ covered calibration A, tách theo operation/cohort:
  10 bin quantile cho số liên tục, category cố định cho biến rời rạc. Cửa sổ ít nhất
  1.000 snapshot hợp lệ; chỉ so các cửa sổ cùng quần thể với reference.
- Cờ drift thử nghiệm: total-variation distance >=0,15 ở ít nhất 3 feature,
  trong 2 cửa sổ liên tiếp; thiếu mẫu trả INSUFFICIENT_DATA. Coverage giảm ít nhất
  5 điểm phần trăm được báo riêng. Drift không tự đổi ngưỡng, refit hoặc chặn.
- Gate chức năng drift: xác định đúng >=90% của 100 cửa sổ shift đã cài trước;
  false alarm <=1% trên 100 cửa sổ ổn định mô phỏng. Tạo các stream bằng resampling
  theo account từ development A, seed cố định, giữ tỷ lệ lớp và chỉ lưu histogram;
  không coi đây là 200 cửa sổ người dùng thực độc lập. Khóa ngưỡng sau development.
- P1 chưa mở scoring evaluation A. Cuối P2 mở evaluation A đúng một lần cho cả
  robustness và calibration, sau khi mọi model/reference/threshold đã niêm phong.
- Đầu ra: drift-reference, robustness receipt, báo cáo theo nhóm, finding và
  interface monitor cho ASVS. Các con số trên là gate lab, không phải SLA production.

## P2 — Confidence và bằng chứng giải thích

- Giữ classifier READY đã fit. Fit đúng một scalar temperature T trong [0,25;4]
  trên calibration A bằng log-loss multiclass; không fit lại classifier.
- Calibrate **xác suất ba context** từ logits. Normal-support novelty/fused raw score
  được báo riêng; không gọi percentile hoặc confidence này là xác suất chiếm quyền.
- Báo reliability diagram, ECE với 15 bin cố định, log-loss/Brier toàn tập và từng nhóm;
  nhóm dưới 100 mẫu ghi thiếu bằng chứng. So sánh ghép cặp theo account group.
- Gate trên evaluation A: log-loss và Brier không xấu hơn đầu ra chưa calibrate,
  cảnh báo nhầm/recall không kém reference. Nếu không đạt, không gắn nhãn CALIBRATED.
- Confidence <0,8 gắn LOW_CONFIDENCE để xem xét; trong bản offline v1 đây là
  diagnostics, không tự sửa recommendation hay enforcement hiện hữu.
- Output bổ sung: confidence, confidence_status, confidence_scope, reason_codes
  tối đa 8 phần tử và evidence_summary tối đa 3 quan sát số có nguồn feature rõ ràng.
  Dữ liệu thiếu/model không sẵn sàng trả confidence null cùng reason cụ thể.
- Evidence là mô tả quan sát như số lần OTP sai, đổi nguồn/UA, thay đổi phiên;
  không giả làm causal feature attribution. Không đưa danh tính hay outcome hiện tại vào feature.
- Đầu ra: calibrator số thuần, schema diagnostics có version, receipt và ví dụ JSON;
  không thay response API đang chạy trong chat này.

## P3 — Model COLD riêng

- COLD là 0–29 trusted window; chia ba strata 0, 1–9 và 10–29, cân bằng trên
  các lớp ở mỗi split. READY vẫn dùng nguyên model/schema đã nghiệm thu.
- Projection nội bộ **42 feature**: POSTLOGIN_NAMES (20) + ROLLING_NAMES[:6] (6)
  + NEW_NAMES (16). Bỏ 37 chiều baseline dài hạn và median lịch sử đóng chưa có.
  Các flag quan sát sẵn có đi cùng duration/count để phân biệt absent với zero.
- Transport đề xuất tiếp tục nhận snapshot schema7 do server tạo; projection/model
  COLD có format riêng `AUTH_COLD_CONTEXT_V1`. Không pad vector 42 thành 81 và
  không thay định nghĩa global schema7/READY. Thiếu coverage vẫn UND.
- Classifier ba context dùng HGB: A=(100 vòng,15 lá), B=(200 vòng,31 lá), seed42/43.
  Đúng 4 fit tối đa. Không dùng/refit normal-support READY cho COLD.
- Ngưỡng chọn bằng calibration B, candidate chọn bằng development: ưu tiên ít FP,
  rồi ít FN, rồi recipe nhỏ và seed thấp. Chỉ một candidate được evaluation một lần.
- Gate evaluation B: FPR <=0,1%, cận trên 95% bảo thủ <=0,2%; recall từng họ >=90%;
  operational false review =0 và operational-correct >=95%; ít nhất 90% COLD hợp lệ
  có assessment. Báo riêng ba strata để không che một nhóm yếu bằng trung bình.
- Fit tối đa một temperature calibrator sau chọn model COLD, dùng calibration B;
  confidence chỉ áp dụng cho context lab. Invalid/missing coverage không được score.
- Codec mới số thuần, bounded, có dimension/order/version/hash; kiểm tra save/load
  parity bằng chính các model đã fit, không tạo thêm fit fixture.
- Nếu gate không đạt: giữ artifact và RESEARCH_NO_ADMISSION; không hạ điều kiện
  READY hoặc biến COLD thành READY để đạt tỷ lệ coverage.

## P4 — Prototype serving và hiệu suất offline

- Adapter/prototype HTTP riêng cho kiểm thử, không chỉnh worker/backend đang chạy.
  Router READY/COLD dựa metadata server-authored và coverage, không tin client tự chọn model.
- Reuse batch tối đa32; batch theo model-manifest/cohort, kiểm tra ID độc nhất và
  ánh xạ kết quả theo snapshot_id kể cả khi thứ tự response thay đổi.
- Batch nền gom trong tick hiện có, tối đa32, không chờ gom trong luồng xác nhận OTP.
  Prototype giới hạn tối đa256 pending item trong bộ nhớ, không tạo Redis/DB queue mới.
- Giữ deadline RPC shadow tối đa2s. Không retry mù; lỗi ảnh hưởng item nào thì
  item đó UND. Circuit breaker: 5 lỗi liên tiếp, mở30s, half-open một request.
- Load model/calibrator một lần theo publication bất biến, giữ kiểm tra checksum;
  không bỏ validation để tăng tốc. READY/COLD phải cùng nằm trong ngân sách worker.
- Test tải batch1/8/32, concurrency1/2/4; 100 warm-up và1.000 batch đo mỗi cấu hình.
  Đo riêng model, HTTP và feature extraction, không gộp để che bottleneck.
- Gate: model batch32 P95<=100ms; HTTP batch32 P95<=250ms ở concurrency4;
  cgroup1CPU/512MiB, RSS đỉnh<=448MiB. Soak60phút không OOM/restart, không tăng
  RSS trung vị >5% giữa phút30–35 và phút55–60 (sample mỗi5s);
  request/result mapping đúng100%. Feature extraction được đo riêng, không coi
  HTTP harness này là benchmark toàn backend/DB của ứng dụng.
- Fault injection: timeout, model hỏng/đổi hash, response thiếu/trùng ID, payload lớn,
  worker unavailable, cạn pending capacity và request bị hủy. Giữ reason rõ, không
  tạo hold, block, revoke session hoặc incident từ prototype.

## Tài nguyên, checkpoint và chia ca

- Mỗi lúc một job; capture/train2CPU/2GiB, benchmark/soak1CPU/512MiB.
  Admission RAM5,5GiB, reserve3GiB; tối đa4GiB artifact mới cộng dồn cho đợt1–4,
  yêu cầu ít nhất9GiB ổ trống. Chỉ chuẩn bị mã/test nhẹ khi chưa đủ admission.
- Với tác vụ nặng, dùng quy trình tạm dừng ELK đã được user cho phép: chỉ các
  service cần để đủ RAM; lưu container/image ban đầu và phục hồi cùng identity
  trong finally, có watchdog độc lập. Không dừng app/DB/Redis/worker/OTP/mail.
- Hết quota không được để ELK dừng vô hạn: process có deadline, journal và cleanup
  độc lập với lượt suy luận. Wake-up sau phải đối soát process/result trước khi tiếp tục.
- 00:45: mục tiêu P0, P1, P2; nếu còn thời gian/quota thì tiếp tục phase kế tiếp.
- 05:55: resume phase đầu chưa xong, ưu tiên P3, P4 và P5. Đây là hai mốc tiếp tục,
  không phải cam kết mọi công việc hoàn thành trong một ca hoặc quota đã reset.
- Trước/sau mỗi phase ghi checkpoint; phần đã đạt không chạy lại khi chưa có thay đổi
  hoặc lỗi cụ thể. Không tự dùng reset quota hoặc mua credit.

## P5 — Bàn giao và gate tích hợp ASVS

Gói bàn giao gồm protocol/manifest/ledger, state/calibrator, schema diagnostics,
router contract, bộ test contract/fault/replay, benchmark/soak, báo cáo giới hạn
lab và hướng dẫn quay lại READY model cũ. Raw corpus/model ở ngoài Git; chỉ
source, test và bản tóm tắt được commit/push trên nhánh nghiên cứu.

Các file runtime dự kiến do ASVS phụ trách, không sửa trong lịch offline:

- `ueba-worker/app/auth_shadow_contract.py`
- `ueba-worker/app/auth_shadow_serving.py`
- `ueba-worker/app/main.py`
- `backend/src/main/java/com/flarefitness/backend/service/siem/SiemAuthShadowService.java`
- `backend/src/main/java/com/flarefitness/backend/service/siem/SiemUebaGateway.java`

Backend hiện bỏ qua COLD trước khi gọi worker, và gateway chỉ nhận đúng một
assessment; chỉ thêm model COLD hoặc batch ở Python sẽ chưa đủ để dùng runtime.
ASVS cần thống nhất routing, diagnostics additive và batch wrapper tương thích
single-item, rồi kiểm chứng trên phiên bản auth/session cuối của họ.

Chỉ đề xuất SHADOW khi cả chất lượng, parity, tài nguyên và compatibility đạt.
Không mở rộng allowlist, không đổi OTP/session/hold policy và không triển khai
từ offline receipt. User duyệt bản tích hợp cụ thể trước deployment.
