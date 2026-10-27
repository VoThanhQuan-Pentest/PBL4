# Kết quả nghiên cứu model auth offline — 27/10/2026

Job `auth-context-v2-20261027-r2` hoàn tất với `RESEARCH_PASS` và
`BENCHMARK_PASS`. Candidate mới A-42 được fit trên corpus mới; đối chứng A-42
cũ giữ nguyên state và ngưỡng. Candidate chỉ nằm offline, chưa được kích hoạt.

## Chất lượng trên evaluation lab mới

| Chỉ số | A-42 cũ | Candidate A-42 mới |
|---|---:|---:|
| Cảnh báo nhầm / 20.000 routine | 2.500 | 0 |
| Phát hiện / 3.000 review context | 3.000 | 3.000 |
| Recall từng họ case3/case4/case5 | 100% / 100% / 100% | 100% / 100% / 100% |
| Phân loại đúng / 2.000 lỗi dịch vụ | 2.000 | 2.000 |
| Nhầm lỗi dịch vụ thành review | 0 | 0 |

Cảnh báo nhầm của đối chứng nằm ở nhóm cập nhật trình duyệt hợp lệ.
Bootstrap ghép cặp theo 256 nhóm tài khoản, 2.000 resample, cho khoảng 95%
của chênh lệch false-review rate candidate−A42 là −12,94 đến −12,08 điểm
phần trăm. Đây là dữ liệu `CONTROLLED_CLOCK_LAB`; không suy ra độ chính xác
trên người dùng thực hoặc qualification production. Hai nhóm control gồm
5.000 COLD và 5.000 thiếu coverage được kiểm tra hợp lệ, không được fit.

## Thời gian và tài nguyên

| Bước | Thời gian |
|---|---:|
| Chuẩn bị Java classpath riêng | 12 giây |
| Tạo 100.000 snapshot | 568 giây |
| Tái xuất và kiểm tra parity | 302 giây |
| Bốn lượt fit, calibration và chọn candidate | 52 giây |
| Evaluation một candidate | 20 giây |
| Benchmark | 14 giây |

Đúng 4 classifier fits, 0 normal-component fits. Tổng thời gian job, gồm
tạm dừng và khôi phục ELK, khoảng 17 phút 9 giây. Artifact job khoảng
612 MiB. Benchmark chạy 1 CPU/512 MiB: RSS đỉnh 130 MiB; P95 batch 1 là
3,89 ms, batch 32 là 7,40 ms, mỗi cỡ có 100 warm-up và 1.000 batch đo.

## Bằng chứng và bảo toàn runtime

Artifact riêng ở `/home/quan/.codex/research/model-capability-assessment/auth-context-v2-20261027-r2`.
State candidate: `35b3500d0d924a244224071c74aa9127e482be61863b665070b8532fe058971f`.
Receipt: `result/research-receipt.json`, `result/benchmark-receipt.json` và
`maintenance.json`. Corpus/model không đưa vào Git.

Elasticsearch, Logstash và Kibana đã được khôi phục về cùng container/image,
đều healthy. Checksum model cũ không đổi; ứng dụng, database, Redis, worker,
gateway, Nginx, Filebeat và Mailpit giữ nguyên container/start time.

Job r1 được giữ lại: parity dừng trước mọi fit do so sánh tuple với list sau
JSON round-trip. Commit `08c8c6a` sửa bằng so sánh canonical JSON và có test
hồi quy; r2 tạo lại corpus từ đầu, không sửa dữ liệu r1 hoặc thử thêm model.
