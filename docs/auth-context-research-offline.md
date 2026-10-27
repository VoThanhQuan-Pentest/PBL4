# Nghiên cứu model auth offline

Pipeline này tạo corpus lab và candidate riêng, so sánh với A-42, rồi ghi receipt
nghiên cứu. Nó không kích hoạt model và không điều khiển stack đang chạy. Dữ liệu
mô phỏng và artifact model nằm ngoài Git, trong một job mới thuộc
`/home/quan/.codex/research/model-capability-assessment/`.

Capture, parity, train và benchmark yêu cầu ít nhất 5,5 GiB RAM khả dụng và
9 GiB ổ trống; nếu RAM giảm dưới 3 GiB, tiến trình nghiên cứu bị dừng. Phải có
Docker daemon và các image đã pin trong script. Việc chuẩn bị classpath dùng
app image chỉ để trích xuất jar từ một container riêng không chạy ứng dụng.

```bash
research_job=/home/quan/.codex/research/model-capability-assessment/auth-context-v2-20261027-r1
python3 observability/scripts/auth_context_research_classpath.py --job "$research_job" --init-job
python3 observability/scripts/auth_context_research_classpath.py --job "$research_job"
research_classpath=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["classpath"])' "$research_job/classpath-receipt.json")
research_jar_sha=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["application_jar_sha256"])' "$research_job/classpath-receipt.json")
python3 observability/scripts/auth_context_research_runner.py capture --job "$research_job" --java-classpath "$research_classpath"
python3 observability/scripts/auth_context_research_runner.py parity --job "$research_job" --java-classpath "$research_classpath" --application-jar-sha256 "$research_jar_sha"
mkdir -m 700 "$research_job/result"
python3 observability/scripts/auth_context_research_runner.py select --job "$research_job"
```

Chỉ khi `result/selection.json` có `status: SELECTED`, chạy:

```bash
python3 observability/scripts/auth_context_research_runner.py evaluate --job "$research_job"
```

Chỉ khi `result/research-receipt.json` có `status: RESEARCH_PASS`, chạy:

```bash
python3 observability/scripts/auth_context_research_runner.py benchmark --job "$research_job"
```

Kiểm tra các receipt và log của job khi có lỗi. Một lượt fit hoặc evaluation
đã được đặt chỗ không được chạy lại để chọn kết quả tốt hơn. Kết quả là bằng
chứng `OFFLINE_RESEARCH_ONLY`, chưa phải qualification cho người dùng thực.
