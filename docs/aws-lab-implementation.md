# Triển khai AWS SOC và nghiệm thu đề tài 515

Tài liệu vận hành cho bản Web–SOC–UEBA mới. Cấu hình được kiểm thử local;
kết quả cloud phải lấy từ lần triển khai thực tế, không suy ra từ test local.
Phạm vi: hai EC2 tại Singapore, JavaFX/Kibana qua SSH, bộ demo cloud riêng,
ngân sách 40 USD với ngưỡng dự toán triển khai 30 USD. Không bổ sung IDS/IPS mạng hoặc OTP service.

## Trạng thái hiện tại

- Đã bổ sung SG/egress HTTPS 9200 chỉ Web → Monitor private IP.
- Đã bổ sung UEBA worker, model volume, SIEM reader và feature flags trong AWS overlay.
- Có bootstrap Admin qua CLI với encoder hiện có; không tạo endpoint bootstrap HTTP.
- Có seed/verify AWS riêng, công cụ tạo operator, huấn luyện model, duyệt chữ ký và tra IP.
- Đã apply và deploy 29 tài nguyên; Web 52.77.184.249 và Monitor 18.138.13.58 hoạt động.
- Runtime gate AWS PASS ngày 30/09/2026, gồm ba dashboard/sáu rule và sáu alert ID.
- SOC L1/L2, signature approval/ACK, ban 900s/recovery và scan ban 600s đã kiểm thử thật.
- Access log 30/30 PASS p95 5,136s; incident table JavaFX 30/30 PASS p95 29,777s sau commit fixture đóng cửa sổ.
- Hai EC2 stop/start giữ dữ liệu/model/policy; 10 trace lúc Monitor tắt về ELK đúng 10 document.
- SQL/model/Kibana backup restore đã kiểm tra tách biệt. Báo cáo DOCX/PDF, 14 slide, draw.io/PNG,
  bảng nghiệm thu và video hướng dẫn từ slide/ảnh thật nằm trong docs/delivery.
- ML độc lập trên bộ vector thử đơn giản có recall 0; risk engine kết hợp rule vẫn phát hiện fixture.
  Không công bố đây là AI đạt accuracy sản xuất. A16 vẫn PARTIAL cho tập trình bày 15 phút của người bảo vệ.

## 1 Chuẩn bị và kiểm tra trước triển khai

Chạy từ root repo. AWS CLI cần phiên hợp lệ của profile `flare-lab`.

```bash
export AWS_PROFILE=flare-lab
export AWS_REGION=ap-southeast-1
export AWS_DEFAULT_REGION=ap-southeast-1
aws login --profile flare-signin --region ap-southeast-1
aws sts get-caller-identity
./observability/scripts/snapshot-local-release.sh
```

`flare-lab` dùng credential process từ profile nguồn `flare-signin`. Đăng nhập bằng IAM user
`flare-lab-admin` đã cấu hình. Không đồng ý ghi đè profile này bằng danh tính root nếu trình duyệt
đang giữ phiên root; preflight cũng từ chối root credential.

Snapshot nằm trong runtime/private-backups, chứa source đang chỉnh sửa và tham chiếu tới
backup DB/Kibana, cùng archive model. Đây là dữ liệu riêng tư. Source không phải clean commit;
dùng SHA256 của archive để xác định đúng bản đã lưu.

Điền đơn giá AWS hiện hành vào bản sao riêng của `observability/aws-cost-rates.example.json`.
Đơn giá theo USD; mỗi máy chạy tối đa 30 giờ, EBS/EIP giữ 10 ngày, gp3 không mua thêm IOPS/throughput,
dự phòng tối đa 140 GB snapshot (tổng dung lượng ba volume hiện có; dữ liệu thực lưu snapshot thường thấp hơn) và 5 GB egress. `tax_multiplier` là khoản dự phòng, không phải thuế suất đã xác minh.
Giá phải có nguồn và thời điểm kiểm tra trong bảy ngày. Không tính mặc định Free Tier/credit.

```bash
python3 observability/scripts/aws-preflight.py --rates /duong-dan-rieng/aws-rates.json
```

`observability/aws-cost-rates.checked.json` ghi đơn giá kiểm tra ngày 28/09/2026:
0,1197 USD/giờ EC2; gp3 0,096 USD/GB-tháng; snapshot 0,05 USD/GB-tháng;
IPv4 0,005 USD/giờ; egress 0,12 USD/GB. Hệ số 1,20 là khoản dự trù thuế/phụ phí,
không phải xác nhận thuế tài khoản. Với giả định trên, tổng dự toán xấp xỉ 18 USD.
Preflight từ chối bảng giá quá bảy ngày; kiểm tra lại trước khi dùng.

Preflight đọc inventory, quota, AZ, state và địa chỉ IP hiện tại; từ chối state rỗng nhưng còn tài nguyên dự án.
Nó chạy Terraform checks và ghi saved plan vào runtime/aws-preflight-*/reviewed.tfplan.
Plan ép hai instance thành m7i-flex.large, budget 40 USD và CIDR /32 vừa xác nhận;
nó không sửa file tfvars riêng và không gọi apply.

Chủ tài khoản rà plan và chạy:

```bash
terraform -chdir=terraform apply /duong-dan-tuyet-doi/reviewed.tfplan
terraform -chdir=terraform output
```

Preflight ngày 30/09/2026 đã xác nhận: không còn EC2/EBS/EIP/VPC gắn tag dự án,
không còn key pair/role/budget cùng tên dự án; quota Standard là 16 vCPU (đang dùng 0),
quota EIP là 5 (đang dùng 0). Saved plan có **29 create, 0 update, 0 delete**;
hai máy m7i-flex.large, subnet và data EBS cùng AZ ap-southeast-1a; dung lượng gp3 40/20/80 GB,
mã hóa ổ đĩa và IMDSv2 bắt buộc. Ingress SSH/HTTP chỉ từ 171.225.184.147/32;
5044/9200 của Monitor chỉ tham chiếu Web security group. SSH public key khớp key local.
Dự toán **17,99 USD** theo đơn giá đã kiểm tra ngày 28/09 và giả định 30 giờ/máy,
giữ EBS/EIP 10 ngày, dự trù 20% phụ phí; đây không phải hóa đơn thực tế hoặc trần tự ngắt.

Plan riêng tư: `observability/runtime/aws-preflight-20260930T025348Z/reviewed.tfplan`.
SHA256: `f61bed539f905a589f232d64a0d0d828b8c3b7e88bd0b8fa29b2ff21bb472a54`.
Nếu IP, cấu hình hoặc trạng thái AWS thay đổi trước apply, tạo và rà plan mới;
không dùng kết quả preflight này để kết luận rằng nghiệm thu AWS đã hoàn thành.

Apply lần đầu đã hoàn tất. Web: `i-0740371b276b1f296` / `52.77.184.249`;
Monitor: `i-00b945b767fa67a90` / `18.138.13.58`. Lần apply lặp lại cùng saved plan báo
`Saved plan is stale` vì state đã thay đổi sau lần apply đầu; không apply lại file cũ.
Khi cần thay đổi tiếp, tạo một plan mới từ state hiện hành và rà các thay đổi trước apply.

Đợi `cloud-init status --wait` trên cả hai EC2. Không tiếp tục khi EBS Monitor chưa mount.

## 2 Monitor và bundle AWS riêng

```bash
MONITOR_HOST=ubuntu@<MONITOR_EIP> ./observability/scripts/deploy-monitor.sh
MONITOR_HOST=ubuntu@<MONITOR_EIP> ./observability/scripts/fetch-aws-web-bundle.sh
```

Bundle mới nằm dưới `.secrets/aws-lab/web-bundle-*`. Chỉ có CA public, chứng chỉ/key Filebeat
và mật khẩu reader hạn chế. CA private key, server private key và mật khẩu elastic không rời Monitor.
Không copy bundle này đè lên `.secrets/observability` của lab local.

## 3 Web và secret ứng dụng

```bash
python3 observability/scripts/prepare-aws-web-env.py --web-ip <WEB_EIP>
scp .secrets/aws-lab/web.env ubuntu@<WEB_EIP>:/opt/flare/.env
ssh ubuntu@<WEB_EIP> 'chmod 600 /opt/flare/.env'
WEB_HOST=ubuntu@<WEB_EIP> \
AWS_WEB_BUNDLE_DIR="$(pwd)/.secrets/aws-lab/web-bundle-XXXXXX" \
./observability/scripts/deploy-web.sh
```

File môi trường mới không bật profile dev/e2e. Script tạo mật khẩu ngẫu nhiên, từ chối ghi đè.
Deploy lấy hai provider key từ `.secrets/prevention` hoặc `AWS_PROVIDER_KEYS_DIR` được chỉ định.
Chỉ token thuần, không dùng URL hay `Bearer`. Token dịch vụ mới được sinh trên Web.
Nếu provider giới hạn nguồn, thêm Web EIP vào allowlist của tài khoản provider.

Trên Web luôn dùng `observability/scripts/aws-compose.sh web ...`; trên Monitor dùng
`aws-compose.sh monitor ...`. Wrapper đặt root/Compose project nhất quán và kiểm tra secret mount.

## 4 Tài khoản và dữ liệu demo mới

Trên Web qua SSH:

```bash
cd /opt/flare
./observability/scripts/bootstrap-aws-admin.sh
python3 observability/scripts/aws-soc.py provision --url http://127.0.0.1 \
  --bootstrap observability/runtime/private-credentials/aws-bootstrap.json \
  --credentials observability/runtime/private-credentials/aws-operators.json \
  --dataset aws-demo01
python3 observability/scripts/seed-aws-demo.py normal --dataset aws-demo01
python3 observability/scripts/seed-aws-demo.py verify-normal --dataset aws-demo01
```

`verify-normal` có thể chưa đạt ngay trong lúc các worker đang gom/export dữ liệu; xem queue và chạy lại.
Provision tạo Admin vận hành, SOC L1, SOC L2 qua API hiện có, kiểm tra Admin mới rồi soft-delete Admin bootstrap.
Bootstrap khóa chạy đồng thời và chỉ xuất bản file credential chính sau khi JSON hợp lệ.
Nếu Docker/SSH hoặc validation lỗi, file `aws-bootstrap.capture-*` được giữ mode 0600 trong
thư mục private-credentials để kiểm tra trực tiếp; không gửi nội dung vào chat/evidence và
không tự reset Admin. Không ghi đè file credential đã tồn tại.
Catalog có ba sản phẩm demo với SKU riêng để website mới có dữ liệu thao tác.
Mật khẩu không được in ra terminal; file credentials mode 0600. Bốn khách hàng có mật khẩu ngẫu nhiên riêng.
Một khách hàng thứ năm chỉ có một sự kiện mẫu để trình diễn trạng thái chưa đủ baseline.
Seed idempotent theo dataset; không xóa dữ liệu cũ. Đổi dataset khi cần một thí nghiệm độc lập.

```bash
python3 observability/scripts/aws-soc.py train --url http://127.0.0.1:8089 \
  --credentials observability/runtime/private-credentials/aws-operators.json
python3 observability/scripts/seed-aws-demo.py abnormal --dataset aws-demo01
python3 observability/scripts/seed-aws-demo.py verify-abnormal --dataset aws-demo01
python3 observability/scripts/aws-soc.py signature --url http://127.0.0.1:8089 \
  --credentials observability/runtime/private-credentials/aws-operators.json
python3 observability/scripts/aws-soc.py lookup --url http://127.0.0.1:8089 \
  --credentials observability/runtime/private-credentials/aws-operators.json
```

Train chỉ activate sau khi job SUCCEEDED với provenance DEMO_ONLY. Abnormal được tạo sau huấn luyện.
Signature sử dụng tài khoản L2, mẫu GET /.env và fixture mặc định rồi đợi ACK ACTIVE.
Lookup kiểm tra cả IPinfo/AbuseIPDB FRESH/REAL với IP công khai 8.8.4.4.

## 5 Kết nối người vận hành

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18089:127.0.0.1:8089 ubuntu@<WEB_EIP>
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18088:127.0.0.1:80 ubuntu@<WEB_EIP>
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:15601:127.0.0.1:5601 ubuntu@<MONITOR_EIP>
```

JavaFX server URL: http://127.0.0.1:18089. Website đăng nhập/quản trị: http://127.0.0.1:18088.
Kibana: http://127.0.0.1:15601. Copy credentials qua SSH vào file riêng tư trên máy vận hành nếu cần.
Public EIP chỉ dùng request thử nghiệm được cho phép; IP nguồn khi đi qua tunnel sẽ khác IP public người thử.

Credential vận hành AWS được lưu riêng trong `.secrets/aws-lab/aws-operators.json` trên máy quản trị
(mode 0600), không đưa vào tài liệu công khai. Trong file có Admin, SOC L1 và SOC L2; Admin bootstrap đã retire.
Chạy bản Linux đã đóng gói bằng `desktop-client/target/dist/FlareSecurityMonitor/bin/FlareSecurityMonitor`.
Sau stop/start EC2 phải mở lại tunnel trước khi dùng client; lỗi ConnectException không có nghĩa mất tài khoản.

## 6 Nghiệm thu và hồ sơ

```bash
WEB_HOST=ubuntu@<WEB_EIP> MONITOR_HOST=ubuntu@<MONITOR_EIP> \
FLARE_LAB_TARGET=http://<WEB_EIP> FLARE_LAB_ALLOWED_HOST=<WEB_EIP> \
I_OWN_THIS_TARGET=yes ./observability/scripts/verify-aws-lab.sh
```

Gate này kiểm tra hạ tầng, log/GeoIP, Kibana, role SOC, model và policy/provider. Nó không thay thế
ma trận nghiệm thu đầy đủ: workflow L1/L2, 30 mẫu độ trễ và phục hồi phải có bằng chứng riêng.
Điền `docs/aws-acceptance.csv`; không chuyển PENDING thành PASS từ việc script build thành công.

Sau khi Terraform output có EIP thật và hai máy được deploy, đo access-log từ máy kiểm thử:

```bash
python3 observability/scripts/measure-aws-access-latency.py --samples 30
```

Tool lấy đích và Monitor từ Terraform output, chỉ gửi GET /api/health, truy vấn ELK qua SSH bằng
reader credential trên Monitor. CSV và summary ở runtime. Độ trễ tính từ lúc gửi request tới
lần truy vấn đầu tiên tìm thấy trace, có cả overhead SSH; p50/p95 dùng nearest rank.
Kết quả này chỉ đánh giá access-log visibility, chưa đo thời gian tạo incident/UEBA.

Demo 15 phút: kiến trúc (2), website và log (2), L1 chuyển L2 (3), chữ ký/block/unblock (3),
IP intelligence (1), UEBA (2), kết quả đo và giới hạn (2). Mã OTP, cookie, key và mật khẩu không nằm trong video.
Thử HTTP flood bằng fixture local; không chạy DDoS lên AWS.

## 7 Vận hành và khôi phục

Sau mỗi buổi, dừng hai EC2 theo Instance ID trong Terraform output và ghi số giờ sử dụng.
EBS/IPv4 vẫn tính phí khi máy dừng; kiểm tra chi phí trước buổi tiếp theo. Không xem Budgets là hard cap.
Trước cập nhật: snapshot source, backup DB/model, export Kibana; giữ bản backup ngoài máy sẽ bị destroy.
Khi code lỗi: trở lại image/source đã ghi SHA, recreate app bằng wrapper, không dùng `down -v`.
Không tự động downgrade schema; thử khôi phục DB vào volume/container kiểm tra riêng trước.
Sau nghiệm thu cuối, chỉ destroy khi đã xác nhận backup và đúng tài nguyên của dự án.

## Tiêu chí báo cáo

Sáu chương: yêu cầu; cơ sở lý thuyết; thiết kế; triển khai; đánh giá; kết luận.
Tách local/AWS và dữ liệu thật/DEMO_ONLY. Ghi commit hoặc archive SHA và ngày đo.
Không ghi accuracy/precision/recall hoặc độ trễ nếu chưa có mẫu và phép đo.
Hồ sơ cuối cần DOCX/PDF, draw.io/PNG, bộ slide 12–15 trang, JavaFX Linux và video demo thực.

Video đã tạo là walkthrough không âm thanh 15 phút từ slide và ảnh JavaFX AWS thật,
không phải bản quay thao tác liên tục. Xem `docs/delivery/huong-dan-video.txt`.
Các kết quả PASS_SCOPE trong CSV có giới hạn phương pháp ngay trong cột evidence.
