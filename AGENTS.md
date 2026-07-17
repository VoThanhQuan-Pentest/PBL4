<!-- CODEX-CONTEXT-POLICY:START -->
## Codex context and quality policy

### Context efficiency

- Tìm kiếm bằng `rg`, `git grep` hoặc tên file trước khi mở nhiều file.
- Chỉ đọc file liên quan trực tiếp đến nhiệm vụ và dependency gần nhất.
- Không quét toàn bộ repository khi chưa có lý do rõ ràng.
- Không đọc lại file chưa thay đổi nếu không cần xác minh.
- Tóm tắt log dài, giữ lỗi có thể xử lý đầu tiên và nguyên nhân gốc.
- Không tạo tài liệu hoặc kế hoạch dài trừ khi người dùng yêu cầu.
- Không dùng subagent cho nhiệm vụ một agent có thể xử lý tin cậy.
- Chỉ kích hoạt số lượng skill tối thiểu cần cho nhiệm vụ.
- Sau mỗi giai đoạn, giữ lại quyết định, file đã sửa, test và lỗi còn lại.

### Implementation quality

- Tuân thủ kiến trúc và convention hiện có của project.
- Không tạo kiến trúc song song khi có thể mở rộng code hiện tại.
- Thực hiện thay đổi nhỏ, có thể kiểm tra và dễ hoàn tác.
- Chạy test liên quan trước khi chạy toàn bộ test suite.
- Kiểm tra `git diff` trước khi kết thúc.
- Không tự động thay đổi secret, credential hoặc file môi trường.
- Không chạy script từ skill nếu chưa kiểm tra nội dung và sự cần thiết.

### Skill selection

- Dùng `frontend-design` cho thiết kế giao diện và visual direction.
- Dùng `web-design-guidelines` để review UI, responsive và accessibility.
- Dùng `react-best-practices` chỉ khi phần đang sửa sử dụng React hoặc Next.js.
- Dùng các Spring skill cho backend Spring Boot.
- Dùng `api-and-interface-design` cho API contract và error semantics.
- Dùng `security-and-hardening` cho thay đổi liên quan bảo mật.
- Dùng context skill khi conversation, log hoặc repository context quá lớn.
<!-- CODEX-CONTEXT-POLICY:END -->
