"use strict";
const endpoint = "/api/lab/action-proof/webauthn";
const scope = { action: "EMAIL_CHANGE", target: "readiness-only@example.test" };
const status = document.getElementById("status");
const register = document.getElementById("register");
const assert = document.getElementById("assert");
const ceremonyTimeoutMs = 120000;
const uploadReserveMs = 20000;
let windowClosesAt = 0;
const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
async function request(path, init, expected, step) {
  let response;
  try { response = await fetch(path, { credentials: "same-origin", ...init }); }
  catch (error) { throw new Error("Không nhận được phản hồi khi " + step + ": " + error.message); }
  if (response.status !== expected) throw new Error("Lab từ chối khi " + step + " (HTTP " + response.status + ").");
  if (expected !== 200) return null;
  try { return await response.json(); }
  catch (error) { throw new Error("Không đọc được phản hồi khi " + step + ": " + error.message); }
}
async function post(path, body, expected = 200, step = "gửi yêu cầu") {
  const csrf = await request("/api/auth/csrf", {}, 200, "chuẩn bị " + step);
  return request(path, { method: "POST",
    headers: { "Content-Type": "application/json", "X-XSRF-TOKEN": csrf.token }, body: JSON.stringify(body) }, expected, step);
}
async function availableWindow() {
  const started = performance.now();
  const state = await request(endpoint + "/status", {}, 200, "kiểm tra thời gian lab");
  windowClosesAt = started + (Number.isFinite(state.remaining_ms) ? state.remaining_ms : 0);
  requireWindow();
  return state;
}
function requireWindow() {
  if (windowClosesAt - performance.now() < ceremonyTimeoutMs + uploadReserveMs)
    throw new Error("Không đủ thời gian lab để mở hộp thoại và gửi kết quả. Không mở thêm hộp thoại; cần điều phối phiên mới.");
}
async function login() {
  // Deliberately public credentials of the disposable isolated test fixture.
  await post("/api/auth/login", { username: "__USERNAME__", password: "__PASSWORD__" }, 200, "đăng nhập tài khoản lab");
}
function options(document) {
  const o = JSON.parse(document).publicKey;
  o.challenge = decode(o.challenge);
  if (o.user) o.user.id = decode(o.user.id);
  for (const item of o.excludeCredentials || []) item.id = decode(item.id);
  for (const item of o.allowCredentials || []) item.id = decode(item.id);
  o.timeout = ceremonyTimeoutMs;
  return o;
}
function credential(c) {
  const r = c.response;
  const response = { clientDataJSON: encode(r.clientDataJSON) };
  for (const key of ["attestationObject", "authenticatorData", "signature", "userHandle"])
    if (r[key]) response[key] = encode(r[key]);
  if (r.getTransports) response.transports = r.getTransports();
  return JSON.stringify({ id: c.id, rawId: encode(c.rawId), type: c.type, response,
    clientExtensionResults: c.getClientExtensionResults(), authenticatorAttachment: c.authenticatorAttachment });
}
function waitForRestart(attempts = 60) {
  setTimeout(async () => {
    try {
      const response = await fetch("/lab/webauthn", { credentials: "same-origin", cache: "no-store" });
      if (response.ok && (await response.text()).includes('data-lifecycle-phase="RESTORED_ASSERTION"')) {
        location.reload();
        return;
      }
    } catch (error) { /* The original server is expected to be stopped between phases. */ }
    if (attempts > 1) waitForRestart(attempts - 1);
    else status.textContent = "Khóa đã được lưu. Chưa thấy server mở lại; không đăng ký thêm, báo trạng thái này trong chat.";
  }, 2000);
}
register.onclick = async () => {
  register.disabled = true;
  let deviceStarted = false;
  let step = "kiểm tra thời gian lab";
  try {
    const state = await availableWindow();
    if (state.registration_ceremony_started) throw new Error("Lượt đăng ký đã dùng. Không tạo thêm credential.");
    status.textContent = "Hãy xác nhận đăng ký trên điện thoại hoặc khóa riêng.";
    step = "nhận yêu cầu đăng ký";
    const o = await post(endpoint + "/register/options", {}, 200, step);
    requireWindow();
    step = "xác nhận trên thiết bị";
    deviceStarted = true;
    const c = await navigator.credentials.create({ publicKey: options(o.public_key_json) });
    step = "gửi kết quả đăng ký về server";
    status.textContent = "Thiết bị đã trả kết quả. Đang gửi về server lab…";
    const enrollment = await post(endpoint + "/register/finish", { reference: o.reference, credential_json: credential(c) }, 200, step);
    if (enrollment.lifecycle_phase === "ENROLL_ONLY") {
      status.textContent = "Đã lưu public key được kiểm chứng. Chờ server khởi động lại; không đăng ký thêm khóa.";
      try { await post(endpoint + "/complete", {}, 200, "đóng phiên đăng ký"); }
      catch (error) { status.textContent += " Chưa nhận được xác nhận đóng phiên: " + error.message; }
      waitForRestart();
      return;
    }
    step = "mở phiên sau đăng ký";
    await login(); // A new real JWT session after enrollment, required by the server.
    assert.disabled = false;
    status.textContent = "Đã đăng ký khóa. Bấm xác nhận thao tác giả để kiểm chữ ký trong phiên mới.";
  } catch (error) {
    status.textContent = "Chưa hoàn tất đăng ký ở bước " + step + ": " + error.name + ". " + error.message +
      (deviceStarted ? " Khóa có thể đã được lưu trên thiết bị. Không đăng ký lại." : "");
  }
};
assert.onclick = async () => {
  assert.disabled = true;
  try {
    await availableWindow();
    status.textContent = "Xác nhận EMAIL_CHANGE giả tới readiness-only@example.test trên thiết bị riêng.";
    const o = await post(endpoint + "/assert/options", scope, 200, "nhận yêu cầu xác nhận");
    requireWindow();
    const c = await navigator.credentials.get({ publicKey: options(o.public_key_json) });
    const body = { ...scope, reference: o.reference, credential_json: credential(c) };
    const result = await post(endpoint + "/assert/finish", body, 200, "gửi chữ ký về server");
    await post(endpoint + "/assert/finish", body, 400, "kiểm tra chống replay"); // Real HTTP replay must be refused.
    await post(endpoint + "/complete", {}, 200, "kết thúc lab");
    status.textContent = "Chữ ký và chống replay đã được kiểm. " +
      (result.backup_eligible ? "Khóa có khả năng đồng bộ; tính độc lập chưa được xác nhận." : "Đây là bằng chứng dùng khóa, chưa chứng minh danh tính hoặc ý định.");
  } catch (error) { status.textContent = "Chưa hoàn tất xác nhận: " + error.name + ". " + error.message; }
};
(async () => {
  try {
    if (!window.isSecureContext || !window.PublicKeyCredential || location.hostname !== "localhost")
      throw new Error("Cần trình duyệt hỗ trợ WebAuthn tại localhost.");
    await login();
    const state = await availableWindow();
    if (state.registered_credentials === 1 && state.successful_assertions < 2) {
      assert.disabled = false;
      status.textContent = state.lifecycle_phase === "RESTORED_ASSERTION"
        ? "Server mới đã nạp public key. Bấm xác nhận thao tác giả bằng cùng khóa trên iPhone."
        : "Khóa đã đăng ký. Bấm xác nhận thao tác giả bằng khóa đó.";
    } else if (!state.registration_ceremony_started) {
      register.disabled = false;
      status.textContent = "Sẵn sàng; lab còn khoảng " + Math.floor(state.remaining_ms / 1000) + " giây. Bấm đăng ký rồi xác nhận trên thiết bị riêng.";
    } else {
      status.textContent = "Lượt đăng ký đã được sử dụng. Không tạo thêm credential; cần kiểm tra kết quả lab.";
    }
  } catch (error) { status.textContent = "Chưa sẵn sàng: " + error.message; }
})();
