/** One operation, one server-held payload, one current-mailbox confirmation. No browser storage. */
export async function confirmSensitiveAction(options) {
    let closed = false;
    const markClosed = () => { closed = true; };
    options.overlay?.addEventListener('overlay:close', markClosed);
    try {
        return await confirmPreparedAction({ ...options, isAuthCurrent: () => {
            if (closed) throw new Error('Đã hủy xác nhận. Thao tác chưa được gửi để thực hiện.');
            return options.isAuthCurrent();
        } });
    } catch (error) {
        if (error.code === 'ACTION_TEMPORARILY_HELD') showTemporaryHold(options.form, options.overlay, error);
        throw error;
    } finally {
        options.overlay?.removeEventListener('overlay:close', markClosed);
    }
}

async function confirmPreparedAction({ apiRequest, operation, payload, form, overlay,
    isAuthCurrent, requestCode = requestInlineCode }) {
    const requireCurrent = () => {
        if (!isAuthCurrent()) throw new Error('Phiên đăng nhập đã thay đổi. Vui lòng thử lại.');
    };
    requireCurrent();
    const policy = await apiRequest('/profile/action-confirmations/policy');
    requireCurrent();
    if (!policy || typeof policy.required !== 'boolean') throw new Error('Không đọc được chính sách xác nhận thao tác.');
    if (!policy.required) return null;
    if (policy.contact_available !== true) {
        throw new Error('Email hiện tại chưa có bằng chứng xác minh. Chưa thể thực hiện thao tác.');
    }
    const response = await apiRequest('/profile/action-confirmations', {
        method: 'POST',
        body: { operation, [operation === 'EMAIL_CHANGE' ? 'profile' : 'password']: payload }
    });
    requireCurrent();
    const challenge = { id: response?.id, operation: response?.operation, expiresAt: response?.expires_at,
        confirmationEmailMasked: response?.confirmation_email_masked };
    if (!challenge.id || challenge.operation !== operation || !Number.isFinite(Date.parse(challenge.expiresAt))) {
        throw new Error('Không nhận được yêu cầu xác nhận hợp lệ. Thao tác chưa được thực hiện.');
    }
    let previousError = '';
    for (let attempt = 0; attempt < 5; attempt += 1) {
        const confirmation = requestCode({ form, overlay, challenge, previousError,
            target: operation === 'EMAIL_CHANGE' ? payload.email : null });
        try {
            const code = await confirmation.code;
            requireCurrent();
            if (!/^\d{6}$/.test(code)) throw new Error('Mã xác nhận phải gồm 6 chữ số.');
            const result = await apiRequest(`/profile/action-confirmations/${encodeURIComponent(challenge.id)}/execute`, {
                method: 'POST', body: { confirmation_code: code, destination_otp_code: payload.otp_code || '',
                    request_id: crypto.randomUUID() }
            });
            if (result?.state !== 'COMMITTED' || result.id !== challenge.id || result.operation !== operation) {
                throw new Error('Chưa xác minh được kết quả thao tác. Hãy kiểm tra tài khoản trước khi thử lại.');
            }
            return result;
        } catch (error) {
            if (error.code !== 'ACTION_CONFIRMATION_CODE_INVALID' || attempt === 4
                || Date.parse(challenge.expiresAt) <= Date.now() || !isAuthCurrent()) throw error;
            previousError = error.message;
        } finally {
            confirmation.release();
        }
    }
}

/** No automatic mutation retry after a hold; a fresh challenge is required when it ends. */
function showTemporaryHold(form, overlay, error) {
    if (!form || !overlay) return;
    const seconds = Number(error.retryAfterSeconds);
    const until = Date.now() + Math.max(1, Math.min(600, Number.isFinite(seconds) ? seconds : 600)) * 1000;
    const note = document.createElement('p'); note.setAttribute('role', 'alert');
    const controls = [...form.querySelectorAll('input, button, select, textarea')].map(e => [e, e.disabled]);
    controls.forEach(([element]) => { element.disabled = true; });
    form.append(note);
    const finish = () => {
        clearInterval(timer); overlay.removeEventListener('overlay:close', finish);
        controls.forEach(([element, disabled]) => { element.disabled = disabled; });
    };
    const update = () => {
        const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
        note.textContent = left > 0
            ? `Thao tác tạm dừng ${left} giây. OTP vẫn bắt buộc. Có thể liên hệ SOC với mã ${error.decisionId || 'trên thông báo'}.`
            : 'Đã hết thời gian tạm dừng. Hãy gửi lại biểu mẫu để tạo yêu cầu và OTP mới.';
        if (left === 0) finish();
    };
    const timer = setInterval(update, 1000);
    overlay.addEventListener('overlay:close', finish, { once: true }); update();
}

function requestInlineCode({ form, overlay, challenge, target, previousError }) {
    const section = document.createElement('section');
    section.className = 'space-y-3 rounded border p-4';
    section.setAttribute('aria-label', 'Xác nhận thao tác tài khoản');
    const description = document.createElement('p');
    description.textContent = target
        ? `Xác nhận đổi email sang ${target}. Nhập mã gửi tới email hiện tại ${challenge.confirmationEmailMasked}.`
        : `Xác nhận đổi mật khẩu. Nhập mã gửi tới email hiện tại ${challenge.confirmationEmailMasked}.`;
    const input = document.createElement('input');
    input.type = 'text'; input.inputMode = 'numeric'; input.autocomplete = 'one-time-code';
    input.maxLength = 6; input.pattern = '[0-9]{6}'; input.setAttribute('aria-label', 'Mã xác nhận thao tác 6 số');
    input.className = 'w-full rounded border p-2';
    const error = document.createElement('p'); error.setAttribute('role', 'alert');
    error.textContent = previousError || '';
    const confirm = document.createElement('button'); confirm.type = 'button';
    confirm.className = 'rounded bg-blue-600 px-4 py-2 text-white'; confirm.textContent = 'Xác nhận thao tác';
    const cancel = document.createElement('button'); cancel.type = 'button';
    cancel.className = 'rounded border px-4 py-2'; cancel.textContent = 'Hủy';
    const controls = [...form.querySelectorAll('input, button, select, textarea')].map(element => [element, element.disabled]);
    controls.forEach(([element]) => { element.disabled = true; });
    section.append(description, input, error, confirm, cancel); form.append(section);
    let timer; let released = false; let rejectCode;
    const blockSubmit = event => { event.preventDefault(); event.stopImmediatePropagation(); };
    const closed = () => rejectCode(new Error('Đã hủy xác nhận. Thao tác chưa được gửi để thực hiện.'));
    const code = new Promise((resolve, reject) => {
        rejectCode = reject;
        confirm.addEventListener('click', () => {
            if (!/^\d{6}$/.test(input.value.trim())) {
                error.textContent = 'Nhập đúng 6 chữ số trong email xác nhận thao tác.';
                input.focus(); return;
            }
            clearTimeout(timer); confirm.disabled = true; cancel.disabled = true; input.disabled = true;
            overlay.removeEventListener('overlay:close', closed);
            resolve(input.value.trim());
        });
        cancel.addEventListener('click', closed);
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') { event.preventDefault(); confirm.click(); }
        });
        overlay.addEventListener('overlay:close', closed, { once: true });
        timer = setTimeout(() => reject(new Error('Yêu cầu xác nhận đã hết hạn. Hãy tạo yêu cầu mới.')),
            Math.max(0, Math.min(300000, Date.parse(challenge.expiresAt) - Date.now())));
    });
    form.addEventListener('submit', blockSubmit, true); input.focus();
    return { code, release() {
        if (released) return;
        released = true; clearTimeout(timer);
        overlay.removeEventListener('overlay:close', closed);
        form.removeEventListener('submit', blockSubmit, true);
        controls.forEach(([element, disabled]) => { element.disabled = disabled; });
        input.value = ''; section.remove();
    } };
}
