// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { confirmSensitiveAction } from './sensitive-action-confirmation.js';

const challenge = { id: 'challenge/one', operation: 'PASSWORD_CHANGE',
    expires_at: '2099-01-01T00:00:00Z', confirmation_email_masked: 'o***@example.test' };
const flush = async () => { for (let i = 0; i < 12; i += 1) await Promise.resolve(); };

function fixture(operation = 'PASSWORD_CHANGE') {
    document.body.innerHTML = '<div id="overlay"><form><input id="original"><button disabled>Locked</button></form></div>';
    const form = document.querySelector('form');
    const overlay = document.querySelector('#overlay');
    const apiRequest = vi.fn().mockResolvedValueOnce({ required: true, contact_available: true })
        .mockResolvedValueOnce({ ...challenge, operation })
        .mockResolvedValue({ id: challenge.id, operation, state: 'COMMITTED' });
    const options = { form, overlay, apiRequest, operation, payload: { email: 'destination@example.test' },
        isAuthCurrent: () => true };
    return { form, overlay, apiRequest, options };
}

describe('current-mailbox confirmation in the real DOM', () => {
    beforeEach(() => { vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] }); });
    afterEach(() => { vi.useRealTimers(); document.body.replaceChildren(); });

    it.each(['PASSWORD_CHANGE', 'EMAIL_CHANGE'])('validates and submits %s with Enter, then restores controls', async operation => {
        const { form, apiRequest, options } = fixture(operation);
        const pending = confirmSensitiveAction(options);
        await flush();
        expect(document.activeElement.getAttribute('aria-label')).toContain('6 số');
        expect(form.querySelector('#original').disabled).toBe(true);
        const submit = new Event('submit', { bubbles: true, cancelable: true });
        form.dispatchEvent(submit);
        expect(submit.defaultPrevented).toBe(true);
        const input = form.querySelector('section input');
        const confirm = form.querySelector('section button');
        input.value = '12x'; confirm.click();
        expect(form.querySelector('[role="alert"]').textContent).toContain('6 chữ số');
        expect(apiRequest).toHaveBeenCalledTimes(2);
        input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', cancelable: true }));
        input.value = ' 123456 ';
        input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', cancelable: true }));
        expect(input.disabled).toBe(true);
        expect((await pending).state).toBe('COMMITTED');
        expect(apiRequest.mock.calls[2][0]).toContain('challenge%2Fone/execute');
        expect(apiRequest.mock.calls[2][1].body.confirmation_code).toBe('123456');
        expect(form.querySelector('section')).toBeNull();
        expect(input.value).toBe('');
        expect(form.querySelector('#original').disabled).toBe(false);
        expect(form.querySelector('button').disabled).toBe(true);
        expect(vi.getTimerCount()).toBe(0);
        const after = new Event('submit', { cancelable: true });
        form.dispatchEvent(after);
        expect(after.defaultPrevented).toBe(false);
    });

    it.each(['button', 'overlay'])('cancels by %s without executing or leaving listeners', async method => {
        const { form, overlay, apiRequest, options } = fixture();
        const pending = confirmSensitiveAction(options);
        const rejected = expect(pending).rejects.toThrow('Đã hủy');
        await flush();
        if (method === 'button') form.querySelectorAll('section button')[1].click();
        else overlay.dispatchEvent(new Event('overlay:close'));
        await rejected;
        expect(apiRequest).toHaveBeenCalledTimes(2);
        expect(form.querySelector('section')).toBeNull();
        expect(form.querySelector('#original').disabled).toBe(false);
        expect(vi.getTimerCount()).toBe(0);
        overlay.dispatchEvent(new Event('overlay:close'));
    });

    it('expires after the bounded timer and cleans up without sending a mutation', async () => {
        const { form, apiRequest, options } = fixture();
        const pending = confirmSensitiveAction(options);
        const rejected = expect(pending).rejects.toThrow('hết hạn');
        await flush();
        await vi.advanceTimersByTimeAsync(300000);
        await rejected;
        expect(form.querySelector('section')).toBeNull();
        expect(apiRequest).toHaveBeenCalledTimes(2);
        expect(vi.getTimerCount()).toBe(0);
    });

    it('shows the server error and accepts another code on the same challenge', async () => {
        const { form, apiRequest, options } = fixture();
        apiRequest.mockReset().mockResolvedValueOnce({ required: true, contact_available: true })
            .mockResolvedValueOnce(challenge)
            .mockRejectedValueOnce(Object.assign(new Error('Wrong code'), { code: 'ACTION_CONFIRMATION_CODE_INVALID' }))
            .mockResolvedValueOnce({ id: challenge.id, operation: challenge.operation, state: 'COMMITTED' });
        const pending = confirmSensitiveAction(options);
        await flush();
        form.querySelector('section input').value = '111111'; form.querySelector('section button').click();
        await flush();
        expect(form.querySelector('[role="alert"]').textContent).toBe('Wrong code');
        form.querySelector('section input').value = '222222'; form.querySelector('section button').click();
        await pending;
        expect(apiRequest).toHaveBeenCalledTimes(4);
        expect(apiRequest.mock.calls[2][0]).toBe(apiRequest.mock.calls[3][0]);
        expect(form.querySelectorAll('section')).toHaveLength(0);
    });

    it('refuses execution when the session changes while the code form is open', async () => {
        const { form, apiRequest, options } = fixture();
        let current = true; options.isAuthCurrent = () => current;
        const pending = confirmSensitiveAction(options);
        const rejected = expect(pending).rejects.toThrow('Phiên đăng nhập');
        await flush(); current = false;
        form.querySelector('section input').value = '123456'; form.querySelector('section button').click();
        await rejected;
        expect(apiRequest).toHaveBeenCalledTimes(2);
        expect(form.querySelector('section')).toBeNull();
    });

    it('does not accept a mismatched committed result', async () => {
        const { form, apiRequest, options } = fixture();
        apiRequest.mockReset().mockResolvedValueOnce({ required: true, contact_available: true })
            .mockResolvedValueOnce(challenge).mockResolvedValueOnce({ id: 'other', state: 'COMMITTED' });
        const pending = confirmSensitiveAction(options);
        const rejected = expect(pending).rejects.toThrow('Chưa xác minh');
        await flush();
        form.querySelector('section input').value = '123456'; form.querySelector('section button').click();
        await rejected;
        expect(form.querySelector('section')).toBeNull();
    });

    it.each([null, {}, { required: 'yes' }])('rejects malformed policy %j before preparing an action', async policy => {
        const apiRequest = vi.fn().mockResolvedValue(policy);
        await expect(confirmSensitiveAction({ apiRequest, isAuthCurrent: () => true })).rejects.toThrow('chính sách');
        expect(apiRequest).toHaveBeenCalledTimes(1);
    });

    it('restores the previous control states when a bounded hold overlay closes', async () => {
        const { form, overlay, apiRequest, options } = fixture();
        apiRequest.mockReset().mockRejectedValue(Object.assign(new Error('Held'), {
            code: 'ACTION_TEMPORARILY_HELD', retryAfterSeconds: 'invalid' }));
        await expect(confirmSensitiveAction(options)).rejects.toThrow('Held');
        expect(form.querySelector('[role="alert"]').textContent).toContain('600 giây');
        expect(form.querySelector('#original').disabled).toBe(true);
        overlay.dispatchEvent(new Event('overlay:close'));
        expect(form.querySelector('#original').disabled).toBe(false);
        expect(form.querySelector('button').disabled).toBe(true);
        expect(vi.getTimerCount()).toBe(0);
        expect(apiRequest).toHaveBeenCalledTimes(1);
    });
});
