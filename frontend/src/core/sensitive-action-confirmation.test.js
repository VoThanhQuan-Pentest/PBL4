import { describe, expect, it, vi } from 'vitest';
import { confirmSensitiveAction } from './sensitive-action-confirmation.js';

describe('sensitive action confirmation', () => {
    it('shows a bounded hold countdown without replaying the mutation and requires a fresh challenge', async () => {
        vi.useFakeTimers();
        const input = { disabled: false };
        const note = { setAttribute: vi.fn(), textContent: '' };
        vi.stubGlobal('document', { createElement: () => note });
        const form = { querySelectorAll: () => [input], append: vi.fn() };
        const overlay = new EventTarget();
        const held = Object.assign(new Error('Held'), { code: 'ACTION_TEMPORARILY_HELD', retryAfterSeconds: 2, decisionId: 'pld-test' });
        const apiRequest = vi.fn().mockResolvedValueOnce({ required: true, contact_available: true }).mockRejectedValueOnce(held);
        try {
            await expect(confirmSensitiveAction({ apiRequest, operation: 'PASSWORD_CHANGE', payload: {}, form, overlay,
                isAuthCurrent: () => true })).rejects.toBe(held);
            expect(input.disabled).toBe(true);expect(note.textContent).toContain('2 giây');
            await vi.advanceTimersByTimeAsync(2000);
            expect(input.disabled).toBe(false);expect(note.textContent).toContain('OTP mới');
            expect(apiRequest).toHaveBeenCalledTimes(2);
        } finally { vi.useRealTimers();vi.unstubAllGlobals(); }
    });
    const challenge = { id: 'server-id', operation: 'EMAIL_CHANGE', expires_at: '2099-01-01T00:00:00Z' };
    it('keeps the legacy path only when the server policy does not require confirmation', async () => {
        const apiRequest = vi.fn().mockResolvedValue({ required: false });
        const result = await confirmSensitiveAction({ apiRequest, isAuthCurrent: () => true });
        expect(result).toBeNull(); expect(apiRequest).toHaveBeenCalledTimes(1);
    });
    it('prepares immutable payload and executes only after a separately entered current-mailbox code', async () => {
        const apiRequest = vi.fn().mockResolvedValueOnce({ required: true, contact_available: true })
            .mockResolvedValueOnce(challenge).mockResolvedValueOnce({ id: challenge.id, operation: 'EMAIL_CHANGE', state: 'COMMITTED' });
        const release = vi.fn();
        const result = await confirmSensitiveAction({ apiRequest, isAuthCurrent: () => true, operation: 'EMAIL_CHANGE',
            payload: { email: 'new@example.test', otp_code: '111111' },
            requestCode: () => ({ code: Promise.resolve('222222'), release }) });
        expect(apiRequest.mock.calls[2][1].body).toEqual({ confirmation_code: '222222', destination_otp_code: '111111',
            request_id: expect.stringMatching(/^[0-9a-f-]{36}$/) });
        expect(result.state).toBe('COMMITTED'); expect(release).toHaveBeenCalledOnce();
    });
    it('does not execute a prepared action if the authenticated account changes while waiting', async () => {
        let current = true;
        const apiRequest = vi.fn().mockResolvedValueOnce({ required: true, contact_available: true })
            .mockResolvedValueOnce({ ...challenge, operation: 'PASSWORD_CHANGE' });
        const release = vi.fn();
        await expect(confirmSensitiveAction({ apiRequest, isAuthCurrent: () => current, operation: 'PASSWORD_CHANGE', payload: {},
            requestCode: () => { current = false; return { code: Promise.resolve('123456'), release }; }
        })).rejects.toThrow('Phiên đăng nhập');
        expect(apiRequest).toHaveBeenCalledTimes(2); expect(release).toHaveBeenCalledOnce();
    });
    it('does not prepare when verified contact is unavailable and never treats destination proof as account confirmation', async () => {
        const apiRequest = vi.fn().mockResolvedValue({ required: true, contact_available: false });
        await expect(confirmSensitiveAction({ apiRequest, isAuthCurrent: () => true, operation: 'EMAIL_CHANGE',
            payload: { otp_code: '123456' } })).rejects.toThrow('chưa có bằng chứng');
        expect(apiRequest).toHaveBeenCalledTimes(1);
    });
    it('retries a code typo on the same operation without resending or resetting the challenge', async () => {
        const invalid = Object.assign(new Error('Mã sai'), { code: 'ACTION_CONFIRMATION_CODE_INVALID' });
        const apiRequest = vi.fn().mockResolvedValueOnce({ required: true, contact_available: true })
            .mockResolvedValueOnce({ ...challenge, operation: 'PASSWORD_CHANGE' }).mockRejectedValueOnce(invalid)
            .mockResolvedValueOnce({ id: challenge.id, operation: 'PASSWORD_CHANGE', state: 'COMMITTED' });
        const release = vi.fn();
        const requestCode = vi.fn().mockReturnValueOnce({ code: Promise.resolve('111111'), release })
            .mockReturnValueOnce({ code: Promise.resolve('222222'), release });
        await confirmSensitiveAction({ apiRequest, isAuthCurrent: () => true,
            operation: 'PASSWORD_CHANGE', payload: {}, requestCode });
        expect(apiRequest.mock.calls.filter(([path]) => path === '/profile/action-confirmations')).toHaveLength(1);
        expect(apiRequest.mock.calls[2][0]).toBe(apiRequest.mock.calls[3][0]);
        expect(apiRequest.mock.calls[2][1].body.request_id).not.toBe(apiRequest.mock.calls[3][1].body.request_id);
        expect(release).toHaveBeenCalledTimes(2);
    });
    it('cancels a late preparation response after the overlay closes', async () => {
        const overlay = new EventTarget();
        let releasePreparation;
        const prepared = new Promise(resolve => { releasePreparation = resolve; });
        const apiRequest = vi.fn().mockResolvedValueOnce({ required: true, contact_available: true })
            .mockReturnValueOnce(prepared);
        const requestCode = vi.fn();
        const result = confirmSensitiveAction({ apiRequest, isAuthCurrent: () => true,
            operation: 'EMAIL_CHANGE', payload: {}, overlay, requestCode });
        const rejected = expect(result).rejects.toThrow('Đã hủy');
        await vi.waitFor(() => expect(apiRequest).toHaveBeenCalledTimes(2));
        overlay.dispatchEvent(new Event('overlay:close'));
        releasePreparation(challenge);
        await rejected;
        expect(requestCode).not.toHaveBeenCalled();
    });
    it('rejects a challenge for a different operation before asking for or consuming a proof', async () => {
        const apiRequest = vi.fn().mockResolvedValueOnce({ required: true, contact_available: true }).mockResolvedValueOnce(challenge);
        const requestCode = vi.fn();
        await expect(confirmSensitiveAction({ apiRequest, isAuthCurrent: () => true,
            operation: 'PASSWORD_CHANGE', payload: {}, requestCode })).rejects.toThrow('yêu cầu xác nhận hợp lệ');
        expect(requestCode).not.toHaveBeenCalled();
        expect(apiRequest).toHaveBeenCalledTimes(2);
    });
});
