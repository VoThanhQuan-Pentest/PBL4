import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');

// Test the shipped input definitions with native keyboard insertion, which
// applies HTML maxlength in UTF-16 units. Backend/JS code-point validation
// remains authoritative; an input must not silently truncate a valid secret.
for (const id of ['register-password', 'edit-email-password']) {
  test(`${id} preserves supplementary Unicode characters during input`, async ({ page }) => {
    const tag = html.match(new RegExp(`<input\\b[^>]*id="${id}"[^>]*>`))?.[0];
    expect(tag).toBeTruthy();
    await page.setContent(`<label for="${id}">Password</label>${tag}`);
    const input = page.locator(`#${id}`);
    for (const value of ['a'.repeat(128), '😀'.repeat(128), 'a'.repeat(64) + '😀'.repeat(64)]) {
      await input.fill('');
      await input.focus();
      await page.keyboard.insertText(value);
      await expect(input).toHaveValue(value);
    }
  });
}
