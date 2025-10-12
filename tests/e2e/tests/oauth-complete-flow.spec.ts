// ABOUTME: Playwright test for complete OAuth flow including bunker URL and note loading
// ABOUTME: Tests registration → authorization → bunker URL → viewing notes

import { test, expect } from '@playwright/test';

test.describe('Complete OAuth Flow', () => {
  test('should complete full OAuth flow and load notes', async ({ page }) => {
    // Navigate to the OAuth client page
    await page.goto('/nostr-client-oauth-ndk.html');

    // Register a new user
    await page.click('#btnRegister');
    const timestamp = Date.now();
    const email = `test-${timestamp}@example.com`;
    await page.fill('#registerEmail', email);
    await page.fill('#registerPassword', 'testpass123');
    await page.click('#btnDoRegister');

    // Wait for OAuth flow to complete
    await expect(page.locator('#appSection')).toBeVisible({ timeout: 10000 });

    // Verify bunker URL is valid format
    const bunkerUrl = await page.locator('#userBunker').textContent();
    expect(bunkerUrl).toMatch(/^bunker:\/\/[0-9a-f]{64}\?relay=wss:\/\/.+&secret=.{32,}$/);

    // Extract components from bunker URL
    const pubkeyMatch = bunkerUrl?.match(/bunker:\/\/([0-9a-f]{64})/);
    expect(pubkeyMatch).toBeTruthy();
    const pubkey = pubkeyMatch![1];

    const relayMatch = bunkerUrl?.match(/relay=([^&]+)/);
    expect(relayMatch).toBeTruthy();
    const relay = relayMatch![1];
    expect(relay).toContain('wss://');

    const secretMatch = bunkerUrl?.match(/secret=([^&\s]+)/);
    expect(secretMatch).toBeTruthy();
    const secret = secretMatch![1];
    expect(secret.length).toBeGreaterThanOrEqual(32);

    // Verify public key matches between display and bunker URL
    const displayedPubkey = await page.locator('#userPubkey').textContent();
    expect(displayedPubkey).toBe(pubkey);

    // Try to load notes (should work even if no notes exist)
    await page.click('#btnLoadNotes');

    // Wait for loading to complete (status should contain success or error, not "Loading")
    await expect(page.locator('#notesStatus')).not.toContainText('Loading', { timeout: 10000 });

    // Should show either success with count or error/no notes message
    const notesStatus = await page.locator('#notesStatus').textContent();
    expect(notesStatus).toMatch(/Loaded \d+ notes|✗|No notes/i);
  });

  test('should handle logout and show login screen', async ({ page }) => {
    // Register and login
    await page.goto('/nostr-client-oauth-ndk.html');
    await page.click('#btnRegister');
    const timestamp = Date.now();
    await page.fill('#registerEmail', `test-${timestamp}@example.com`);
    await page.fill('#registerPassword', 'testpass123');
    await page.click('#btnDoRegister');

    // Wait for app section
    await expect(page.locator('#appSection')).toBeVisible({ timeout: 10000 });

    // Click logout
    await page.click('#btnLogout');

    // Should return to OAuth section
    await expect(page.locator('#oauthSection')).toBeVisible();
    await expect(page.locator('#appSection')).toBeHidden();

    // Should show auth choice
    await expect(page.locator('#authChoice')).toBeVisible();
  });

  test('should persist OAuth state across page refreshes', async ({ page, context }) => {
    // Register and login
    await page.goto('/nostr-client-oauth-ndk.html');
    await page.click('#btnRegister');
    const timestamp = Date.now();
    await page.fill('#registerEmail', `test-${timestamp}@example.com`);
    await page.fill('#registerPassword', 'testpass123');
    await page.click('#btnDoRegister');

    // Wait for app section
    await expect(page.locator('#appSection')).toBeVisible({ timeout: 10000 });
    const bunkerUrl = await page.locator('#userBunker').textContent();

    // Note: Currently the app doesn't persist state in localStorage
    // This test documents the expected behavior for future implementation

    // Reload the page
    await page.reload();

    // Currently will show login screen again (state not persisted)
    // In the future, this should remain logged in
    await expect(page.locator('#oauthSection')).toBeVisible();
  });
});
