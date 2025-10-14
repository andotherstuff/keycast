// ABOUTME: Playwright end-to-end test for keycast-login registration flow
// ABOUTME: Tests registration, bunker URL retrieval, and NIP-46 connection

const { test, expect } = require('@playwright/test');

test.describe('Keycast Registration Flow', () => {
  test('should complete full registration flow', async ({ page }) => {
    // Set a longer timeout for this test since it involves network requests to relays
    test.setTimeout(60000);

    // Navigate to test page
    await page.goto('http://localhost:8000/keycast-test-bundled.html');

    // Fill in registration details
    const timestamp = Date.now();
    const testEmail = `test-${timestamp}@example.com`;
    const testPassword = 'testpass123';

    await page.fill('#email', testEmail);
    await page.fill('#password', testPassword);

    // Click register button
    await page.click('#registerBtn');

    // Wait for status to change from initial
    await page.waitForFunction(
      () => {
        const status = document.querySelector('#status').textContent;
        return status !== 'disconnected';
      },
      { timeout: 10000 }
    );

    // Check console for errors
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Wait for connection (up to 30 seconds for relay communication)
    let finalStatus;
    try {
      await page.waitForFunction(
        () => {
          const status = document.querySelector('#status').textContent;
          return status === 'connected' || status === 'error';
        },
        { timeout: 30000 }
      );

      finalStatus = await page.locator('#status').textContent();
    } catch (e) {
      // Timeout - get current status
      finalStatus = await page.locator('#status').textContent();
      console.log('Timed out waiting for connection. Current status:', finalStatus);

      // Get console logs
      const consoleLogs = [];
      page.on('console', msg => consoleLogs.push(msg.text()));
      console.log('Console logs:', consoleLogs);

      throw new Error(`Registration flow timed out. Final status: ${finalStatus}`);
    }

    // Log any console errors
    if (consoleErrors.length > 0) {
      console.log('Console errors detected:', consoleErrors);
    }

    // Check final status
    expect(finalStatus).toBe('connected');

    console.log('✅ Registration flow completed successfully');
    console.log('Email:', testEmail);
    console.log('Final status:', finalStatus);
  });

  test('should handle login flow for existing user', async ({ page }) => {
    test.setTimeout(60000);

    // First register a user
    await page.goto('http://localhost:8000/keycast-test-bundled.html');

    const timestamp = Date.now();
    const testEmail = `test-login-${timestamp}@example.com`;
    const testPassword = 'testpass123';

    await page.fill('#email', testEmail);
    await page.fill('#password', testPassword);
    await page.click('#registerBtn');

    // Wait for registration to complete
    await page.waitForFunction(
      () => document.querySelector('#status').textContent === 'connected',
      { timeout: 30000 }
    );

    // Reload page to simulate coming back
    await page.reload();

    // Now login with same credentials
    await page.fill('#email', testEmail);
    await page.fill('#password', testPassword);
    await page.click('#loginBtn');

    // Wait for login to complete
    await page.waitForFunction(
      () => document.querySelector('#status').textContent === 'connected',
      { timeout: 30000 }
    );

    console.log('✅ Login flow completed successfully');
    console.log('Email:', testEmail);
  });
});
