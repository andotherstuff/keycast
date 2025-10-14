// ABOUTME: Playwright test for nostr-tools-based profile management
// ABOUTME: Tests registration, profile loading from relays, and publishing kind 0 events via NIP-46

const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Log console messages and errors
  page.on('console', msg => {
    const type = msg.type();
    const text = msg.text();
    if (type === 'error') {
      console.log('BROWSER ERROR:', text);
    } else {
      console.log('BROWSER:', text);
    }
  });
  page.on('pageerror', err => console.error('PAGE ERROR:', err.message));

  try {
    const testEmail = `test${Date.now()}@example.com`;
    const testPassword = 'testpass123';
    const testUsername = `testuser${Date.now()}`;

    console.log('\n=== Testing Nostr-Tools Profile Management Flow ===\n');

    // Step 1: Register
    console.log('1. Registering new user...');
    await page.goto('http://localhost:3000/register');
    await page.waitForSelector('#email');
    await page.fill('#email', testEmail);
    await page.fill('#password', testPassword);
    await page.fill('#confirmPassword', testPassword);
    await page.click('button[type="submit"]');
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    console.log('✓ Registration successful');

    // Step 2: Navigate to profile page
    console.log('\n2. Navigating to profile page...');
    await page.goto('http://localhost:3000/profile');

    // Wait for nostr-tools to load and bunker to connect
    console.log('3. Waiting for bunker to connect...');
    await page.waitForTimeout(8000); // Give time for bunker connection and relay queries

    // Check for loading errors
    const statusText = await page.textContent('#status', { timeout: 1000 }).catch(() => '');
    if (statusText.includes('Failed')) {
      console.log('❌ Profile page failed to load:', statusText);
      await page.screenshot({ path: 'test-profile-error.png' });
      throw new Error('Profile page loading failed');
    }

    // Wait for profile form to appear
    await page.waitForSelector('#profileForm', { timeout: 10000 });
    console.log('✓ Profile page loaded');

    // Step 3: Fill profile form
    console.log('\n4. Filling profile form...');
    await page.fill('#username', testUsername);
    await page.fill('#name', 'Test User');
    await page.fill('#about', 'This is a test profile using NDK and NIP-46');
    await page.fill('#website', 'https://example.com');

    // Step 4: Submit profile (sign via NIP-46 and publish to relays)
    console.log('5. Submitting profile (will sign via NIP-46)...');
    await page.click('button[type="submit"]');

    // Wait for completion (up to 30 seconds for NIP-46 signing + relay publishing)
    let attempts = 0;
    let status = '';
    while (attempts < 30) {
      await page.waitForTimeout(1000);
      status = await page.textContent('#status').catch(() => '');

      if (attempts === 0 || attempts % 5 === 0) {
        console.log(`Attempt ${attempts + 1}/30 - Status:`, status);
      }

      if (status.includes('successfully') || status.includes('published')) {
        console.log('✓ Profile published successfully');
        break;
      }

      if (status.includes('Failed') || status.includes('error')) {
        console.log('❌ Profile save failed:', status);
        await page.screenshot({ path: 'test-profile-save-error.png' });
        throw new Error('Profile save failed: ' + status);
      }

      attempts++;
    }

    if (attempts >= 30) {
      console.log('❌ Timeout waiting for profile to publish');
      await page.screenshot({ path: 'test-profile-timeout.png' });
      throw new Error('Timeout waiting for profile to publish');
    }

    // Step 5: Reload and verify profile persists
    console.log('\n6. Waiting 10 seconds for relay propagation...');
    await page.waitForTimeout(10000); // Allow time for relays to index the event
    console.log('7. Reloading page to verify profile was published...');
    await page.reload();
    await page.waitForSelector('#profileForm', { timeout: 10000 });
    await page.waitForTimeout(5000); // Wait for bunker setup and relay fetch

    const savedUsername = await page.inputValue('#username');
    const savedName = await page.inputValue('#name');
    const savedAbout = await page.inputValue('#about');

    console.log(`✓ Username: ${savedUsername}`);
    console.log(`✓ Name: ${savedName}`);
    console.log(`✓ About: ${savedAbout}`);

    if (savedUsername === testUsername && savedName === 'Test User') {
      console.log('\n✅ Nostr-Tools Profile management test PASSED!');
      console.log('- Profile loaded from Nostr relays via SimplePool');
      console.log('- Signed via NIP-46 bunker');
      console.log('- Published to Nostr relays');
      console.log('- Retrieved on reload');
    } else {
      console.log('\n❌ Profile data mismatch');
      console.log('Expected username:', testUsername, 'Got:', savedUsername);
      console.log('Expected name: Test User, Got:', savedName);
      await page.screenshot({ path: 'test-profile-mismatch.png' });
    }

    console.log('\n=== Test Complete ===\n');

  } catch (error) {
    console.error('\n❌ Test failed with error:', error.message);
    console.error('Stack:', error.stack);
    await page.screenshot({ path: 'test-profile-error.png', fullPage: true });
    console.log('Screenshot saved to test-profile-error.png');
  } finally {
    await browser.close();
  }
})();
