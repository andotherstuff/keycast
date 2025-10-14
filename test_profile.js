// ABOUTME: Playwright test for profile management flow
// ABOUTME: Tests registration, login, and profile update with username

const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Log console messages
  page.on('console', msg => console.log('BROWSER:', msg.text()));
  page.on('pageerror', err => console.error('PAGE ERROR:', err));

  try {
    const testEmail = `test${Date.now()}@example.com`;
    const testPassword = 'testpass123';
    const testUsername = `testuser${Date.now()}`;

    console.log('\n=== Testing Profile Management Flow ===\n');

    // Step 1: Register
    console.log('1. Navigating to /register...');
    await page.goto('http://localhost:3000/register');
    await page.waitForSelector('#email');

    console.log(`2. Registering with email: ${testEmail}`);
    await page.fill('#email', testEmail);
    await page.fill('#password', testPassword);
    await page.fill('#confirmPassword', testPassword);
    await page.click('button[type="submit"]');

    // Wait for redirect to dashboard
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    await page.waitForLoadState('networkidle');
    console.log('✓ Registration successful, redirected to dashboard');

    // Step 2: Navigate to profile
    console.log('\n3. Navigating to /profile...');
    await page.goto('http://localhost:3000/profile');
    await page.waitForSelector('#profileForm');

    // Step 3: Fill profile form
    console.log('4. Filling profile form...');
    await page.fill('#username', testUsername);
    await page.fill('#name', 'Test User');
    await page.fill('#about', 'This is a test profile created by Playwright');
    await page.fill('#website', 'https://example.com');

    console.log('5. Submitting profile...');
    await page.click('button[type="submit"]');

    // Wait for success message
    await page.waitForSelector('.status.success', { timeout: 5000 });
    const successMessage = await page.textContent('.status.success');
    console.log(`✓ Profile saved: ${successMessage}`);

    // Step 4: Verify profile was saved by reloading
    console.log('\n6. Reloading page to verify profile persists...');
    await page.reload();
    await page.waitForSelector('#profileForm');

    const savedUsername = await page.inputValue('#username');
    const savedName = await page.inputValue('#name');
    const savedAbout = await page.inputValue('#about');

    console.log(`✓ Username: ${savedUsername}`);
    console.log(`✓ Name: ${savedName}`);
    console.log(`✓ About: ${savedAbout}`);

    if (savedUsername === testUsername && savedName === 'Test User') {
      console.log('\n✅ Profile management test PASSED!');
    } else {
      console.log('\n❌ Profile management test FAILED - data mismatch');
    }

    // Step 5: Test NIP-05 discovery
    console.log('\n7. Testing NIP-05 discovery endpoint...');
    const response = await page.request.get(`http://localhost:3000/.well-known/nostr.json?name=${testUsername}`);
    const nip05Data = await response.json();
    console.log('NIP-05 response:', JSON.stringify(nip05Data, null, 2));

    if (nip05Data.names && nip05Data.names[testUsername]) {
      console.log(`✓ NIP-05 discovery working: ${testUsername} -> ${nip05Data.names[testUsername]}`);
    } else {
      console.log('⚠ NIP-05 discovery not returning username mapping');
    }

    console.log('\n=== Test Complete ===\n');

  } catch (error) {
    console.error('\n❌ Test failed with error:', error.message);
    await page.screenshot({ path: 'test-error.png' });
    console.log('Screenshot saved to test-error.png');
  } finally {
    await browser.close();
  }
})();
