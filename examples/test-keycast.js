// ABOUTME: Playwright test script for Keycast provider authentication and signing
// ABOUTME: Tests register/login flow, bunker connection, event signing, and encryption

const { chromium } = require('playwright');

async function testKeycast() {
  console.log('🚀 Starting Keycast provider test...\n');

  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Listen to console logs
  page.on('console', msg => {
    const type = msg.type();
    const text = msg.text();
    if (type === 'error') {
      console.log(`❌ Browser error: ${text}`);
    } else if (text.includes('[') || text.includes('ERROR')) {
      console.log(`   ${text}`);
    }
  });

  try {
    // Navigate to test page
    console.log('📄 Loading test page...');
    await page.goto('http://localhost:8000/keycast-test-bundled.html');
    await page.waitForLoadState('networkidle');
    console.log('✓ Page loaded\n');

    // Set unique email with timestamp
    const uniqueEmail = `test-${Date.now()}@example.com`;
    await page.fill('#email', uniqueEmail);
    console.log(`Using email: ${uniqueEmail}\n`);

    // Test 1: Authentication
    console.log('🔐 Testing authentication...');
    await page.click('#authBtn');

    // Wait for authentication to complete
    await page.waitForFunction(() => {
      const status = document.getElementById('status');
      return status.textContent === 'connected' || status.textContent === 'error';
    }, { timeout: 15000 });

    const status = await page.locator('#status').textContent();
    console.log(`   Status: ${status}`);

    const authOutput = await page.locator('#authOutput').textContent();
    console.log(`   Output:\n${authOutput.split('\n').map(l => '   ' + l).join('\n')}`);

    if (status === 'error') {
      console.log('\n❌ Authentication failed');
      await browser.close();
      return;
    }
    console.log('✓ Authentication successful\n');

    // Test 2: Get Public Key
    console.log('🔑 Testing getPublicKey...');
    await page.click('#getPubkeyBtn');
    await page.waitForTimeout(2000);

    const pubkeyOutput = await page.locator('#pubkeyOutput').textContent();
    console.log(`   Output:\n${pubkeyOutput.split('\n').map(l => '   ' + l).join('\n')}`);

    const pubkeyMatch = pubkeyOutput.match(/Public Key: ([a-f0-9]{64})/);
    if (pubkeyMatch) {
      console.log(`✓ Got pubkey: ${pubkeyMatch[1].substring(0, 16)}...\n`);
    } else {
      console.log('❌ Failed to get pubkey\n');
    }

    // Test 3: Sign Event
    console.log('✍️  Testing signEvent via NIP-46...');
    await page.click('#signBtn');

    // Wait longer for NIP-46 relay communication
    await page.waitForTimeout(5000);

    const signOutput = await page.locator('#signOutput').textContent();
    console.log(`   Output:\n${signOutput.split('\n').map(l => '   ' + l).join('\n')}`);

    if (signOutput.includes('Signed event:')) {
      console.log('✓ Event signed successfully\n');
    } else if (signOutput.includes('ERROR')) {
      console.log('❌ Signing failed\n');
    } else {
      console.log('⏳ Signing in progress (may need more time)\n');
    }

    // Test 4: Encryption
    console.log('🔒 Testing NIP-44 encryption...');
    await page.click('#encryptBtn');
    await page.waitForTimeout(5000);

    const encryptOutput = await page.locator('#encryptOutput').textContent();
    console.log(`   Output:\n${encryptOutput.split('\n').map(l => '   ' + l).join('\n')}`);

    if (encryptOutput.includes('Ciphertext:')) {
      console.log('✓ Encryption successful\n');

      // Test decryption
      console.log('🔓 Testing NIP-44 decryption...');
      await page.click('#decryptBtn');
      await page.waitForTimeout(5000);

      const decryptOutput = await page.locator('#encryptOutput').textContent();
      if (decryptOutput.includes('Decrypted:')) {
        console.log('✓ Decryption successful\n');
      }
    }

    console.log('\n✅ All tests completed!');
    console.log('\nKeeping browser open for 10 seconds for inspection...');
    await page.waitForTimeout(10000);

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
  } finally {
    await browser.close();
  }
}

testKeycast().catch(console.error);
