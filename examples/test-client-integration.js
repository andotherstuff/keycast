// ABOUTME: Integration test for keycast-test-bundled.html client functionality
// ABOUTME: Tests registration, authentication, NIP-46 connection, and event signing

import { chromium } from 'playwright';

async function testKeycastClient() {
    console.log('Starting Keycast client integration test...\n');

    const browser = await chromium.launch({ headless: false });
    const context = await browser.newContext();
    const page = await context.newPage();

    // Enable console logging
    page.on('console', msg => {
        const type = msg.type();
        const text = msg.text();
        if (type === 'error' || text.includes('ERROR')) {
            console.log(`[BROWSER ERROR] ${text}`);
        } else if (text.includes('[NIP46]') || text.includes('bunker')) {
            console.log(`[BROWSER] ${text}`);
        }
    });

    try {
        // Navigate to test page
        console.log('1. Loading test page...');
        await page.goto('http://localhost:8000/keycast-test-bundled.html');
        await page.waitForLoadState('networkidle');
        console.log('✓ Page loaded\n');

        // Check initial configuration
        console.log('2. Checking configuration...');
        const domain = await page.inputValue('#domain');
        const apiBase = await page.inputValue('#apiBase');
        console.log(`   Domain: ${domain}`);
        console.log(`   API Base: ${apiBase}`);
        console.log('✓ Configuration verified\n');

        // Generate unique email for this test
        const timestamp = Date.now();
        const testEmail = `test-${timestamp}@example.com`;
        const testPassword = 'testpass123';

        console.log('3. Testing registration...');
        console.log(`   Email: ${testEmail}`);
        await page.fill('#email', testEmail);
        await page.fill('#password', testPassword);

        // Click register and wait for result
        await page.click('#registerBtn');
        console.log('   Clicked Register button');

        // Wait for status to change
        await page.waitForFunction(
            () => {
                const status = document.getElementById('status').textContent;
                return status !== 'connecting' && status !== 'disconnected';
            },
            { timeout: 30000 }
        );

        const status = await page.textContent('#status');
        console.log(`   Status: ${status}`);

        if (status === 'error') {
            const output = await page.textContent('#authOutput');
            console.log(`   Error output: ${output}`);
            throw new Error('Registration failed');
        }

        if (status !== 'connected') {
            throw new Error(`Expected status 'connected', got '${status}'`);
        }

        console.log('✓ Registration successful\n');

        // Check if we got a pubkey
        console.log('4. Testing get public key...');
        await page.click('#getPubkeyBtn');

        // Wait for pubkey output
        await page.waitForFunction(
            () => document.getElementById('pubkeyOutput').textContent.length > 50,
            { timeout: 10000 }
        );

        const pubkeyOutput = await page.textContent('#pubkeyOutput');
        const pubkeyMatch = pubkeyOutput.match(/Public Key: ([a-f0-9]{64})/);

        if (!pubkeyMatch) {
            throw new Error('Failed to get public key');
        }

        const pubkey = pubkeyMatch[1];
        console.log(`   Pubkey: ${pubkey.substring(0, 16)}...`);
        console.log('✓ Public key retrieved\n');

        // Test event signing
        console.log('5. Testing event signing...');
        await page.fill('#eventContent', 'Test message from integration test');
        await page.click('#signBtn');

        // Wait for signed event
        await page.waitForFunction(
            () => document.getElementById('signOutput').textContent.includes('Signed event:'),
            { timeout: 30000 }
        );

        const signOutput = await page.textContent('#signOutput');
        console.log('   Sign output received');

        if (signOutput.includes('ERROR')) {
            throw new Error('Signing failed: ' + signOutput);
        }

        // Verify the signed event has required fields
        const eventMatch = signOutput.match(/"id":\s*"([a-f0-9]{64})"/);
        const sigMatch = signOutput.match(/"sig":\s*"([a-f0-9]{128})"/);

        if (!eventMatch || !sigMatch) {
            throw new Error('Signed event missing id or sig');
        }

        console.log(`   Event ID: ${eventMatch[1].substring(0, 16)}...`);
        console.log(`   Signature: ${sigMatch[1].substring(0, 16)}...`);
        console.log('✓ Event signed successfully\n');

        // Test NIP-44 encryption
        console.log('6. Testing NIP-44 encryption...');
        await page.fill('#targetPubkey', pubkey);
        await page.fill('#plaintext', 'Secret test message');
        await page.click('#encryptBtn');

        // Wait for encryption result
        await page.waitForFunction(
            () => document.getElementById('encryptOutput').textContent.includes('Ciphertext:'),
            { timeout: 10000 }
        );

        const encryptOutput = await page.textContent('#encryptOutput');

        if (encryptOutput.includes('ERROR')) {
            throw new Error('Encryption failed: ' + encryptOutput);
        }

        console.log('✓ Encryption successful\n');

        // Test decryption
        console.log('7. Testing NIP-44 decryption...');
        await page.click('#decryptBtn');

        // Wait for decryption result
        await page.waitForFunction(
            () => document.getElementById('encryptOutput').textContent.includes('Decrypted:'),
            { timeout: 10000 }
        );

        const decryptOutput = await page.textContent('#encryptOutput');

        if (!decryptOutput.includes('Decrypted: Secret test message')) {
            throw new Error('Decryption result incorrect: ' + decryptOutput);
        }

        console.log('✓ Decryption successful\n');

        console.log('========================================');
        console.log('✓ ALL TESTS PASSED');
        console.log('========================================\n');

    } catch (error) {
        console.error('\n========================================');
        console.error('✗ TEST FAILED');
        console.error('========================================');
        console.error(error);
        throw error;
    } finally {
        await browser.close();
    }
}

testKeycastClient().catch(err => {
    console.error('Test suite failed:', err);
    process.exit(1);
});
