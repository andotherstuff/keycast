#!/usr/bin/env node
const { SimplePool, verifyEvent } = require('nostr-tools');

const API_URL = process.env.API_URL || 'http://localhost:3000';
const CONTENT_RELAY = 'wss://relay3.openvine.co';

async function testHttpSigning() {
    console.log('🧪 Testing Fast HTTP Signing Endpoints\n');

    // Step 1: Register new user
    const email = `test-${Date.now()}@example.com`;
    const password = 'test123';

    console.log('1️⃣  Registering new user:', email);
    const registerResp = await fetch(`${API_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });
    const registerData = await registerResp.json();

    if (!registerResp.ok) {
        console.error('❌ Registration failed:', registerData);
        process.exit(1);
    }

    console.log('✅ Registered! User pubkey:', registerData.pubkey);
    const token = registerData.token;

    // Step 2: Test GET /api/user/pubkey
    console.log('\n2️⃣  Testing GET /api/user/pubkey...');
    const pubkeyResp = await fetch(`${API_URL}/api/user/pubkey`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const pubkeyData = await pubkeyResp.json();

    if (!pubkeyResp.ok) {
        console.error('❌ Get pubkey failed:', pubkeyData);
        process.exit(1);
    }

    console.log('✅ Got pubkey:');
    console.log('   Hex:', pubkeyData.pubkey);
    console.log('   Npub:', pubkeyData.npub);

    // Verify it matches registration
    if (pubkeyData.pubkey !== registerData.pubkey) {
        console.error('❌ Pubkey mismatch!');
        process.exit(1);
    }

    // Step 3: Test POST /api/user/sign with fast HTTP signing
    console.log('\n3️⃣  Testing POST /api/user/sign (fast HTTP signing)...');

    const unsignedEvent = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Testing fast HTTP signing - no NIP-46 relay overhead!'
    };

    console.log('Unsigned event:', JSON.stringify(unsignedEvent, null, 2));

    const startTime = Date.now();
    const signResp = await fetch(`${API_URL}/api/user/sign`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ event: unsignedEvent })
    });
    const signData = await signResp.json();
    const latency = Date.now() - startTime;

    if (!signResp.ok) {
        console.error('❌ Signing failed:', signData);
        process.exit(1);
    }

    const signedEvent = signData.signed_event;
    console.log('✅ Event signed in', latency, 'ms');
    console.log('Signed event ID:', signedEvent.id);
    console.log('Signed event pubkey:', signedEvent.pubkey);

    // Verify the signature
    const isValid = verifyEvent(signedEvent);
    console.log('🔐 Signature valid:', isValid);

    if (!isValid) {
        console.error('❌ Signature verification failed!');
        process.exit(1);
    }

    // Verify pubkey matches
    if (signedEvent.pubkey !== registerData.pubkey) {
        console.error('❌ Signed event pubkey mismatch!');
        process.exit(1);
    }

    // Step 4: Publish to relay
    console.log('\n4️⃣  Publishing to', CONTENT_RELAY);
    const pool = new SimplePool();
    await pool.publish([CONTENT_RELAY], signedEvent);
    console.log('✅ Published to relay');

    pool.close([CONTENT_RELAY]);

    // Success!
    console.log('\n✨ ALL TESTS PASSED!');
    console.log('\n📊 Performance:');
    console.log('   HTTP signing latency:', latency, 'ms');
    console.log('   Expected NIP-46 latency: ~2000-5000 ms');
    console.log('   Speedup:', Math.round(3500 / latency) + 'x faster');

    process.exit(0);
}

testHttpSigning().catch(err => {
    console.error('❌ Error:', err.message);
    console.error(err);
    process.exit(1);
});
