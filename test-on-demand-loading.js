#!/usr/bin/env node
const { SimplePool, nip04, getPublicKey, finalizeEvent, generateSecretKey, verifyEvent } = require('nostr-tools');

const API_URL = 'https://keycast-unified-4uaiddnawq-uc.a.run.app';
const CONTENT_RELAY = 'wss://relay3.openvine.co';

async function testOnDemandLoading() {
    console.log('🧪 Testing On-Demand Authorization Loading\n');
    
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
    console.log('✅ Registered! User pubkey:', registerData.pubkey);
    
    // Step 2: Get bunker URL
    console.log('\n2️⃣  Getting bunker URL...');
    const bunkerResp = await fetch(`${API_URL}/api/user/bunker`, {
        headers: { 'Authorization': `Bearer ${registerData.token}` }
    });
    const bunkerData = await bunkerResp.json();
    const bunkerUrl = new URL(bunkerData.bunker_url);
    const remotePubkey = bunkerUrl.hostname || bunkerUrl.pathname.replace('//', '');
    const relay = bunkerUrl.searchParams.get('relay');
    const secret = bunkerUrl.searchParams.get('secret');
    
    console.log('✅ Got bunker URL');
    console.log('  Remote pubkey:', remotePubkey);
    console.log('  NIP-46 relay:', relay);
    
    // Step 3: IMMEDIATELY try to sign (on-demand loading test!)
    console.log('\n3️⃣  IMMEDIATELY sending NIP-46 signing request (no reload wait!)...');
    
    const pool = new SimplePool();
    const localSecretKey = generateSecretKey();
    const localPubkey = getPublicKey(localSecretKey);
    
    const testEvent = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Testing on-demand loading - no reload needed!'
    };
    
    const request = {
        id: Math.random().toString(36).substring(7),
        method: 'sign_event',
        params: [JSON.stringify(testEvent)]
    };
    
    const encryptedRequest = await nip04.encrypt(localSecretKey, remotePubkey, JSON.stringify(request));
    
    const requestEvent = {
        kind: 24133,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', remotePubkey]],
        content: encryptedRequest,
        pubkey: localPubkey
    };
    
    const signedRequestEvent = finalizeEvent(requestEvent, localSecretKey);
    
    await pool.publish([relay], signedRequestEvent);
    console.log('✅ Request published, waiting for response...');
    
    // Wait for response
    const response = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timeout')), 10000);
        
        const sub = pool.subscribeMany([relay], [{
            kinds: [24133],
            '#p': [localPubkey],
            since: Math.floor(Date.now() / 1000) - 5
        }], {
            async onevent(event) {
                const decrypted = await nip04.decrypt(localSecretKey, remotePubkey, event.content);
                const resp = JSON.parse(decrypted);
                if (resp.id === request.id) {
                    clearTimeout(timeout);
                    sub.close();
                    resolve(resp);
                }
            }
        });
    });
    
    if (response.result) {
        const signedEvent = JSON.parse(response.result);
        console.log('\n🎉 SUCCESS! Event signed via on-demand loading!');
        console.log('Event ID:', signedEvent.id);
        
        // Publish to content relay
        await pool.publish([CONTENT_RELAY], signedEvent);
        console.log('✅ Published to', CONTENT_RELAY);
        
        // Verify signature
        const isValid = verifyEvent(signedEvent);
        console.log('🔐 Signature valid:', isValid);
        
        pool.close([relay, CONTENT_RELAY]);
        
        if (isValid) {
            console.log('\n✨ COMPLETE SUCCESS - On-demand loading works perfectly!');
            process.exit(0);
        }
    } else {
        console.log('❌ Error:', response.error);
        pool.close([relay]);
        process.exit(1);
    }
}

testOnDemandLoading().catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
});
