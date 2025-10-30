#!/usr/bin/env node
const { SimplePool, nip04, getPublicKey, finalizeEvent, generateSecretKey } = require('nostr-tools');

async function quickTest() {
    console.log('🧪 Testing bunker response...\n');
    
    // Use existing bunker URL from earlier test
    const BUNKER_URL = 'bunker://3fac8ff7a1c02424514541c347b70f230ab4ae761d9d557fe459bb9889dc7cf0?relay=wss://relay.damus.io&secret=B0jG9mmguyUbSCdj4wgiVGSWDwRIq5TEb92akkCo0X8kbOHx';
    
    const bunkerUrl = new URL(BUNKER_URL);
    const remotePubkey = bunkerUrl.hostname || bunkerUrl.pathname.replace('//', '');
    const relay = bunkerUrl.searchParams.get('relay');
    
    console.log('Testing with bunker:', remotePubkey);
    console.log('Relay:', relay);
    
    const pool = new SimplePool();
    const localSecretKey = generateSecretKey();
    const localPubkey = getPublicKey(localSecretKey);
    
    const testEvent = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Quick bunker test at ' + new Date().toISOString()
    };
    
    const request = {
        id: Math.random().toString(36).substring(7),
        method: 'sign_event',
        params: [JSON.stringify(testEvent)]
    };
    
    const encryptedRequest = await nip04.encrypt(localSecretKey, remotePubkey, JSON.stringify(request));
    const requestEvent = finalizeEvent({
        kind: 24133,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', remotePubkey]],
        content: encryptedRequest,
        pubkey: localPubkey
    }, localSecretKey);
    
    console.log('\n📤 Sending NIP-46 request...');
    await pool.publish([relay], requestEvent);
    console.log('✅ Published, waiting for response...\n');
    
    const timeout = setTimeout(() => {
        console.log('❌ TIMEOUT - No response after 10 seconds');
        pool.close([relay]);
        process.exit(1);
    }, 10000);
    
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
                console.log('✅ GOT RESPONSE!');
                console.log('Response:', JSON.stringify(resp, null, 2));
                
                if (resp.result) {
                    console.log('\n🎉 BUNKER IS WORKING!');
                } else if (resp.error) {
                    console.log('\n❌ Error:', resp.error);
                }
                
                sub.close();
                pool.close([relay]);
                process.exit(resp.result ? 0 : 1);
            }
        }
    });
}

quickTest().catch(err => {
    console.error('❌ Error:', err.message);
    process.exit(1);
});
