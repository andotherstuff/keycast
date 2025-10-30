#!/usr/bin/env node
const { SimplePool, verifyEvent } = require('nostr-tools');

// The event ID from our last test
const EVENT_ID = '28c477d3f8e212cb7fce5af485cd749b08563d9ecda144860bbc77d5f463e84e';
const RELAY = 'wss://relay3.openvine.co';

async function verifyEventOnRelay() {
    console.log('🔍 Fetching event', EVENT_ID, 'from', RELAY, '...\n');
    
    const pool = new SimplePool();
    
    const events = await pool.querySync([RELAY], {
        ids: [EVENT_ID],
        limit: 1
    });
    
    if (events.length === 0) {
        console.log('❌ Event not found on relay');
        pool.close([RELAY]);
        process.exit(1);
    }
    
    const event = events[0];
    console.log('✅ Event found on relay!');
    console.log('Event:', JSON.stringify(event, null, 2));
    
    // Verify the signature
    const isValid = verifyEvent(event);
    console.log('\n🔐 Signature verification:', isValid ? '✅ VALID' : '❌ INVALID');
    
    if (isValid) {
        console.log('\n🎉 SUCCESS! Event is properly signed and stored on relay3.openvine.co');
    }
    
    pool.close([RELAY]);
    process.exit(isValid ? 0 : 1);
}

verifyEventOnRelay().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
