#!/usr/bin/env node

// Test script to verify NIP-46 bunker signing
const { SimplePool, nip04, nip19, getPublicKey, getEventHash, finalizeEvent, generateSecretKey } = require('nostr-tools');

const BUNKER_URL = 'bunker://65f431a440f8a2513462ed2e1ce95f5cb4a9c415f6ddc3a56013dd705d695c32?relay=wss://relay.damus.io&secret=PzKiqEmUUHyZrv6wJlwyUgMI6Yx42oJctiUtRVyRsfBZ0eFu';
const CONTENT_RELAY = 'wss://relay3.openvine.co';  // Now test with our relay

async function testBunkerSigning() {
    console.log('🔑 Testing Bunker Signing...\n');

    // Parse bunker URL
    const bunkerUrl = new URL(BUNKER_URL);
    const remotePubkey = bunkerUrl.hostname || bunkerUrl.pathname.replace('//', '');
    const relay = bunkerUrl.searchParams.get('relay');
    const secret = bunkerUrl.searchParams.get('secret');

    console.log('Bunker Details:');
    console.log('- Remote Pubkey:', remotePubkey);
    console.log('- NIP-46 Relay:', relay);
    console.log('- Content Relay:', CONTENT_RELAY);
    console.log('- Secret:', secret.substring(0, 10) + '...\n');

    // Generate local keypair for the client
    const localSecretKey = generateSecretKey();
    const localPubkey = getPublicKey(localSecretKey);

    console.log('Local Client Pubkey:', localPubkey, '\n');

    // Create pool and connect to relay
    const pool = new SimplePool();

    console.log('Connecting to relays...');

    // Create a test event to sign (WITHOUT pubkey - bunker will add it)
    const testEvent = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Testing NIP-46 bunker signing from unified service!'
    };

    console.log('\nTest Event to Sign (unsigned):');
    console.log(JSON.stringify(testEvent, null, 2));

    // Create NIP-46 request (event must be stringified!)
    const request = {
        id: Math.random().toString(36).substring(7),
        method: 'sign_event',
        params: [JSON.stringify(testEvent)]
    };

    console.log('\nNIP-46 Request:');
    console.log(JSON.stringify(request, null, 2));

    try {
        // Encrypt the request
        const encryptedRequest = await nip04.encrypt(localSecretKey, remotePubkey, JSON.stringify(request));

        // Create the request event
        const requestEvent = {
            kind: 24133,
            created_at: Math.floor(Date.now() / 1000),
            tags: [['p', remotePubkey]],
            content: encryptedRequest,
            pubkey: localPubkey
        };

        const signedRequestEvent = finalizeEvent(requestEvent, localSecretKey);

        console.log('\n📤 Publishing NIP-46 request event...');

        // Publish to relay and wait for response
        const pub = pool.publish([relay], signedRequestEvent);

        console.log('✅ Request published, waiting for response...\n');

        // Listen for response
        const sub = pool.subscribeMany(
            [relay],
            [{
                kinds: [24133],
                '#p': [localPubkey],
                since: Math.floor(Date.now() / 1000) - 5
            }],
            {
                onevent(event) {
                    console.log('📥 Received response event:', event.id);

                    // Decrypt response
                    nip04.decrypt(localSecretKey, remotePubkey, event.content).then(async decrypted => {
                        console.log('\n✅ Decrypted Response:');
                        const response = JSON.parse(decrypted);
                        console.log(JSON.stringify(response, null, 2));

                        if (response.result) {
                            console.log('\n🎉 SUCCESS! Bunker signed the event!');
                            // Parse the signed event (it's returned as a string)
                            const signedEvent = typeof response.result === 'string'
                                ? JSON.parse(response.result)
                                : response.result;
                            console.log('Signed Event:', JSON.stringify(signedEvent, null, 2));

                            // Now publish the signed event to our content relay
                            console.log('\n📤 Publishing signed event to', CONTENT_RELAY, '...');
                            try {
                                const pubs = await Promise.all(
                                    pool.publish([CONTENT_RELAY], signedEvent)
                                );
                                console.log('✅ Event published to content relay!');
                                console.log('Publish results:', pubs);

                                // Wait a bit for the relay to process the event
                                console.log('⏳ Waiting 2 seconds for relay to process...');
                                await new Promise(resolve => setTimeout(resolve, 2000));

                                // Verify it appears on the relay
                                console.log('\n🔍 Verifying event appears on relay...');
                                const verifySub = pool.subscribeMany(
                                    [CONTENT_RELAY],
                                    [{
                                        ids: [signedEvent.id],
                                        limit: 1
                                    }],
                                    {
                                        onevent(verifiedEvent) {
                                            console.log('✅ VERIFIED! Event found on relay:', verifiedEvent.id);
                                            console.log('\n🎉 COMPLETE END-TO-END TEST SUCCESS!');
                                            console.log('- Bunker signed the event via NIP-46');
                                            console.log('- Event published to', CONTENT_RELAY);
                                            console.log('- Event verified on relay');

                                            verifySub.close();
                                            sub.close();
                                            pool.close([relay, CONTENT_RELAY]);
                                            process.exit(0);
                                        },
                                        oneose() {
                                            console.log('❌ Event not found on relay after 5 seconds');
                                            verifySub.close();
                                            sub.close();
                                            pool.close([relay, CONTENT_RELAY]);
                                            process.exit(1);
                                        }
                                    }
                                );

                                // Timeout for verification
                                setTimeout(() => {
                                    console.log('⏱️  Verification timeout');
                                    verifySub.close();
                                    sub.close();
                                    pool.close([relay, CONTENT_RELAY]);
                                    process.exit(1);
                                }, 5000);

                            } catch (publishErr) {
                                console.error('❌ Failed to publish to content relay:', publishErr);
                                sub.close();
                                pool.close([relay, CONTENT_RELAY]);
                                process.exit(1);
                            }
                        } else if (response.error) {
                            console.log('\n❌ Error:', response.error);
                            sub.close();
                            pool.close([relay]);
                            process.exit(1);
                        }
                    }).catch(err => {
                        console.error('❌ Decryption error:', err);
                        sub.close();
                        pool.close([relay]);
                        process.exit(1);
                    });
                },
                oneose() {
                    console.log('End of stored events');
                }
            }
        );

        // Timeout after 10 seconds
        setTimeout(() => {
            console.log('\n⏱️  Timeout - no response received');
            sub.close();
            pool.close([relay]);
            process.exit(1);
        }, 10000);

    } catch (error) {
        console.error('❌ Error:', error);
        pool.close([relay]);
        process.exit(1);
    }
}

testBunkerSigning().catch(console.error);
