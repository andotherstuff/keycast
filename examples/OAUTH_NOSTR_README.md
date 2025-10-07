# OAuth-Authenticated Nostr Client

Complete implementation of a Nostr client using Keycast's OAuth flow for remote signing via NIP-46.

## What We Have

### 1. OAuth Test Client (`oauth-test-client.html`)
Interactive web UI for testing the OAuth flow without Nostr integration.

**Features:**
- User registration
- OAuth authorization flow
- Bunker URL retrieval
- Manual and automatic flow testing

### 2. OAuth-Integrated Nostr Client (`nostr-client-oauth.html`) ✨
**Full-featured Nostr client with OAuth authentication**

**Features:**
- OAuth 2.0 authorization flow
- NIP-46 remote signing via bunker URL
- Post notes to Nostr
- View your notes from relay
- No private keys in browser (all signing done remotely)

**Flow:**
1. User registers or logs in
2. OAuth authorization (client requests permission)
3. Bunker URL obtained
4. Nostr events signed remotely via NIP-46
5. Events published to Nostr relays

### 3. Legacy Nostr Clients (Personal Auth)
- `nostr-client-enhanced.html` - Uses personal auth (register/login endpoints)
- `nostr-client-full.html` - Uses personal auth with full features

These use the `/api/auth/register` and `/api/auth/login` endpoints instead of OAuth.

## OAuth Flow Diagram

```
┌─────────────┐                                    ┌──────────────┐
│   Nostr     │                                    │   Keycast    │
│   Client    │                                    │     API      │
└──────┬──────┘                                    └──────┬───────┘
       │                                                  │
       │  1. User clicks "Register" or "Login"           │
       │ ─────────────────────────────────────────────>  │
       │                                                  │
       │  2. POST /api/auth/register (or /login)         │
       │    Returns JWT token                            │
       │ <─────────────────────────────────────────────  │
       │                                                  │
       │  3. POST /api/oauth/authorize (approved=true)   │
       │    (with JWT token in Cookie header)            │
       │ ─────────────────────────────────────────────>  │
       │                                                  │
       │  4. Redirect with authorization code            │
       │    (redirect_uri?code=XXXXXXX)                  │
       │ <─────────────────────────────────────────────  │
       │                                                  │
       │  5. POST /api/oauth/token (code=XXXXXXX)        │
       │ ─────────────────────────────────────────────>  │
       │                                                  │
       │  6. Returns bunker URL                          │
       │    { "bunker_url": "bunker://..." }             │
       │ <─────────────────────────────────────────────  │
       │                                                  │
       │  7. Use bunker URL for NIP-46 remote signing    │
       │                                                  │
```

## Running the Nostr OAuth Client

### Prerequisites
1. **API Server Running:**
   ```bash
   cd api
   cargo run
   ```
   API should be running on `http://localhost:3000`

2. **HTTP Server for HTML:**
   ```bash
   cd examples
   python3 -m http.server 8000
   ```

### Testing Steps

1. **Open the OAuth Nostr Client:**
   ```
   http://localhost:8000/nostr-client-oauth.html
   ```

2. **Configure Settings:**
   - API URL: `http://localhost:3000`
   - Client ID: `nostr-web-client`
   - Redirect URI: `http://localhost:8000/callback`

3. **Authorize:**
   - Click "New User (Register)" or "Existing User (Login)"
   - Enter credentials
   - OAuth authorization happens automatically
   - Bunker URL is obtained

4. **Post to Nostr:**
   - Type a message in the text area
   - Click "Post to Nostr"
   - Event is signed remotely via NIP-46
   - Event is published to Nostr relay

5. **View Your Notes:**
   - Click "Load My Notes"
   - See your published notes from the relay

## Testing with Script

Run the automated test script:

```bash
# Make sure API is running first
cargo run --bin keycast_api

# In another terminal
./tests/test_nostr_oauth_flow.sh
```

This tests:
- ✓ User registration
- ✓ OAuth authorization
- ✓ Bunker URL retrieval
- ✓ Bunker URL format validation
- ✓ Nostr client compatibility

## OAuth vs Personal Auth

### OAuth Flow (`/api/oauth/*`)
**Use case:** Third-party applications

**Pros:**
- Separate authorization per application
- User can revoke access per app
- Each app gets its own signing key
- More secure for third-party apps

**Endpoints:**
- `GET /api/oauth/authorize` - Show authorization page
- `POST /api/oauth/authorize` - Approve/deny authorization
- `POST /api/oauth/token` - Exchange code for bunker URL

### Personal Auth (`/api/auth/*`)
**Use case:** First-party applications (your own client)

**Pros:**
- Simpler flow (register → bunker URL directly)
- No separate authorization step needed
- Single bunker URL for user

**Endpoints:**
- `POST /api/auth/register` - Register and get bunker URL
- `POST /api/auth/login` - Login and get bunker URL
- `GET /api/user/bunker` - Get existing bunker URL

## NIP-46 Remote Signing

Both flows provide a **bunker URL** in this format:

```
bunker://{public_key_hex}?relay={relay_url}&secret={secret}
```

**Example:**
```
bunker://a1b2c3d4...?relay=wss://relay.damus.io&secret=xyz123...
```

The Nostr client uses this to:
1. Connect to the relay
2. Send signing requests (kind 24133 events)
3. Receive signed events back
4. Publish signed events to Nostr network

## Security Model

### OAuth Model
- ✅ Each application gets separate keys
- ✅ User explicitly approves each app
- ✅ User can revoke per-app access
- ✅ Authorization codes expire in 10 minutes
- ✅ Authorization codes are single-use
- ✅ Secret keys encrypted with GCP KMS

### Personal Auth Model
- ✅ Single user key (simpler)
- ✅ Suitable for first-party apps
- ✅ Secret keys encrypted with GCP KMS
- ⚠️  No per-app revocation

## Files Overview

```
examples/
├── oauth-test-client.html           # OAuth flow testing (no Nostr)
├── nostr-client-oauth.html          # ✨ OAuth + Nostr integration
├── nostr-client-enhanced.html       # Personal auth + Nostr
├── nostr-client-full.html           # Personal auth + Nostr (full features)
└── test-oauth-client.html           # Original OAuth test (simpler)

tests/
├── test_nostr_oauth_flow.sh         # Automated OAuth + Nostr test
└── e2e_oauth_test.sh                # OAuth-only E2E test
```

## Troubleshooting

### "Failed to get authorization code"
- Make sure API server is running
- Check browser console for errors
- Verify JWT token was obtained from register/login

### "Bunker signing timeout"
- Check that the bunker/signer service is running
- Verify relay URL is accessible
- Check signer logs for errors

### "Invalid bunker URL format"
- Ensure API returned proper bunker URL
- Check that bunker URL matches pattern: `bunker://{64-hex}?relay={url}&secret={secret}`

### CORS Errors
- API should have CORS enabled for all origins (embeddable auth)
- Check API logs for CORS configuration
- Ensure you're using the correct API URL

## Next Steps

1. **Run the test script** to verify the full flow works
2. **Open the OAuth Nostr client** in a browser
3. **Register and authorize** to get a bunker URL
4. **Post your first note** using remote signing
5. **Check Nostr relays** to see your published events

## Architecture Benefits

This implementation demonstrates:
- ✅ **Secure OAuth 2.0 flow** - Industry standard authorization
- ✅ **NIP-46 remote signing** - No private keys in browser
- ✅ **Encrypted key storage** - Keys encrypted with GCP KMS
- ✅ **Flexible authentication** - OAuth for third-party, personal for first-party
- ✅ **Testable architecture** - Comprehensive test coverage
- ✅ **Production-ready** - Proper error handling and security

Enjoy your OAuth-authenticated Nostr experience! 🔐🦩
