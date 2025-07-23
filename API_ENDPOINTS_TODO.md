# API Endpoints Implementation TODO

## Current Status
✅ = Implemented
⚠️ = Partially Implemented  
❌ = Not Implemented

## Authentication Endpoints
- ✅ `POST /api/auth/register` - Register with email/password
- ✅ `POST /api/auth/login` - Login with email/password
- ✅ `POST /api/auth/logout` - Logout and invalidate session
- ✅ `GET /api/auth/me` - Get current user from session
- ⚠️ `POST /api/auth/passkey/register` - Register passkey (returns "Not implemented")
- ⚠️ `POST /api/auth/passkey/login` - Login with passkey (returns "Not implemented")
- ⚠️ `GET /api/auth/oauth/:provider` - OAuth init (returns "Not implemented")
- ⚠️ `GET /api/auth/oauth/:provider/callback` - OAuth callback (returns "Not implemented")

## User Management Endpoints (ALL MISSING)
- ❌ `GET /api/users/profile` - Get full user profile with auth methods
- ❌ `PUT /api/users/profile` - Update profile (name, NIP-05, picture)
- ❌ `DELETE /api/users/account` - Delete user account and all data
- ❌ `GET /api/users/auth-methods` - List all auth methods
- ❌ `POST /api/users/auth-methods` - Add new auth method
- ❌ `DELETE /api/users/auth-methods/:id` - Remove auth method

## Key Management Endpoints (ALL MISSING)
- ❌ `GET /api/users/keys` - List user's keys
- ❌ `POST /api/users/keys` - Create new key
- ❌ `GET /api/users/keys/:id` - Get key details
- ❌ `PUT /api/users/keys/:id` - Update key (name, status)
- ❌ `DELETE /api/users/keys/:id` - Delete key
- ❌ `POST /api/users/keys/:id/rotate` - Rotate key
- ❌ `POST /api/users/keys/:id/set-primary` - Set as primary key
- ❌ `POST /api/users/keys/import` - Import existing key

## Policy Management Endpoints (ALL MISSING)
- ❌ `GET /api/users/policies` - List user's policies
- ❌ `POST /api/users/policies` - Create new policy
- ❌ `GET /api/users/policies/:id` - Get policy with permissions
- ❌ `PUT /api/users/policies/:id` - Update policy
- ❌ `DELETE /api/users/policies/:id` - Delete policy
- ❌ `GET /api/users/policies/templates` - Get policy templates
- ❌ `POST /api/users/policies/from-template` - Create from template
- ❌ `GET /api/users/policies/:id/permissions` - List permissions
- ❌ `POST /api/users/policies/:id/permissions` - Add permission
- ❌ `DELETE /api/users/policies/:id/permissions/:permId` - Remove permission

## Application Management Endpoints (ALL MISSING)
- ❌ `GET /api/users/applications` - List connected apps
- ❌ `GET /api/users/applications/:id` - Get app details
- ❌ `DELETE /api/users/applications/:id/revoke` - Revoke all app authorizations
- ❌ `GET /api/applications` - List all known applications
- ❌ `GET /api/applications/:id` - Get public app info
- ❌ `PUT /api/applications/:id/verify` - Mark app as verified (admin)

## Authorization Management Endpoints (ALL MISSING)
- ❌ `GET /api/users/authorizations` - List active authorizations
- ❌ `POST /api/users/authorizations` - Create manual authorization
- ❌ `GET /api/users/authorizations/:id` - Get authorization details
- ❌ `PUT /api/users/authorizations/:id` - Update (extend expiry, change policy)
- ❌ `DELETE /api/users/authorizations/:id` - Revoke authorization
- ❌ `GET /api/users/authorizations/:id/bunker` - Get bunker connection URL
- ❌ `GET /api/users/authorizations/:id/usage` - Get usage statistics
- ❌ `POST /api/users/authorizations/:id/regenerate` - New bunker secret

## Authorization Request Endpoints (ALL MISSING)
- ❌ `GET /api/auth/requests` - List pending authorization requests
- ❌ `GET /api/auth/requests/:id` - Get request details
- ❌ `POST /api/auth/requests/:id/approve` - Approve with params
- ❌ `POST /api/auth/requests/:id/reject` - Reject request
- ❌ `GET /api/auth/connection-attempts` - View recent attempts
- ❌ `POST /api/auth/connection-attempts/:id/block` - Block app domain

## NIP-05 Management Endpoints
- ✅ `GET /.well-known/nostr.json` - NIP-05 discovery
- ⚠️ `POST /api/nip05/claim` - Claim identifier (partial)
- ❌ `GET /api/users/nip05` - Get user's NIP-05 settings
- ❌ `PUT /api/users/nip05` - Update NIP-05 identifier
- ❌ `DELETE /api/users/nip05` - Remove NIP-05
- ❌ `POST /api/nip05/verify-domain` - Verify custom domain
- ❌ `GET /api/nip05/available/:identifier` - Check availability

## Activity & Audit Endpoints (ALL MISSING)
- ❌ `GET /api/users/activity` - Get activity log
- ❌ `GET /api/users/sessions` - List active sessions
- ❌ `DELETE /api/users/sessions/:id` - Revoke specific session
- ❌ `DELETE /api/users/sessions` - Revoke all sessions
- ❌ `GET /api/users/audit-log` - Detailed audit trail

## Admin Endpoints (ALL MISSING)
- ❌ `GET /api/admin/users` - List all users
- ❌ `GET /api/admin/users/:id` - Get user details
- ❌ `PUT /api/admin/users/:id/suspend` - Suspend user
- ❌ `DELETE /api/admin/users/:id` - Delete user
- ❌ `GET /api/admin/stats` - System statistics
- ❌ `GET /api/admin/authorizations` - All authorizations
- ❌ `GET /api/admin/applications` - Manage applications

## WebSocket/SSE Endpoints (ALL MISSING)
- ❌ `WS /api/ws` - WebSocket for real-time updates
- ❌ `SSE /api/events` - Server-sent events alternative
  - Authorization request notifications
  - Key usage alerts
  - Policy violation warnings

## Implementation Priority

### Phase 1 - Core Functionality (MUST HAVE)
1. User keys endpoints (create, list, get)
2. Basic policy endpoints (create, list, templates)
3. Authorization creation endpoint
4. Authorization requests (list, approve, reject)
5. Bunker URL generation

### Phase 2 - Management (SHOULD HAVE)
1. Full key management (rotate, delete, import)
2. Policy permissions management
3. Application listing and revocation
4. Authorization management (update, revoke)
5. Activity logging

### Phase 3 - Enhanced Features (NICE TO HAVE)
1. WebAuthn implementation
2. OAuth provider integration
3. Custom domain NIP-05
4. WebSocket notifications
5. Admin dashboard

## Route Organization

```rust
// api/src/api/http/routes.rs

pub fn routes() -> Router {
    Router::new()
        // Existing
        .nest("/api/auth", auth_routes())
        .nest("/api/teams", team_routes()) // Legacy
        
        // New routes to add
        .nest("/api/users", user_routes())
        .nest("/api/applications", app_routes())
        .nest("/api/nip05", nip05_routes())
        .nest("/api/admin", admin_routes())
        .route("/api/ws", get(websocket_handler))
}

fn user_routes() -> Router {
    Router::new()
        .route("/profile", get(get_profile).put(update_profile))
        .route("/account", delete(delete_account))
        .nest("/keys", key_routes())
        .nest("/policies", policy_routes())
        .nest("/applications", user_app_routes())
        .nest("/authorizations", authorization_routes())
        .route("/activity", get(get_activity))
        .route("/sessions", get(list_sessions).delete(revoke_all_sessions))
}
```

## Request/Response Examples

### Create Key
```json
POST /api/users/keys
{
  "name": "My signing key",
  "key_type": "primary",
  "generate": true
}

Response:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My signing key",
  "public_key": "npub1...",
  "key_type": "primary",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### Approve Authorization Request
```json
POST /api/auth/requests/123/approve
{
  "user_key_id": "550e8400-e29b-41d4-a716-446655440000",
  "policy_id": 1,
  "max_uses": 100,
  "expires_in_hours": 720
}

Response:
{
  "authorization_id": "123",
  "bunker_url": "bunker://pubkey?relay=wss://relay.url&secret=abc123"
}
```

## Middleware Requirements

### Auth Middleware
```rust
async fn require_auth(
    headers: HeaderMap,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract bearer token
    // Validate session
    // Add user to request extensions
}
```

### Rate Limiting
- Per-user limits on key creation
- Per-app limits on authorization requests
- Global limits on expensive operations

### Audit Logging
- Log all state changes
- Track API usage per user
- Monitor suspicious patterns