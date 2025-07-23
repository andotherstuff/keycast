# Keycast Personal Nostr Authentication Service - Implementation Plan

## Executive Summary

This document outlines the comprehensive plan to transform Keycast from a team-based remote signing service into a personal Nostr authentication service. The transformation involves removing team concepts, implementing NIP-05 discovery, creating dynamic app authorization flows, and building a user account system with multiple authentication methods.

## Current Architecture Analysis

### Current System Components (Team-Based)
- **Database Schema**: Team-centric with `teams`, `team_users`, `policies` tied to teams
- **Authentication**: NIP-98 HTTP Auth with allowed pubkey whitelist 
- **Key Management**: Team-owned stored keys with AES-256 encryption
- **Authorization Flow**: Pre-registered apps with team policies
- **UI**: Team management dashboard with user roles (admin/member)
- **Signing**: **COMPLETE NIP-46 implementation** with:
  - Full remote signer daemon (`nostr-connect` crate)
  - Per-authorization signer processes
  - Bunker URL generation
  - Policy-based permission validation
  - All NIP-46 request types supported

### Components to Keep/Modify/Remove

#### **KEEP & ENHANCE**
- Core encryption system (file/AWS KMS key managers)
- **NIP-46 remote signing daemon** (fully functional, just needs adaptation)
- **Signer manager** (process spawning, monitoring, health checks)
- **Bunker URL generation** (already implemented in Authorization type)
- SQLite database with migrations
- Permission system framework (custom permissions)
- Web frontend framework (SvelteKit + Tailwind)
- API framework (Rust + Axum + SQLx)

#### **HEAVILY MODIFY**
- Database schema (remove teams, restructure around users)
- API endpoints (user-centric instead of team-centric)
- Authentication system (multiple auth methods)
- Authorization flow (dynamic instead of pre-registered)
- UI/UX (personal dashboard instead of team management)

#### **REMOVE COMPLETELY**
- Team management functionality
- Team user roles and permissions
- Team-based policies
- All team-related database tables
- Team-related API endpoints (`/teams/*`)
- Team management UI components

## Updated Implementation Strategy Based on Existing NIP-46

### Key Discovery: NIP-46 is Already Complete
After analyzing the codebase, we discovered that Keycast already has a **production-ready NIP-46 implementation**:
- Full remote signer daemon using `nostr-connect` crate
- Per-authorization signer processes with health monitoring
- Bunker URL generation and connection management
- Policy-based permission validation
- Support for all NIP-46 request types

### Revised Approach: Adapt, Don't Rebuild
Instead of reimplementing NIP-46, we need to:
1. **Adapt the authorization model** from team-based to user-based
2. **Add dynamic app discovery** (currently apps must be pre-registered)
3. **Create user-centric UI** for managing personal keys and app authorizations
4. **Simplify the data model** from Team→Key→Authorization to User→Key→App Authorization

## Phase 1: Core Architecture Transformation

### 1.1 Database Schema Migration

#### New Schema Design

```sql
-- ================ USERS (Enhanced) ================
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key CHAR(64) UNIQUE NOT NULL, -- hex
    display_name TEXT,
    email TEXT,
    nip05_identifier TEXT UNIQUE, -- user@domain.com format
    profile_picture_url TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- ================ USER AUTHENTICATION METHODS ================
CREATE TABLE user_auth_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    auth_type TEXT NOT NULL CHECK (auth_type IN ('nip07', 'nip46', 'email_password', 'oauth', 'passkey')),
    auth_data TEXT NOT NULL, -- JSON with method-specific data
    is_primary BOOLEAN DEFAULT FALSE,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- ================ USER KEYS (Personal Keys) ================
CREATE TABLE user_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    name TEXT NOT NULL,
    public_key CHAR(64) NOT NULL, -- hex
    secret_key BLOB NOT NULL, -- encrypted secret key
    key_type TEXT NOT NULL CHECK (key_type IN ('primary', 'app_specific', 'temporary')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- ================ APPLICATIONS (Dynamic Registration) ================
CREATE TABLE applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    description TEXT,
    icon_url TEXT,
    pubkey CHAR(64), -- App's pubkey if available
    metadata TEXT, -- JSON with app metadata
    is_verified BOOLEAN DEFAULT FALSE,
    first_seen_at DATETIME NOT NULL,
    last_used_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- ================ USER POLICIES (Personal Policies) ================
CREATE TABLE user_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    name TEXT NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- ================ AUTHORIZATIONS (App-User-Key) ================
CREATE TABLE authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    application_id INTEGER REFERENCES applications(id),
    user_key_id INTEGER REFERENCES user_keys(id),
    policy_id INTEGER REFERENCES user_policies(id),
    secret TEXT NOT NULL UNIQUE, -- connection secret
    bunker_public_key CHAR(64) NOT NULL, -- hex
    bunker_secret BLOB NOT NULL, -- encrypted bunker secret key
    relays TEXT NOT NULL, -- JSON array of relays
    max_uses INTEGER,
    expires_at DATETIME,
    last_used_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- ================ NIP-05 DOMAINS ================
CREATE TABLE nip05_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    verification_record TEXT, -- DNS/HTTP verification
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
```

#### Migration Strategy
1. **Phase 1a**: Create new tables alongside existing ones
2. **Phase 1b**: Migrate existing user data to new user-centric structure
3. **Phase 1c**: Migrate keys from team ownership to user ownership
4. **Phase 1d**: Drop old team-related tables
5. **Phase 1e**: Add indexes and constraints

### 1.2 Core Type System Updates

#### New Rust Types

```rust
// core/src/types/user.rs - Enhanced
pub struct User {
    pub id: u32,
    pub public_key: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub nip05_identifier: Option<String>,
    pub profile_picture_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// core/src/types/application.rs - New
pub struct Application {
    pub id: u32,
    pub name: String,
    pub domain: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub pubkey: Option<String>,
    pub metadata: serde_json::Value,
    pub is_verified: bool,
    pub first_seen_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// core/src/types/user_key.rs - New
pub struct UserKey {
    pub id: u32,
    pub user_id: u32,
    pub name: String,
    pub public_key: String,
    pub secret_key: Vec<u8>, // encrypted
    pub key_type: UserKeyType,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
pub enum UserKeyType {
    Primary,
    AppSpecific,
    Temporary,
}
```

## Phase 2: NIP-05 Discovery Implementation

### 2.1 NIP-05 Service Components

#### Domain Management System
```rust
// core/src/nip05/mod.rs - New module
pub struct Nip05Service {
    pool: SqlitePool,
    allowed_domains: Vec<String>,
}

impl Nip05Service {
    pub async fn register_identifier(
        &self,
        user_id: u32,
        identifier: String, // user@domain.com
    ) -> Result<(), Nip05Error>;
    
    pub async fn resolve_identifier(
        &self,
        identifier: String,
    ) -> Result<PublicKey, Nip05Error>;
    
    pub async fn generate_well_known_response(
        &self,
        domain: String,
    ) -> Result<Nip05Response, Nip05Error>;
}
```

#### Well-known Endpoint
```rust
// api/src/api/http/nip05.rs - New
pub async fn well_known_nostr(
    Path(domain): Path<String>,
    State(pool): State<SqlitePool>,
) -> Result<Json<Nip05Response>, ApiError> {
    let nip05_service = Nip05Service::new(pool);
    let response = nip05_service.generate_well_known_response(domain).await?;
    Ok(Json(response))
}
```

### 2.2 Dynamic DNS/Domain Integration
- Support for custom domains
- Subdomain allocation (user.keycast.app)
- DNS verification for custom domains
- SSL certificate management

## Phase 3: Dynamic App Authorization Flow (CRITICAL NEW WORK)

### 3.1 Application Discovery & Registration

#### Automatic App Registration
```rust
// core/src/application/mod.rs - New
pub struct ApplicationService {
    pool: SqlitePool,
}

impl ApplicationService {
    pub async fn register_or_update_app(
        &self,
        domain: String,
        app_metadata: AppMetadata,
    ) -> Result<Application, ApplicationError>;
    
    pub async fn verify_app(
        &self,
        app_id: u32,
        verification_method: VerificationMethod,
    ) -> Result<(), ApplicationError>;
}
```

#### Authorization Request Flow (NEW - Does Not Exist)
1. **App Connection Request**: App requests authorization via NIP-46
2. **Dynamic App Discovery**: System automatically creates app record
3. **Pending Authorization**: Create authorization in pending state
4. **User Notification**: Alert user of pending authorization request
5. **User Consent Flow**: User sees app request with metadata in UI
6. **Policy Selection**: User selects or creates policy for app  
7. **Key Assignment**: User assigns specific key to app authorization
8. **Authorization Activation**: Activate authorization and spawn signer daemon
9. **App Connection**: App can now connect with the approved authorization

### 3.2 Smart Authorization Management

#### Intelligent Policy Suggestions
```rust
// core/src/policy/suggestions.rs - New
pub struct PolicySuggestionService {
    pool: SqlitePool,
}

impl PolicySuggestionService {
    pub async fn suggest_policy_for_app(
        &self,
        user_id: u32,
        app_domain: String,
    ) -> Result<Vec<PolicySuggestion>, PolicyError>;
    
    pub async fn create_policy_from_template(
        &self,
        user_id: u32,
        template: PolicyTemplate,
        app_context: AppContext,
    ) -> Result<UserPolicy, PolicyError>;
}
```

## Phase 4: User Account System

### 4.1 Multi-Auth Authentication System

#### Authentication Methods
```rust
// core/src/auth/mod.rs - Enhanced
pub enum AuthMethod {
    Nip07Extension,
    Nip46Bunker { bunker_url: String },
    EmailPassword { email: String, password_hash: String },
    OAuth { provider: String, oauth_data: OAuthData },
    Passkey { credential_id: String, public_key: Vec<u8> },
}

pub struct AuthService {
    pool: SqlitePool,
    key_manager: Box<dyn KeyManager>,
}

impl AuthService {
    pub async fn authenticate_user(
        &self,
        auth_request: AuthRequest,
    ) -> Result<AuthResult, AuthError>;
    
    pub async fn register_user(
        &self,
        registration_data: RegistrationData,
    ) -> Result<User, AuthError>;
    
    pub async fn add_auth_method(
        &self,
        user_id: u32,
        auth_method: AuthMethod,
    ) -> Result<(), AuthError>;
}
```

### 4.2 User Profile Management

#### Profile Enhancement
```rust
// core/src/user/profile.rs - New
pub struct ProfileService {
    pool: SqlitePool,
}

impl ProfileService {
    pub async fn update_profile(
        &self,
        user_id: u32,
        profile_data: ProfileData,
    ) -> Result<User, ProfileError>;
    
    pub async fn upload_avatar(
        &self,
        user_id: u32,
        image_data: Vec<u8>,
    ) -> Result<String, ProfileError>; // Returns URL
    
    pub async fn set_nip05_identifier(
        &self,
        user_id: u32,
        identifier: String,
    ) -> Result<(), ProfileError>;
}
```

## Phase 5: API Endpoint Transformation

### 5.1 New API Structure

#### User-Centric Endpoints
```rust
// api/src/api/http/routes.rs - Transformed
pub fn routes(pool: SqlitePool) -> Router {
    Router::new()
        // User management
        .route("/user/profile", get(users::get_profile))
        .route("/user/profile", put(users::update_profile))
        .route("/user/auth-methods", get(users::list_auth_methods))
        .route("/user/auth-methods", post(users::add_auth_method))
        
        // User keys
        .route("/user/keys", get(keys::list_user_keys))
        .route("/user/keys", post(keys::create_key))
        .route("/user/keys/:id", get(keys::get_key))
        .route("/user/keys/:id", put(keys::update_key))
        .route("/user/keys/:id", delete(keys::delete_key))
        
        // Applications
        .route("/applications", get(apps::list_user_apps))
        .route("/applications/:id", get(apps::get_app))
        .route("/applications/:id/authorize", post(apps::create_authorization))
        
        // Authorizations
        .route("/authorizations", get(auth::list_authorizations))
        .route("/authorizations/:id", get(auth::get_authorization))
        .route("/authorizations/:id", put(auth::update_authorization))
        .route("/authorizations/:id", delete(auth::revoke_authorization))
        
        // Policies
        .route("/user/policies", get(policies::list_policies))
        .route("/user/policies", post(policies::create_policy))
        .route("/user/policies/:id", get(policies::get_policy))
        .route("/user/policies/:id", put(policies::update_policy))
        .route("/user/policies/:id", delete(policies::delete_policy))
        
        // NIP-05
        .route("/.well-known/nostr.json", get(nip05::well_known_nostr))
        .route("/user/nip05", get(nip05::get_identifier))
        .route("/user/nip05", post(nip05::claim_identifier))
        
        .layer(middleware::from_fn(auth_middleware))
        .with_state(pool)
}
```

### 5.2 Authentication Middleware Updates
- Support multiple auth methods
- JWT token management for web sessions
- NIP-98 HTTP Auth for API access
- Session management for different auth types

## Phase 6: UI/UX Transformation

### 6.1 New User Interface Structure

#### Page Structure
```
/
├── auth/
│   ├── signin
│   ├── signup
│   └── add-method
├── dashboard/
│   ├── overview
│   ├── keys
│   ├── applications
│   ├── authorizations
│   └── policies
├── profile/
│   ├── settings
│   ├── nip05
│   └── security
└── app-auth/
    └── [request_id] (authorization flow)
```

#### Key UI Components
```typescript
// web/src/lib/components/ - New/Updated Components
- UserDashboard.svelte
- KeyManager.svelte  
- ApplicationList.svelte
- AuthorizationCard.svelte
- PolicyEditor.svelte
- Nip05Setup.svelte
- AuthMethodSelector.svelte
- AppAuthorizationFlow.svelte
```

### 6.2 Mobile-First Responsive Design
- Progressive Web App (PWA) capabilities
- Mobile-optimized authentication flows
- Touch-friendly interface elements
- Dark/light mode support

## Phase 7: Security Implementation

### 7.1 Enhanced Security Measures

#### Key Security
- Hardware security module (HSM) support
- Key derivation for app-specific keys
- Secure key backup/recovery system
- Key rotation capabilities

#### Authorization Security  
```rust
// core/src/security/authorization.rs - Enhanced
pub struct AuthorizationSecurity {
    pool: SqlitePool,
}

impl AuthorizationSecurity {
    pub async fn validate_authorization_request(
        &self,
        request: AuthorizationRequest,
    ) -> Result<ValidationResult, SecurityError>;
    
    pub async fn detect_suspicious_activity(
        &self,
        user_id: u32,
        activity: ActivityLog,
    ) -> Result<SecurityAlert, SecurityError>;
    
    pub async fn enforce_rate_limits(
        &self,
        user_id: u32,
        action: ActionType,
    ) -> Result<(), SecurityError>;
}
```

### 7.2 Privacy Protection
- Zero-knowledge architecture where possible
- Minimal data collection
- GDPR compliance
- Data export/deletion capabilities

## Phase 8: Infrastructure & Deployment

### 8.1 Scalability Improvements

#### Database Optimization
- Connection pooling optimization
- Query performance monitoring
- Database sharding preparation
- Read replica support

#### Caching Strategy
```rust
// core/src/cache/mod.rs - New
pub struct CacheService {
    redis_client: RedisClient,
    memory_cache: MemoryCache,
}

impl CacheService {
    pub async fn cache_user_profile(&self, user_id: u32, profile: &User) -> Result<(), CacheError>;
    pub async fn cache_app_metadata(&self, domain: &str, metadata: &AppMetadata) -> Result<(), CacheError>;
    pub async fn invalidate_user_cache(&self, user_id: u32) -> Result<(), CacheError>;
}
```

### 8.2 Deployment Strategy
- Docker containerization updates
- Kubernetes deployment manifests  
- Load balancer configuration
- SSL/TLS termination
- CDN integration for static assets

## Implementation Timeline

### Phase 1: Foundation (Weeks 1-3)
- [ ] Database schema migration
- [ ] Core type system updates
- [ ] Basic user management

### Phase 2: NIP-05 (Weeks 2-4)  
- [ ] NIP-05 service implementation
- [ ] Well-known endpoint
- [ ] Domain management system

### Phase 3: Dynamic Auth (Weeks 4-6)
- [ ] Application discovery system
- [ ] Dynamic authorization flow
- [ ] Policy suggestion engine

### Phase 4: Multi-Auth (Weeks 5-7)
- [ ] Multiple authentication methods
- [ ] User profile management
- [ ] Account linking system

### Phase 5: API Updates (Weeks 6-8)
- [ ] New endpoint implementation
- [ ] Authentication middleware
- [ ] API documentation

### Phase 6: UI/UX (Weeks 7-10)
- [ ] Frontend component development
- [ ] User dashboard implementation
- [ ] Mobile optimization

### Phase 7: Security (Weeks 9-11)
- [ ] Security enhancements
- [ ] Privacy protection
- [ ] Audit logging

### Phase 8: Deployment (Weeks 10-12)
- [ ] Infrastructure updates
- [ ] Performance optimization
- [ ] Monitoring & alerting

## Risk Assessment & Mitigation

### High Risk Areas

#### **Data Migration**
- **Risk**: Data loss during team-to-user migration
- **Mitigation**: Comprehensive backup strategy, gradual migration, rollback plan

#### **Authentication Changes**
- **Risk**: Users locked out during auth system changes
- **Mitigation**: Maintain backward compatibility during transition, multiple auth fallbacks

#### **NIP-05 Implementation**
- **Risk**: Domain management complexity
- **Mitigation**: Start with subdomain-only, gradual custom domain rollout

### Medium Risk Areas

#### **Performance Impact**
- **Risk**: System slowdown during transition
- **Mitigation**: Load testing, caching implementation, gradual feature rollout

#### **Security Vulnerabilities**
- **Risk**: New attack vectors with dynamic app registration
- **Mitigation**: Security audit, rate limiting, app verification system

## Success Metrics

### Technical Metrics
- User authentication success rate > 99%
- API response times < 200ms
- Zero data loss during migration
- 99.9% uptime during transition

### User Experience Metrics
- User onboarding completion rate > 80%
- Average time to first authorization < 2 minutes
- User retention rate > 90%
- Support ticket reduction > 50%

### Security Metrics
- Zero security incidents
- All app registrations verified within 24h
- Suspicious activity detection accuracy > 95%
- Key compromise detection time < 1 minute

## Testing Strategy

### Unit Testing
- Core business logic coverage > 90%
- Database operations testing
- Encryption/decryption testing
- Permission validation testing

### Integration Testing
- End-to-end authentication flows
- NIP-05 discovery testing
- Cross-browser compatibility
- Mobile device testing

### Security Testing  
- Penetration testing
- Vulnerability scanning
- Authentication bypass testing
- Authorization escalation testing

## Monitoring & Observability

### Application Monitoring
```rust
// core/src/monitoring/mod.rs - New
pub struct MonitoringService {
    metrics_collector: MetricsCollector,
    logger: StructuredLogger,
}

impl MonitoringService {
    pub fn track_user_action(&self, user_id: u32, action: UserAction);
    pub fn track_app_authorization(&self, app_id: u32, user_id: u32, success: bool);
    pub fn track_security_event(&self, event: SecurityEvent);
    pub fn track_performance_metric(&self, metric: PerformanceMetric);
}
```

### Key Metrics to Track
- Authentication attempts and success rates
- Authorization creation and usage patterns
- NIP-05 resolution performance
- Key usage and rotation patterns
- Security alerts and responses

## Conclusion

This implementation plan provides a comprehensive roadmap for transforming Keycast from a team-based remote signing service into a personal Nostr authentication service. The phased approach ensures minimal disruption while building robust, scalable, and secure infrastructure for personal Nostr key management and application authorization.

The plan prioritizes user experience, security, and scalability while maintaining the core strengths of the existing Keycast system. Success depends on careful execution of the database migration, thoughtful implementation of the dynamic authorization flow, and comprehensive testing throughout the process.

---

**Document Status**: Draft v2.0  
**Last Updated**: 2025-07-23  
**Major Update**: Discovered existing NIP-46 implementation, revised approach
**Next Review**: Weekly during implementation phases