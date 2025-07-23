-- ================ USERS TABLE ================
-- Core user table with enhanced fields for personal auth
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    public_key CHAR(64) UNIQUE NOT NULL, -- hex
    display_name TEXT,
    email TEXT,
    nip05_identifier TEXT UNIQUE,
    profile_picture_url TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER users_update_trigger 
AFTER UPDATE ON users
BEGIN
    UPDATE users SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- Indexes for users
CREATE UNIQUE INDEX idx_users_public_key ON users(public_key);
CREATE INDEX idx_users_email ON users(email);
CREATE UNIQUE INDEX idx_users_nip05 ON users(nip05_identifier) WHERE nip05_identifier IS NOT NULL;

-- ================ USER AUTHENTICATION METHODS ================
CREATE TABLE user_auth_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT REFERENCES users(id),
    auth_type TEXT NOT NULL CHECK (auth_type IN ('nip07', 'nip46', 'email_password', 'oauth', 'passkey')),
    auth_data TEXT NOT NULL, -- JSON with method-specific data
    is_primary BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER user_auth_methods_update_trigger 
AFTER UPDATE ON user_auth_methods
BEGIN
    UPDATE user_auth_methods SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- Indexes for auth methods
CREATE INDEX idx_user_auth_methods_user ON user_auth_methods(user_id);
CREATE INDEX idx_user_auth_methods_type ON user_auth_methods(auth_type);

-- ================ USER KEYS ================
-- Personal keys for users (primary, app-specific, temporary)
CREATE TABLE user_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    name TEXT NOT NULL,
    public_key CHAR(64) NOT NULL, -- hex
    secret_key BLOB NOT NULL, -- encrypted secret key
    key_type TEXT NOT NULL CHECK (key_type IN ('primary', 'app_specific', 'temporary')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER user_keys_update_trigger 
AFTER UPDATE ON user_keys
BEGIN
    UPDATE user_keys SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- Indexes for user keys
CREATE INDEX idx_user_keys_user ON user_keys(user_id);
CREATE INDEX idx_user_keys_type ON user_keys(key_type);
CREATE UNIQUE INDEX idx_user_keys_public_key ON user_keys(public_key);

-- ================ APPLICATIONS ================
-- Dynamically registered applications
CREATE TABLE applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT UNIQUE NOT NULL,
    description TEXT,
    icon_url TEXT,
    pubkey CHAR(64), -- App's pubkey if available
    metadata TEXT NOT NULL DEFAULT '{}', -- JSON with app metadata
    is_verified BOOLEAN DEFAULT FALSE,
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER applications_update_trigger 
AFTER UPDATE ON applications
BEGIN
    UPDATE applications SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- Indexes for applications
CREATE INDEX idx_applications_domain ON applications(domain);
CREATE INDEX idx_applications_verified ON applications(is_verified);

-- ================ POLICIES ================
-- User-specific policies for controlling access
CREATE TABLE policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT REFERENCES users(id),
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER policies_update_trigger 
AFTER UPDATE ON policies
BEGIN
    UPDATE policies SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- Indexes for policies
CREATE INDEX idx_policies_user ON policies(user_id);

-- ================ PERMISSIONS ================
-- Available permissions in the system
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('custom')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER permissions_update_trigger 
AFTER UPDATE ON permissions
BEGIN
    UPDATE permissions SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- ================ POLICY PERMISSIONS ================
-- Link permissions to policies
CREATE TABLE policy_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL REFERENCES policies(id),
    permission_id INTEGER NOT NULL REFERENCES permissions(id),
    permission_data TEXT NOT NULL, -- JSON
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(policy_id, permission_id)
);

CREATE TRIGGER policy_permissions_update_trigger 
AFTER UPDATE ON policy_permissions
BEGIN
    UPDATE policy_permissions SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- ================ AUTHORIZATIONS ================
-- App authorizations with NIP-46 bunker support
CREATE TABLE authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT REFERENCES users(id),
    user_key_id TEXT REFERENCES user_keys(id),
    application_id INTEGER REFERENCES applications(id),
    policy_id INTEGER REFERENCES policies(id),
    secret TEXT NOT NULL UNIQUE, -- connection secret
    bunker_public_key CHAR(64) NOT NULL, -- hex
    bunker_secret BLOB NOT NULL, -- encrypted bunker secret key
    relays TEXT NOT NULL, -- JSON array of relays
    max_uses INTEGER,
    expires_at DATETIME,
    last_used_at DATETIME,
    status TEXT DEFAULT 'active' CHECK (status IN ('pending', 'active', 'revoked')),
    requested_at DATETIME,
    approved_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Legacy support for existing code
    stored_key_id INTEGER DEFAULT 0
);

CREATE TRIGGER authorizations_update_trigger 
AFTER UPDATE ON authorizations
BEGIN
    UPDATE authorizations SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- Indexes for authorizations
CREATE INDEX idx_authorizations_user ON authorizations(user_id);
CREATE INDEX idx_authorizations_app ON authorizations(application_id);
CREATE INDEX idx_authorizations_status ON authorizations(status);
CREATE INDEX idx_authorizations_secret ON authorizations(secret);

-- ================ USER AUTHORIZATIONS ================
-- Track which users have used which authorizations
CREATE TABLE user_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_public_key CHAR(64) REFERENCES users(public_key),
    authorization_id INTEGER REFERENCES authorizations(id),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER user_authorizations_update_trigger 
AFTER UPDATE ON user_authorizations
BEGIN
    UPDATE user_authorizations SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- ================ NIP-05 DOMAINS ================
CREATE TABLE nip05_domains (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    user_id TEXT REFERENCES users(id),
    verification_type TEXT NOT NULL DEFAULT 'dns_txt',
    verification_value TEXT,
    verified BOOLEAN DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER nip05_domains_update_trigger 
AFTER UPDATE ON nip05_domains
BEGIN
    UPDATE nip05_domains SET updated_at = DATETIME('now') WHERE id = NEW.id;
END;

-- Indexes for NIP-05 domains
CREATE INDEX idx_nip05_domains_user ON nip05_domains(user_id);
CREATE INDEX idx_nip05_domains_verified ON nip05_domains(verified);

-- ================ USER SESSIONS ================
CREATE TABLE user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for sessions
CREATE INDEX idx_user_sessions_token ON user_sessions(token);
CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires ON user_sessions(expires_at);

-- ================ APP CONNECTION ATTEMPTS ================
-- Track connection attempts for dynamic discovery
CREATE TABLE app_connection_attempts (
    id TEXT PRIMARY KEY,
    app_domain TEXT NOT NULL,
    app_pubkey TEXT,
    user_nip05 TEXT,
    connection_metadata TEXT, -- JSON with app info
    attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN DEFAULT FALSE
);

-- Indexes for connection attempts
CREATE INDEX idx_app_attempts_domain ON app_connection_attempts(app_domain);
CREATE INDEX idx_app_attempts_processed ON app_connection_attempts(processed);
CREATE INDEX idx_app_attempts_nip05 ON app_connection_attempts(user_nip05);

-- ================ AUTHORIZATION REQUESTS ================
-- Pending authorization requests
CREATE TABLE authorization_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    app_domain TEXT NOT NULL,
    app_name TEXT,
    app_description TEXT,
    app_icon_url TEXT,
    requested_permissions TEXT, -- JSON array
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    responded_at DATETIME
);

-- Indexes for authorization requests
CREATE INDEX idx_auth_requests_user ON authorization_requests(user_id);
CREATE INDEX idx_auth_requests_status ON authorization_requests(status);
CREATE INDEX idx_auth_requests_created ON authorization_requests(created_at);

-- ================ ACTIVITY LOGS ================
CREATE TABLE activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT REFERENCES users(id),
    action_type TEXT NOT NULL,
    action_details TEXT NOT NULL, -- JSON
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for activity logs
CREATE INDEX idx_activity_logs_user ON activity_logs(user_id);
CREATE INDEX idx_activity_logs_created ON activity_logs(created_at);
CREATE INDEX idx_activity_logs_action ON activity_logs(action_type);

-- ================ MINIMAL LEGACY SUPPORT ================
-- Keep minimal team structure for backward compatibility during transition
-- These will be removed once we fully migrate the codebase
CREATE TABLE teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE stored_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL REFERENCES teams(id),
    name TEXT NOT NULL,
    public_key CHAR(64) NOT NULL,
    secret_key BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);