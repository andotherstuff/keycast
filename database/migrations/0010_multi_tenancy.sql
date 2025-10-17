-- ABOUTME: Add multi-tenancy support with domain-based tenant isolation
-- ABOUTME: Each tenant (domain) gets isolated user pools, OAuth apps, and data

-- ================ TENANTS TABLE ================
-- Central registry of all tenants (domains) in the system
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,  -- e.g. "holis.social", "divine.video"
    name TEXT NOT NULL,            -- Display name for the tenant
    settings TEXT,                 -- JSON config: branding, relay URLs, email config, etc
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_tenants_domain ON tenants(domain);
CREATE INDEX idx_tenants_name ON tenants(name);

CREATE TRIGGER tenants_update_trigger
AFTER UPDATE ON tenants
BEGIN
    UPDATE tenants SET updated_at = DATETIME('now')
    WHERE id = NEW.id;
END;

-- ================ ADD TENANT_ID TO EXISTING TABLES ================
-- Default to 1 (existing data becomes first tenant)

-- Users table (email and username must be unique per tenant)
ALTER TABLE users ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);

-- Teams table
ALTER TABLE teams ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_teams_tenant_id ON teams(tenant_id);

-- Stored keys table
ALTER TABLE stored_keys ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_stored_keys_tenant_id ON stored_keys(tenant_id);

-- Policies table
ALTER TABLE policies ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_policies_tenant_id ON policies(tenant_id);

-- Authorizations table (bunker_public_key must be unique per tenant)
ALTER TABLE authorizations ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_authorizations_tenant_id ON authorizations(tenant_id);

-- Personal keys table (bunker_secret must be unique per tenant)
ALTER TABLE personal_keys ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_personal_keys_tenant_id ON personal_keys(tenant_id);

-- OAuth applications table (client_id must be unique per tenant)
-- NOTE: Must recreate table to remove column-level UNIQUE constraint on client_id
-- Also need to recreate dependent tables to fix FK references

-- Drop existing indexes first
DROP INDEX IF EXISTS idx_oauth_codes_expires;
DROP INDEX IF EXISTS idx_oauth_codes_user;
DROP INDEX IF EXISTS idx_oauth_auth_user;
DROP INDEX IF EXISTS idx_oauth_auth_app;
DROP INDEX IF EXISTS idx_signing_activity_user;
DROP INDEX IF EXISTS idx_signing_activity_app;
DROP INDEX IF EXISTS idx_signing_activity_bunker_secret;
DROP INDEX IF EXISTS idx_signing_activity_created_at;

ALTER TABLE oauth_applications RENAME TO oauth_applications_old;
ALTER TABLE oauth_codes RENAME TO oauth_codes_old;
ALTER TABLE oauth_authorizations RENAME TO oauth_authorizations_old;
ALTER TABLE signing_activity RENAME TO signing_activity_old;

CREATE TABLE oauth_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,  -- Removed UNIQUE constraint (will be tenant-scoped below)
    client_secret TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id)
);

INSERT INTO oauth_applications (id, client_id, client_secret, name, redirect_uris, created_at, updated_at, tenant_id)
SELECT id, client_id, client_secret, name, redirect_uris, created_at, updated_at, 1
FROM oauth_applications_old;

CREATE INDEX idx_oauth_applications_tenant_id ON oauth_applications(tenant_id);

-- OAuth codes table (recreate with proper FK and tenant_id)
CREATE TABLE oauth_codes (
    code TEXT PRIMARY KEY NOT NULL,
    user_public_key TEXT NOT NULL REFERENCES users(public_key),
    application_id INTEGER NOT NULL REFERENCES oauth_applications(id),
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id)
);

INSERT INTO oauth_codes (code, user_public_key, application_id, redirect_uri, scope, expires_at, created_at, tenant_id)
SELECT code, user_public_key, application_id, redirect_uri, scope, expires_at, created_at, 1
FROM oauth_codes_old;

CREATE INDEX idx_oauth_codes_expires ON oauth_codes(expires_at);
CREATE INDEX idx_oauth_codes_user ON oauth_codes(user_public_key);
CREATE INDEX idx_oauth_codes_tenant_id ON oauth_codes(tenant_id);

-- OAuth authorizations table (recreate with proper FK and tenant_id)
CREATE TABLE oauth_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_public_key TEXT NOT NULL REFERENCES users(public_key),
    application_id INTEGER NOT NULL REFERENCES oauth_applications(id),
    bunker_public_key TEXT NOT NULL,
    bunker_secret TEXT NOT NULL,
    secret BLOB NOT NULL,
    relays TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id)
);

INSERT INTO oauth_authorizations (id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at, tenant_id)
SELECT id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at, 1
FROM oauth_authorizations_old;

CREATE INDEX idx_oauth_auth_user ON oauth_authorizations(user_public_key);
CREATE INDEX idx_oauth_auth_app ON oauth_authorizations(application_id);
CREATE INDEX idx_oauth_authorizations_tenant_id ON oauth_authorizations(tenant_id);

-- Signing activity table (recreate with proper FK and tenant_id)
CREATE TABLE signing_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    application_id INTEGER REFERENCES oauth_applications(id) ON DELETE SET NULL,
    bunker_secret TEXT NOT NULL,
    event_kind INTEGER NOT NULL,
    event_content TEXT,
    event_id CHAR(64),
    client_public_key CHAR(64),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id)
);

INSERT INTO signing_activity (id, user_public_key, application_id, bunker_secret, event_kind, event_content, event_id, client_public_key, created_at, tenant_id)
SELECT id, user_public_key, application_id, bunker_secret, event_kind, event_content, event_id, client_public_key, created_at, 1
FROM signing_activity_old;

CREATE INDEX idx_signing_activity_user ON signing_activity(user_public_key);
CREATE INDEX idx_signing_activity_app ON signing_activity(application_id);
CREATE INDEX idx_signing_activity_bunker_secret ON signing_activity(bunker_secret);
CREATE INDEX idx_signing_activity_created_at ON signing_activity(created_at);
CREATE INDEX idx_signing_activity_tenant_id ON signing_activity(tenant_id);

-- Drop all old tables
DROP TABLE oauth_applications_old;
DROP TABLE oauth_codes_old;
DROP TABLE oauth_authorizations_old;
DROP TABLE signing_activity_old;

-- ================ UPDATE UNIQUE CONSTRAINTS ================
-- Drop old global unique constraints and replace with tenant-scoped ones

-- Users: email must be unique per tenant
DROP INDEX IF EXISTS idx_users_email;
CREATE UNIQUE INDEX idx_users_email_tenant ON users(tenant_id, email) WHERE email IS NOT NULL;

-- Users: username must be unique per tenant (for NIP-05)
DROP INDEX IF EXISTS idx_users_username;
CREATE UNIQUE INDEX idx_users_username_tenant ON users(tenant_id, username) WHERE username IS NOT NULL;

-- OAuth applications: client_id must be unique per tenant (table was recreated above)
CREATE UNIQUE INDEX idx_oauth_applications_client_id_tenant ON oauth_applications(tenant_id, client_id);

-- Authorizations: bunker_public_key unique per tenant
DROP INDEX IF EXISTS authorizations_secret_idx;
CREATE UNIQUE INDEX idx_authorizations_secret_tenant ON authorizations(tenant_id, secret);

-- Personal keys: bunker_secret unique per tenant
DROP INDEX IF EXISTS personal_keys_bunker_secret_key;
CREATE UNIQUE INDEX idx_personal_keys_bunker_secret_tenant ON personal_keys(tenant_id, bunker_secret);

-- OAuth authorizations: bunker_public_key unique per tenant
DROP INDEX IF EXISTS oauth_authorizations_bunker_public_key_key;
CREATE UNIQUE INDEX idx_oauth_authorizations_bunker_public_key_tenant ON oauth_authorizations(tenant_id, bunker_public_key);

-- ================ INSERT DEFAULT TENANT ================
-- Create tenant for existing oauth.divine.video deployment
INSERT INTO tenants (id, domain, name, settings, created_at, updated_at)
VALUES (
    1,
    'oauth.divine.video',
    'Divine Video',
    '{"relay":"wss://relay.damus.io","email_from":"noreply@oauth.divine.video"}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
