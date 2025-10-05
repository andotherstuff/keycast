-- OAuth tables for authorization code flow

-- oauth_applications: third-party apps that can request OAuth authorization
CREATE TABLE IF NOT EXISTS oauth_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,  -- JSON array of allowed redirect URIs
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- oauth_codes: authorization codes (short-lived, one-time use)
CREATE TABLE IF NOT EXISTS oauth_codes (
    code TEXT PRIMARY KEY NOT NULL,
    user_public_key TEXT NOT NULL REFERENCES users(public_key),
    application_id INTEGER NOT NULL REFERENCES oauth_applications(id),
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- oauth_authorizations: long-lived authorizations with their own keys
CREATE TABLE IF NOT EXISTS oauth_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_public_key TEXT NOT NULL REFERENCES users(public_key),
    application_id INTEGER NOT NULL REFERENCES oauth_applications(id),
    bunker_public_key TEXT NOT NULL UNIQUE,
    bunker_secret TEXT NOT NULL,
    secret BLOB NOT NULL,  -- Encrypted secret key for this authorization
    relays TEXT NOT NULL,  -- Relay URL for NIP-46
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_user ON oauth_codes(user_public_key);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_user ON oauth_authorizations(user_public_key);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_app ON oauth_authorizations(application_id);
