-- Fix OAuth authorizations UNIQUE constraint
-- Since we now use the user's personal key as bunker_public_key,
-- multiple authorizations per user will have the same bunker_public_key
-- but different application_ids. Change UNIQUE constraint accordingly.

-- Check if old table has the incorrect schema (missing policy_id, expires_at, revoked_at columns)
-- If so, we need to add them. If the table already has them, this migration was already applied.

-- Recreate the table with correct types and without UNIQUE constraint on bunker_public_key
-- Note: The original migration 0004 had bunker_secret as TEXT and secret as BLOB
-- But logically bunker_secret should be BLOB (encrypted key) and secret should be TEXT (connection string)
CREATE TABLE IF NOT EXISTS oauth_authorizations_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_public_key TEXT NOT NULL REFERENCES users(public_key),
    application_id INTEGER NOT NULL REFERENCES oauth_applications(id),
    bunker_public_key TEXT NOT NULL,
    bunker_secret BLOB NOT NULL,      -- Changed from TEXT to BLOB (encrypted user key)
    secret TEXT NOT NULL,              -- Changed from BLOB to TEXT (connection secret)
    relays TEXT NOT NULL,
    policy_id INTEGER,
    expires_at DATETIME,
    revoked_at DATETIME,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_public_key, application_id)
);

-- Only copy data if the old table exists and has data
INSERT INTO oauth_authorizations_new
    (id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at)
SELECT id, user_public_key, application_id, bunker_public_key,
    CASE WHEN typeof(bunker_secret) = 'blob' THEN bunker_secret ELSE CAST(secret AS BLOB) END,
    CASE WHEN typeof(secret) = 'text' THEN secret ELSE CAST(bunker_secret AS TEXT) END,
    relays, created_at, updated_at
FROM oauth_authorizations
WHERE EXISTS (SELECT 1 FROM oauth_authorizations LIMIT 1);

-- Drop old table
DROP TABLE IF EXISTS oauth_authorizations;

-- Rename new table
ALTER TABLE oauth_authorizations_new RENAME TO oauth_authorizations;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_oauth_auth_user ON oauth_authorizations(user_public_key);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_app ON oauth_authorizations(application_id);
