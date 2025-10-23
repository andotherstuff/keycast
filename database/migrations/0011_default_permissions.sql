-- ABOUTME: Seed default permission templates and create default policy for keycast-login
-- ABOUTME: Provides sensible permission defaults for personal signing (social + messaging, no financial)

-- ================ ADD POLICY_ID TO OAUTH_APPLICATIONS ================
-- OAuth applications need to specify which policy they use
ALTER TABLE oauth_applications ADD COLUMN policy_id INTEGER REFERENCES policies(id);
CREATE INDEX idx_oauth_applications_policy_id ON oauth_applications(policy_id);

-- ================ DEFAULT PERMISSION TEMPLATES ================
-- These permissions can be reused across multiple policies

-- Permission 1: Social Events Only (kinds 0, 1, 3, 7, 9735)
-- Allows: Profile, Notes, Follows, Reactions, Zap receipts
-- Safe for basic social clients
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [0, 1, 3, 7, 9735]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 2: Messaging (kinds 4, 44, 1059)
-- Allows: Encrypted DMs (NIP-04, NIP-44), Gift wraps
-- Sensitive: gives access to private messages
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [4, 44, 1059]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 3: Zaps Only (kind 9734)
-- Allows: Zap requests (spending money!)
-- Financial: should require explicit approval
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [9734]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 4: Lists & Data (kinds 10000-19999)
-- Allows: Mute lists, pin lists, bookmarks, etc.
-- Generally safe, user-specific data
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10015, 10030]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 5: Long-form Content (kinds 30000-39999)
-- Allows: Long-form articles, blogs, etc.
-- Generally safe for content creation
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [30023, 30024, 30030, 30040, 30041, 30078, 30311, 30315, 30402, 30403]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 6: Wallet Operations (kinds 23194, 23195)
-- Allows: Wallet connect, wallet operations
-- DANGEROUS: direct wallet access
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [23194, 23195]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 7: Deletion Events (kind 5)
-- Allows: Deleting events
-- DANGEROUS: can delete all user content
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [5]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 8: Reports (kind 1984)
-- Allows: Filing reports/complaints
-- Sensitive: can be abused for harassment
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [1984]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Permission 9: All Social + Messaging (common safe bundle)
-- Combines social events + messaging for convenience
-- Does NOT include financial, deletion, or dangerous operations
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds',
    '{"allowed_kinds": [0, 1, 3, 4, 7, 44, 1059, 9735]}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- ================ DEFAULT POLICIES ================
-- Policy templates that can be cloned for new users

-- Policy 1: "Standard Social" (DEFAULT for keycast-login)
-- Recommended for most users: Social + Messaging, no financial/dangerous ops
-- This gets assigned to new users on registration
INSERT INTO policies (name, team_id, created_at, updated_at, tenant_id)
VALUES (
    'Standard Social (Default)',
    NULL,  -- Not team-specific
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    1  -- Default tenant
);

-- Link Permission 9 (All Social + Messaging) to Policy 1
INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
VALUES (
    (SELECT id FROM policies WHERE name = 'Standard Social (Default)' LIMIT 1),
    (SELECT id FROM permissions WHERE identifier = 'allowed_kinds' AND config LIKE '%0, 1, 3, 4, 7%' LIMIT 1),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Policy 2: "Read Only"
-- For browse-only clients, no posting
-- Just reactions and follows, no content creation
INSERT INTO policies (name, team_id, created_at, updated_at, tenant_id)
VALUES (
    'Read Only',
    NULL,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    1
);

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
VALUES (
    (SELECT id FROM policies WHERE name = 'Read Only' LIMIT 1),
    (SELECT id FROM permissions WHERE identifier = 'allowed_kinds' AND config = '{"allowed_kinds": [0, 1, 3, 7, 9735]}' LIMIT 1),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Policy 3: "Wallet Only"
-- For zap wallets, only allow zap requests
-- No social or messaging capabilities
INSERT INTO policies (name, team_id, created_at, updated_at, tenant_id)
VALUES (
    'Wallet Only',
    NULL,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    1
);

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
VALUES (
    (SELECT id FROM policies WHERE name = 'Wallet Only' LIMIT 1),
    (SELECT id FROM permissions WHERE identifier = 'allowed_kinds' AND config = '{"allowed_kinds": [9734]}' LIMIT 1),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- ================ CREATE DEFAULT OAUTH APPLICATION ================
-- The "keycast-login" OAuth application for personal HTTP signing

-- First, create or update the keycast-login OAuth application
-- This app uses the "Standard Social (Default)" policy
INSERT OR REPLACE INTO oauth_applications (
    client_id,
    client_secret,
    name,
    redirect_uris,
    policy_id,
    tenant_id,
    created_at,
    updated_at
)
VALUES (
    'keycast-login',
    'not-used-for-personal-auth',  -- Personal auth uses JWT, not OAuth client secret
    'Personal Keycast Bunker',
    'http://localhost:3000/api/connect,https://oauth.divine.video/api/connect',
    (SELECT id FROM policies WHERE name = 'Standard Social (Default)' LIMIT 1),
    1,  -- Default tenant
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- ================ NOTES ================
-- When a new user registers:
-- 1. Create oauth_authorization linking user to keycast-login app
-- 2. The authorization inherits the policy_id from oauth_applications
-- 3. HTTP signing validates against this policy's permissions
-- 4. Users can later customize their permissions via UI

-- Event Kind Reference:
-- 0: Profile metadata
-- 1: Short text note
-- 3: Follow list
-- 4: Encrypted DM (NIP-04)
-- 5: Deletion
-- 7: Reaction
-- 44: Encrypted DM (NIP-44)
-- 1059: Gift wrap
-- 1984: Reporting
-- 9734: Zap request
-- 9735: Zap receipt
-- 10000+: Replaceable events (lists)
-- 23194-23195: Wallet operations
-- 30000+: Parameterized replaceable (long-form, etc.)
