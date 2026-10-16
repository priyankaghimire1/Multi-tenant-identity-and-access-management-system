CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations / Tenants
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(128) PRIMARY KEY, -- e.g., 'organization:acme'
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- User Profiles (keyed by Keycloak OIDC 'sub')
CREATE TABLE IF NOT EXISTS user_profiles (
    sub VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(128),
    last_name VARCHAR(128),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tenant Memberships
CREATE TABLE IF NOT EXISTS tenant_memberships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_sub VARCHAR(255) REFERENCES user_profiles(sub) ON DELETE CASCADE,
    org_id VARCHAR(128) REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL, -- 'admin', 'instructor', 'learner'
    is_suspended BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_sub, org_id, role)
);

-- Courses (Protected Operational Domain)
CREATE TABLE IF NOT EXISTS courses (
    id VARCHAR(128) PRIMARY KEY, -- e.g., 'course:cs101'
    org_id VARCHAR(128) REFERENCES organizations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Transactional Outbox for OpenFGA Tuple Synchronization
CREATE TABLE IF NOT EXISTS outbox_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_outbox_unprocessed ON outbox_events(processed) WHERE processed = FALSE;

-- Revoked User Sessions (Stateful check against stolen/compromised tokens)
CREATE TABLE IF NOT EXISTS revoked_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_sub VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) UNIQUE NOT NULL, -- Keycloak 'sid' claim
    revoked_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_sid ON revoked_sessions(session_id);

-- Tamper-Evident Append-Only Audit Trail
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    user_sub VARCHAR(255) NOT NULL,
    org_id VARCHAR(128),
    action VARCHAR(64) NOT NULL,
    resource VARCHAR(128) NOT NULL,
    decision VARCHAR(16) NOT NULL, -- 'ALLOW' | 'DENY'
    context JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);