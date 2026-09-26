# ADR 0001: Core Platform Architecture

## Status
Accepted

## Context
We need a multi-tenant IAM platform with fine-grained authorization, immediate session revocation, and auditability.

## Decision
1. **Decoupled Backend:** Vanilla Keycloak handles OIDC token signing and credentials. Custom Node.js backend handles tenants, memberships, and ReBAC authorization.
2. **PostgreSQL Only (No Redis):** Session invalidation and revocation checks run directly against indexed PostgreSQL tables. JWKS keys are cached in memory.
3. **No Device Table:** Client metadata (`user_agent`, `ip_address`) is stored directly on session records.

## Consequences
- Single database dependency (simpler operations and lower cost).
- Zero JVM/SPI code required in Keycloak.