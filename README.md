# Multi-tenant-identity-and-access-management-system

A multi-tenant authentication and fine-grained authorization gateway. The architecture pairs an unmodified **Keycloak** instance (handling standards-compliant OIDC/SAML credential verification) with a custom **Decoupled Orchestration Gateway** running against **PostgreSQL**.

---

## Key Architectural Decisions

- Decoupled Orchestration Gateway: Keycloak operates as a stateless identity and token engine. All multi-tenant domain models, dynamic ReBAC permissions, consent states, and audit trails reside in the application database.
- Zero-Cache Dependency:In-memory LRU stores handle Keycloak JWKS public key caching, while stateful session tracking and sub-millisecond revocations execute directly via indexed PostgreSQL queries.


---

## Core Tech Stack

- **Identity Engine:** Keycloak 26.x 
- **Application Gateway:** Node.js
- **Database & ORM:** PostgreSQL 16 with Prisma ORM
- **Authorization Engine:** Relationship-Based Access Control 
