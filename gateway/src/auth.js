import { createRemoteJWKSet, jwtVerify } from 'jose';
import { check } from './fga.js';

const issuer = process.env.OIDC_ISSUER;
// jose caches the key set in memory and refreshes it when it sees an unknown "kid"
const jwks = createRemoteJWKSet(new URL(process.env.OIDC_JWKS_URI));

/**
 * 1. Verifies the Keycloak access token (signature, expiry, issuer).
 * 2. Reads the user id (sub) and tenant (tenant_id claim).
 * 3. Asks OpenFGA whether this user is actually a member of that tenant,
 *    so a forged or stale claim alone never grants tenant access.
 */
export async function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing bearer token' });

  try {
    const { payload } = await jwtVerify(token, jwks, { issuer });
    const tenantId = payload.tenant_id;
    if (!tenantId) return res.status(403).json({ error: 'token has no tenant_id' });

    const user = `user:${payload.sub}`;
    const isMember = await check(user, 'member', `tenant:${tenantId}`);
    if (!isMember) {
      return res.status(403).json({ error: `not a member of tenant ${tenantId}` });
    }

    req.auth = {
      sub: payload.sub,
      fgaUser: user,
      username: payload.preferred_username,
      tenantId,
    };
    next();
  } catch (e) {
    console.error('[auth]', e.message);
    res.status(401).json({ error: 'invalid token', detail: e.message });
  }
}

/** Route guard: require an OpenFGA relation on `:id` documents. */
export function requireDocument(relation) {
  return async (req, res, next) => {
    const object = `document:${req.params.id}`;
    const allowed = await check(req.auth.fgaUser, relation, object);
    if (!allowed) return res.status(403).json({ error: `requires ${relation} on ${object}` });
    next();
  };
}
