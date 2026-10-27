// gateway/src/auth.js
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { pool, checkPermission } = require('./fga');
require('dotenv').config();

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8081';
const REALM = process.env.KEYCLOAK_REALM || 'dat';
const JWKS = createRemoteJWKSet(
  new URL(`${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`)
);

/**
 * Resolve the owning tenant from the resource itself. The X-Tenant-ID header is
 * client-controlled, so it is never trusted for audit or authorization attribution.
 */
async function resolveOrgId(objectId) {
  if (!objectId || typeof objectId !== 'string') return null;
  if (objectId.startsWith('organization:')) return objectId;
  if (objectId.startsWith('course:')) {
    const { rows } = await pool.query(
      'SELECT org_id FROM courses WHERE course_id = $1 OR id = $1',
      [objectId]
    );
    if (rows.length > 0) return rows[0].org_id;
  }
  return null;
}

/**
 * Authentication Middleware:
 * - Validates RS256 signature against Keycloak JWKS
 * - Checks against global revoked sessions table in DB
 */
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;

    // Stateful global revocation check (Keycloak session level)
    if (payload.sid) {
      const { rows } = await pool.query(
        'SELECT 1 FROM revoked_sessions WHERE session_id = $1 LIMIT 1',
        [payload.sid]
      );
      if (rows.length > 0) {
        return res.status(401).json({ error: 'Session has been revoked globally' });
      }
    }

    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token', details: err.message });
  }
}

/**
 * ReBAC Authorization Middleware Factory
 * - Checks organization-level session cutoff: rejects if token was issued prior to session_revoked_at
 * - Evaluates OpenFGA permission
 * - Logs audit record
 */
function requirePermission(relation, getObjectId) {
  return async (req, res, next) => {
    try {
      const objectId = typeof getObjectId === 'function' ? getObjectId(req) : getObjectId;
      if (typeof objectId !== 'string' || !objectId) {
        return res.status(400).json({ error: 'Missing resource identifier' });
      }

      const userSub = req.user.sub;
      const orgId = await resolveOrgId(objectId);

      // Organization-scoped session revocation cutoff check
      if (orgId && req.user.iat) {
        const { rows } = await pool.query(
          `SELECT session_revoked_at 
           FROM tenant_memberships 
           WHERE user_sub = $1 AND org_id = $2 
           LIMIT 1`,
          [userSub, orgId]
        );

        if (rows.length > 0 && rows[0].session_revoked_at) {
          const revokedAtSec = Math.floor(new Date(rows[0].session_revoked_at).getTime() / 1000);
          if (req.user.iat <= revokedAtSec) {
            await recordAudit(req, relation, objectId, false);
            return res.status(401).json({
              error: 'Session revoked for this organization. Please re-authenticate.'
            });
          }
        }
      }

      const allowed = await checkPermission(userSub, relation, objectId);
      await recordAudit(req, relation, objectId, allowed);

      if (!allowed) {
        return res.status(403).json({ error: 'Forbidden: Relationship check denied access' });
      }

      next();
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  };
}

/**
 * Append-only audit record
 */
async function recordAudit(req, action, objectId, allowed) {
  try {
    const orgId = await resolveOrgId(objectId);
    await pool.query(
      `INSERT INTO audit_logs (user_sub, org_id, action, resource, decision, context)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        req.user ? req.user.sub : 'anonymous',
        orgId,
        action,
        objectId,
        allowed ? 'ALLOW' : 'DENY',
        JSON.stringify({
          ip: req.ip,
          method: req.method,
          path: req.originalUrl,
          claimed_tenant: req.headers['x-tenant-id'] || null
        })
      ]
    );
  } catch (err) {
    console.error('Failed to write audit log:', err.message);
  }
}

module.exports = {
  requireAuth,
  requirePermission,
  recordAudit,
  resolveOrgId
};