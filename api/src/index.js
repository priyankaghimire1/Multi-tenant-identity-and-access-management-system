import express from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app = express();
const jwks = createRemoteJWKSet(new URL(process.env.OIDC_JWKS_URL));

async function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'missing_token' });
  }
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: process.env.OIDC_ISSUER,
      audience: process.env.OIDC_AUDIENCE,
    });
    req.user = {
      id: payload.sub,
      tenantId: payload.tenant_id,
      roles: payload.realm_access?.roles ?? [],
    };
    next();
  } catch(err) {
    console.error('JWT verification failed:', err.code, err.message);
    res.status(401).json({ error: 'invalid_token' });
  }
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/documents', authenticate, (req, res) =>
  res.json({ tenant: req.user.tenantId, roles: req.user.roles })
);

app.listen(3000, () => console.log('API on :3000'));