import express from 'express';
import { init, check, write } from './fga.js';
import { authenticate, requireDocument } from './auth.js';

const app = express();
app.use(express.json());

app.get('/health', (_req, res) => res.json({ ok: true }));

// Who am I? (proves the Keycloak token + OpenFGA tenant membership both work)
app.get('/me', authenticate, (req, res) => {
  res.json({ sub: req.auth.sub, username: req.auth.username, tenant: req.auth.tenantId });
});

// Create a document in the caller's tenant. Caller becomes the owner.
app.post('/documents', authenticate, async (req, res) => {
  const { id } = req.body || {};
  if (!id || !/^[\w-]+$/.test(id)) return res.status(400).json({ error: 'id required (letters, digits, - _)' });

  // Namespacing by tenant avoids id collisions between tenants
  const docId = `${req.auth.tenantId}-${id}`;
  await write([
    { user: `tenant:${req.auth.tenantId}`, relation: 'parent', object: `document:${docId}` },
    { user: req.auth.fgaUser, relation: 'owner', object: `document:${docId}` },
  ]);
  res.status(201).json({ id: docId });
});

app.get('/documents/:id', authenticate, requireDocument('can_view'), (req, res) => {
  res.json({ id: req.params.id, content: 'secret document body', viewer: req.auth.username });
});

app.put('/documents/:id', authenticate, requireDocument('can_edit'), (req, res) => {
  res.json({ id: req.params.id, updated: true, by: req.auth.username });
});

// Share a document with another user (owner only). Body: { "userId": "<keycloak sub>", "relation": "viewer" | "editor" }
app.post('/documents/:id/share', authenticate, requireDocument('can_share'), async (req, res) => {
  const { userId, relation } = req.body || {};
  if (!userId || !['viewer', 'editor'].includes(relation)) {
    return res.status(400).json({ error: 'userId and relation (viewer|editor) required' });
  }
  // Only allow sharing with members of the same tenant
  const sameTenant = await check(`user:${userId}`, 'member', `tenant:${req.auth.tenantId}`);
  if (!sameTenant) return res.status(403).json({ error: 'target user is not in your tenant' });

  await write([{ user: `user:${userId}`, relation, object: `document:${req.params.id}` }]);
  res.json({ shared: true });
});

// Express 5 forwards rejected async handlers here
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

await init();
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`[gateway] listening on :${port}`));
