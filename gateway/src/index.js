const express = require('express');
const cors = require('cors');
const path = require('path');
const { pool } = require('./fga');
const { requireAuth, requirePermission } = require('./auth');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ----------------------------------------------------
// M1 & M5: Organization Provisioning & Suspension
// ----------------------------------------------------
app.post('/api/orgs', requireAuth, async (req, res) => {
  const { org_id, name, domain } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'INSERT INTO organizations (id, name, domain, is_active) VALUES ($1, $2, $3, TRUE)',
      [org_id, name, domain]
    );
    // Write outbox event to enable the wildcard tenant_active relation
    await client.query(
      `INSERT INTO outbox_events (event_type, payload) VALUES ($1, $2)`,
      ['TENANT_PROVISIONED', { action: 'WRITE', user: 'user:*', relation: 'tenant_active', object: org_id }]
    );
    await client.query('COMMIT');
    res.status(201).json({ message: 'Tenant organization registered', org_id });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Instant tenant-wide kill switch: removes wildcard tenant_active
app.patch('/api/orgs/:org_id/suspend', requireAuth, async (req, res) => {
  const { org_id } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE organizations SET is_active = FALSE WHERE id = $1', [org_id]);
    await client.query(
      `INSERT INTO outbox_events (event_type, payload) VALUES ($1, $2)`,
      ['TENANT_SUSPENDED', { action: 'DELETE', user: 'user:*', relation: 'tenant_active', object: org_id }]
    );
    await client.query('COMMIT');
    res.json({ message: `Tenant ${org_id} suspended across platform` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ----------------------------------------------------
// M4: Role Management & User Suspension
// ----------------------------------------------------
app.post('/api/orgs/:org_id/memberships', requireAuth, async (req, res) => {
  const { org_id } = req.params;
  const { user_sub, role } = req.body; // 'admin', 'instructor', 'learner'

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'INSERT INTO tenant_memberships (user_sub, org_id, role) VALUES ($1, $2, $3)',
      [user_sub, org_id, role]
    );
    await client.query(
      `INSERT INTO outbox_events (event_type, payload) VALUES ($1, $2)`,
      ['MEMBERSHIP_ASSIGNED', { action: 'WRITE', user: `user:${user_sub}`, relation: role, object: org_id }]
    );
    await client.query('COMMIT');
    res.status(201).json({ message: `Role ${role} granted to ${user_sub}` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.patch('/api/orgs/:org_id/members/:user_sub/suspend', requireAuth, async (req, res) => {
  const { org_id, user_sub } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'UPDATE tenant_memberships SET is_suspended = TRUE WHERE user_sub = $1 AND org_id = $2',
      [user_sub, org_id]
    );
    await client.query(
      `INSERT INTO outbox_events (event_type, payload) VALUES ($1, $2)`,
      ['USER_SUSPENDED', { action: 'WRITE', user: `user:${user_sub}`, relation: 'suspended', object: org_id }]
    );
    await client.query('COMMIT');
    res.json({ message: `User ${user_sub} suspended in ${org_id}` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ----------------------------------------------------
// Domain Resource APIs (Courses protected by OpenFGA ReBAC)
// ----------------------------------------------------
app.post('/api/courses',
  requireAuth,
  requirePermission('org_admin', (req) => req.body.org_id),
  async (req, res) => {
    const { course_id, org_id, title, description } = req.body;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'INSERT INTO courses (id, org_id, title, description) VALUES ($1, $2, $3, $4)',
        [course_id, org_id, title, description]
      );
      // Link course to organization in OpenFGA
      await client.query(
        `INSERT INTO outbox_events (event_type, payload) VALUES ($1, $2)`,
        ['COURSE_CREATED', { action: 'WRITE', user: org_id, relation: 'org', object: course_id }]
      );
      await client.query('COMMIT');
      res.status(201).json({ message: 'Course created', course_id });
    } catch (err) {
      await client.query('ROLLBACK');
      res.status(500).json({ error: err.message });
    } finally {
      client.release();
    }
  }
);

app.get('/api/courses/:course_id',
  requireAuth,
  requirePermission('can_view', (req) => req.params.course_id),
  async (req, res) => {
    const { course_id } = req.params;
    const { rows } = await pool.query('SELECT * FROM courses WHERE id = $1', [course_id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Course not found' });
    res.json(rows[0]);
  }
);

// ----------------------------------------------------
// M3: Session Revocation
// ----------------------------------------------------
app.post('/api/auth/revoke-session', requireAuth, async (req, res) => {
  const { sid, sub, exp } = req.user;
  if (!sid) {
    return res.status(400).json({ error: 'Token missing session identifier' });
  }

  const expiresAt = exp ? new Date(exp * 1000) : new Date(Date.now() + 3600000);
  try {
    await pool.query(
      `INSERT INTO revoked_sessions (user_sub, session_id, expires_at)
       VALUES ($1, $2, $3) ON CONFLICT (session_id) DO NOTHING`,
      [sub, sid, expiresAt]
    );
    res.json({ message: 'Session invalidated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------
// M6: Audit Export API
// ----------------------------------------------------
app.get('/api/audit-logs/export', requireAuth, async (req, res) => {
  const format = req.query.format || 'json';
  const { rows } = await pool.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 500');

  if (format === 'csv') {
    const headers = 'id,timestamp,user_sub,org_id,action,resource,decision\n';
    const lines = rows
      .map(r => `"${r.id}","${r.timestamp.toISOString()}","${r.user_sub}","${r.org_id || ''}","${r.action}","${r.resource}","${r.decision}"`)
      .join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="audit_logs.csv"');
    return res.send(headers + lines);
  }

  res.json(rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});