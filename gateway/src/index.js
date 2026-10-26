const express = require('express');
const cors = require('cors');
const path = require('path');
const { pool, checkPermission, checkRelation } = require('./fga');
const { requireAuth, requirePermission, recordAudit } = require('./auth');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ----------------------------------------------------
// Helpers
// ----------------------------------------------------
const ROLES = ['admin', 'instructor', 'learner'];
const ORG_ID_RE = /^organization:[a-z0-9_-]{2,64}$/;
const COURSE_ID_RE = /^course:[a-z0-9_-]{2,64}$/;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Express 4 does not catch rejected promises from async handlers.
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((err) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    if (err && err.code === '23505') return res.status(409).json({ error: 'Already exists' });
    if (err && err.code === '23503') return res.status(404).json({ error: 'Referenced record not found' });
    console.error(err);
    return res.status(500).json({ error: 'Internal error' });
  });

async function withTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Every OpenFGA tuple change goes through the transactional outbox (see fga.js worker).
function outbox(client, eventType, payload) {
  return client.query('INSERT INTO outbox_events (event_type, payload) VALUES ($1, $2)', [
    eventType,
    payload
  ]);
}

async function ensureProfile(user) {
  const email = user.email || `${user.preferred_username || user.sub}@users.local`;
  await pool.query(
    `INSERT INTO user_profiles (sub, email, first_name, last_name)
     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
    [user.sub, email, user.given_name || null, user.family_name || null]
  );
}

// Guard against locking an organization out of its last active admin.
async function assertNotLastAdmin(client, org_id, user_sub) {
  const { rows } = await client.query(
    `SELECT user_sub FROM tenant_memberships
      WHERE org_id = $1 AND role = 'admin' AND is_suspended = FALSE`,
    [org_id]
  );
  const others = rows.filter((r) => r.user_sub !== user_sub);
  if (others.length === 0) {
    throw new HttpError(409, 'This would leave the organization without an active admin');
  }
}

const orgFromParams = (req) => req.params.org_id;

// ----------------------------------------------------
// M1 & M5: Organization Provisioning & Suspension
// ----------------------------------------------------
app.post('/api/orgs', requireAuth, wrap(async (req, res) => {
  const { org_id, name, domain } = req.body || {};
  if (typeof org_id !== 'string' || !ORG_ID_RE.test(org_id) || !name || !domain) {
    throw new HttpError(400, 'org_id (organization:<slug>), name and domain are required');
  }
  await ensureProfile(req.user);

  await withTx(async (client) => {
    await client.query(
      'INSERT INTO organizations (id, name, domain, is_active) VALUES ($1, $2, $3, TRUE)',
      [org_id, name, domain]
    );
    // The creator becomes the first admin of the new tenant.
    await client.query(
      "INSERT INTO tenant_memberships (user_sub, org_id, role) VALUES ($1, $2, 'admin')",
      [req.user.sub, org_id]
    );
    await outbox(client, 'TENANT_PROVISIONED', {
      action: 'WRITE', user: 'user:*', relation: 'tenant_active', object: org_id
    });
    await outbox(client, 'MEMBERSHIP_ASSIGNED', {
      action: 'WRITE', user: `user:${req.user.sub}`, relation: 'admin', object: org_id
    });
  });

  res.status(201).json({ message: 'Tenant organization registered', org_id });
}));

// Instant tenant-wide kill switch: removes wildcard tenant_active
app.patch('/api/orgs/:org_id/suspend',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const { org_id } = req.params;
    await withTx(async (client) => {
      const r = await client.query(
        'UPDATE organizations SET is_active = FALSE WHERE id = $1 AND is_active = TRUE',
        [org_id]
      );
      if (r.rowCount === 0) throw new HttpError(409, 'Organization not found or already suspended');
      await outbox(client, 'TENANT_SUSPENDED', {
        action: 'DELETE', user: 'user:*', relation: 'tenant_active', object: org_id
      });
    });
    res.json({ message: `Tenant ${org_id} suspended across platform` });
  })
);

// ----------------------------------------------------
// Dashboard: who am I, and what can I do in each organization?
// ----------------------------------------------------
app.get('/api/me', requireAuth, wrap(async (req, res) => {
  await ensureProfile(req.user);
  const { rows } = await pool.query(
    `SELECT m.org_id, o.name, m.role, m.is_suspended, o.is_active
       FROM tenant_memberships m
       JOIN organizations o ON o.id = m.org_id
      WHERE m.user_sub = $1
      ORDER BY o.name`,
    [req.user.sub]
  );
  res.json({
    user: {
      sub: req.user.sub,
      email: req.user.email || null,
      name: req.user.name || req.user.preferred_username || null,
      session_id: req.user.sid || null
    },
    orgs: rows
  });
}));

app.get('/api/orgs/:org_id/overview', requireAuth, wrap(async (req, res) => {
  const { org_id } = req.params;
  const sub = req.user.sub;

  const [orgRes, memRes] = await Promise.all([
    pool.query('SELECT id, name, domain, is_active FROM organizations WHERE id = $1', [org_id]),
    pool.query('SELECT role, is_suspended FROM tenant_memberships WHERE user_sub = $1 AND org_id = $2', [sub, org_id])
  ]);
  const org = orgRes.rows[0];
  const memberships = memRes.rows;
  if (!org || memberships.length === 0) {
    throw new HttpError(403, 'Not a member of this organization');
  }

  // Authoritative decisions come from OpenFGA; the database values are shown alongside
  // so the UI can tell when the outbox has not yet synced a change.
  const [orgAdmin, orgInstructor, orgLearner, fgaSuspended, fgaTenantActive] = await Promise.all([
    checkPermission(sub, 'org_admin', org_id),
    checkPermission(sub, 'org_instructor', org_id),
    checkPermission(sub, 'org_learner', org_id),
    checkPermission(sub, 'suspended', org_id),
    checkPermission(sub, 'tenant_active', org_id)
  ]);
  const role = orgAdmin ? 'admin' : orgInstructor ? 'instructor' : orgLearner ? 'learner' : null;
  const dbSuspended = memberships.some((m) => m.is_suspended);

  let courses = [];
  let stats = null;
  if (role) {
    const { rows } = await pool.query(
      'SELECT id, title, description, created_at FROM courses WHERE org_id = $1 ORDER BY created_at',
      [org_id]
    );
    const checked = await Promise.all(rows.map(async (c) => {
      const [view, edit, del] = await Promise.all([
        checkPermission(sub, 'can_view', c.id),
        checkPermission(sub, 'can_edit', c.id),
        checkPermission(sub, 'can_delete', c.id)
      ]);
      return view ? { ...c, permissions: { view, edit, delete: del } } : null;
    }));
    courses = checked.filter(Boolean);
  }
  if (orgAdmin) {
    const { rows } = await pool.query(
      'SELECT COUNT(*)::int AS n FROM tenant_memberships WHERE org_id = $1',
      [org_id]
    );
    stats = { members: rows[0].n, courses: courses.length };
  }

  await recordAudit(req, 'dashboard_view', org_id, !!role);

  res.json({
    org,
    me: {
      sub,
      roles: memberships.map((m) => m.role),
      role,
      suspended: fgaSuspended,
      tenant_active: fgaTenantActive
    },
    sync: {
      in_sync: dbSuspended === fgaSuspended && org.is_active === fgaTenantActive,
      database: { suspended: dbSuspended, tenant_active: org.is_active },
      openfga: { suspended: fgaSuspended, tenant_active: fgaTenantActive }
    },
    courses,
    stats
  });
}));

// Step-by-step explanation of why the caller can (or cannot) see a course.
app.get('/api/orgs/:org_id/courses/:course_id/trace', requireAuth, wrap(async (req, res) => {
  const { org_id, course_id } = req.params;
  const sub = req.user.sub;

  const mem = await pool.query(
    'SELECT 1 FROM tenant_memberships WHERE user_sub = $1 AND org_id = $2 LIMIT 1',
    [sub, org_id]
  );
  if (mem.rows.length === 0) throw new HttpError(403, 'Not a member of this organization');

  const { rows } = await pool.query(
    'SELECT id, title FROM courses WHERE id = $1 AND org_id = $2',
    [course_id, org_id]
  );
  if (rows.length === 0) throw new HttpError(404, 'Course not found in this organization');

  const u = `user:${sub}`;
  const [isAdmin, isInstructor, isLearner, suspended, tenantActive, bound, canView, canEdit, canDelete] =
    await Promise.all([
      checkRelation(u, 'admin', org_id),
      checkRelation(u, 'instructor', org_id),
      checkRelation(u, 'learner', org_id),
      checkRelation(u, 'suspended', org_id),
      checkRelation(u, 'tenant_active', org_id),
      checkRelation(org_id, 'org', course_id),
      checkRelation(u, 'can_view', course_id),
      checkRelation(u, 'can_edit', course_id),
      checkRelation(u, 'can_delete', course_id)
    ]);

  const roles = [isAdmin && 'admin', isInstructor && 'instructor', isLearner && 'learner'].filter(Boolean);
  const steps = [
    { key: 'authenticated', label: 'Signed in', passed: true,
      detail: 'Token signature, expiry and session revocation list checked.' },
    { key: 'membership', label: 'Role in organization', passed: roles.length > 0,
      detail: roles.length ? `Role: ${roles.join(', ')}` : 'No role relationship found in OpenFGA.' },
    { key: 'not_suspended', label: 'Membership not suspended', passed: !suspended,
      detail: suspended ? 'A suspended relationship exists for this user.' : 'No suspension recorded.' },
    { key: 'tenant_active', label: 'Tenant active', passed: tenantActive,
      detail: tenantActive ? 'Organization is active.' : 'Organization is suspended.' },
    { key: 'ownership', label: 'Course belongs to organization', passed: bound,
      detail: bound ? `Course is bound to ${org_id}.` : 'No ownership relationship between this course and the organization.' },
    { key: 'policy_view', label: 'Policy: can view', passed: canView, detail: 'org_member from org' },
    { key: 'policy_edit', label: 'Policy: can edit', passed: canEdit, detail: 'org_instructor or org_admin from org' },
    { key: 'policy_delete', label: 'Policy: can delete', passed: canDelete, detail: 'org_admin from org' }
  ];

  await recordAudit(req, 'trace', course_id, canView);
  res.json({ course: rows[0], steps, decision: { view: canView, edit: canEdit, delete: canDelete } });
}));

// ----------------------------------------------------
// M4: Role Management & User Suspension (org admins only)
// ----------------------------------------------------
app.get('/api/orgs/:org_id/members',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT m.user_sub, p.email, p.first_name, p.last_name, m.role, m.is_suspended, m.created_at
         FROM tenant_memberships m
         JOIN user_profiles p ON p.sub = m.user_sub
        WHERE m.org_id = $1
        ORDER BY p.email`,
      [req.params.org_id]
    );
    res.json(rows);
  })
);

app.post('/api/orgs/:org_id/memberships',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const { org_id } = req.params;
    const { user_sub, email, role } = req.body || {};
    if (!ROLES.includes(role)) throw new HttpError(400, `role must be one of: ${ROLES.join(', ')}`);

    let sub = user_sub;
    if (!sub && email) {
      const { rows } = await pool.query('SELECT sub FROM user_profiles WHERE lower(email) = lower($1)', [email]);
      sub = rows[0] && rows[0].sub;
    }
    if (!sub) throw new HttpError(404, 'User not found. They must sign in once before they can be added.');

    await withTx(async (client) => {
      const existing = await client.query(
        'SELECT role FROM tenant_memberships WHERE user_sub = $1 AND org_id = $2',
        [sub, org_id]
      );
      if (existing.rows.length > 0) {
        throw new HttpError(409, `Already a member (${existing.rows[0].role}). Change their role instead.`);
      }
      await client.query(
        'INSERT INTO tenant_memberships (user_sub, org_id, role) VALUES ($1, $2, $3)',
        [sub, org_id, role]
      );
      await outbox(client, 'MEMBERSHIP_ASSIGNED', {
        action: 'WRITE', user: `user:${sub}`, relation: role, object: org_id
      });
    });
    res.status(201).json({ message: `Role ${role} granted to ${sub}` });
  })
);

app.patch('/api/orgs/:org_id/members/:user_sub/role',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const { org_id, user_sub } = req.params;
    const { role } = req.body || {};
    if (!ROLES.includes(role)) throw new HttpError(400, `role must be one of: ${ROLES.join(', ')}`);

    const changed = await withTx(async (client) => {
      const { rows } = await client.query(
        'SELECT role, is_suspended FROM tenant_memberships WHERE user_sub = $1 AND org_id = $2 FOR UPDATE',
        [user_sub, org_id]
      );
      if (rows.length === 0) throw new HttpError(404, 'Member not found');

      const current = rows.map((r) => r.role);
      if (current.length === 1 && current[0] === role) return false;

      if (current.includes('admin') && role !== 'admin') {
        await assertNotLastAdmin(client, org_id, user_sub);
      }

      for (const old of current) {
        if (old === role) continue;
        await client.query(
          'DELETE FROM tenant_memberships WHERE user_sub = $1 AND org_id = $2 AND role = $3',
          [user_sub, org_id, old]
        );
        await outbox(client, 'ROLE_REVOKED', {
          action: 'DELETE', user: `user:${user_sub}`, relation: old, object: org_id
        });
      }
      if (!current.includes(role)) {
        await client.query(
          'INSERT INTO tenant_memberships (user_sub, org_id, role, is_suspended) VALUES ($1, $2, $3, $4)',
          [user_sub, org_id, role, rows[0].is_suspended]
        );
        await outbox(client, 'ROLE_ASSIGNED', {
          action: 'WRITE', user: `user:${user_sub}`, relation: role, object: org_id
        });
      }
      return true;
    });

    res.json({ message: changed ? `Role changed to ${role}` : 'No change', changed });
  })
);

app.patch('/api/orgs/:org_id/members/:user_sub/suspend',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const { org_id, user_sub } = req.params;
    if (user_sub === req.user.sub) throw new HttpError(400, 'You cannot suspend yourself');

    await withTx(async (client) => {
      const r = await client.query(
        'UPDATE tenant_memberships SET is_suspended = TRUE WHERE user_sub = $1 AND org_id = $2 AND is_suspended = FALSE',
        [user_sub, org_id]
      );
      if (r.rowCount === 0) throw new HttpError(409, 'Member not found or already suspended');
      await outbox(client, 'USER_SUSPENDED', {
        action: 'WRITE', user: `user:${user_sub}`, relation: 'suspended', object: org_id
      });
    });
    res.json({ message: `User ${user_sub} suspended in ${org_id}` });
  })
);

app.patch('/api/orgs/:org_id/members/:user_sub/unsuspend',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const { org_id, user_sub } = req.params;

    await withTx(async (client) => {
      const r = await client.query(
        'UPDATE tenant_memberships SET is_suspended = FALSE WHERE user_sub = $1 AND org_id = $2 AND is_suspended = TRUE',
        [user_sub, org_id]
      );
      if (r.rowCount === 0) throw new HttpError(409, 'Member not found or not suspended');
      await outbox(client, 'USER_REINSTATED', {
        action: 'DELETE', user: `user:${user_sub}`, relation: 'suspended', object: org_id
      });
    });
    res.json({ message: `User ${user_sub} reinstated in ${org_id}` });
  })
);

app.delete('/api/orgs/:org_id/members/:user_sub',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const { org_id, user_sub } = req.params;
    if (user_sub === req.user.sub) throw new HttpError(400, 'You cannot remove yourself');

    await withTx(async (client) => {
      const { rows } = await client.query(
        'SELECT role, is_suspended FROM tenant_memberships WHERE user_sub = $1 AND org_id = $2 FOR UPDATE',
        [user_sub, org_id]
      );
      if (rows.length === 0) throw new HttpError(404, 'Member not found');
      if (rows.some((r) => r.role === 'admin')) {
        await assertNotLastAdmin(client, org_id, user_sub);
      }
      await client.query('DELETE FROM tenant_memberships WHERE user_sub = $1 AND org_id = $2', [user_sub, org_id]);
      for (const r of rows) {
        await outbox(client, 'ROLE_REVOKED', {
          action: 'DELETE', user: `user:${user_sub}`, relation: r.role, object: org_id
        });
      }
      if (rows.some((r) => r.is_suspended)) {
        await outbox(client, 'USER_REINSTATED', {
          action: 'DELETE', user: `user:${user_sub}`, relation: 'suspended', object: org_id
        });
      }
    });
    res.json({ message: `User ${user_sub} removed from ${org_id}` });
  })
);

// ----------------------------------------------------
// Domain Resource APIs (Courses protected by OpenFGA ReBAC)
// ----------------------------------------------------
app.post('/api/courses',
  requireAuth,
  requirePermission('org_admin', (req) => (req.body || {}).org_id),
  wrap(async (req, res) => {
    const { course_id, org_id, title, description } = req.body;
    if (typeof course_id !== 'string' || !COURSE_ID_RE.test(course_id) || !title) {
      throw new HttpError(400, 'course_id (course:<slug>) and title are required');
    }
    await withTx(async (client) => {
      await client.query(
        'INSERT INTO courses (id, org_id, title, description) VALUES ($1, $2, $3, $4)',
        [course_id, org_id, title, description || null]
      );
      // Link course to organization in OpenFGA
      await outbox(client, 'COURSE_CREATED', {
        action: 'WRITE', user: org_id, relation: 'org', object: course_id
      });
    });
    res.status(201).json({ message: 'Course created', course_id });
  })
);

app.get('/api/courses/:course_id',
  requireAuth,
  requirePermission('can_view', (req) => req.params.course_id),
  wrap(async (req, res) => {
    const { course_id } = req.params;
    const { rows } = await pool.query('SELECT * FROM courses WHERE id = $1', [course_id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Course not found' });
    res.json(rows[0]);
  })
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
// M6: Audit Export API (scoped to one organization, admins only)
// ----------------------------------------------------
function csvCell(value) {
  let s = value === null || value === undefined ? '' : String(value);
  // Neutralize spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

app.get('/api/orgs/:org_id/audit-logs',
  requireAuth,
  requirePermission('org_admin', orgFromParams),
  wrap(async (req, res) => {
    const format = req.query.format || 'json';
    const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
    const decision = ['ALLOW', 'DENY'].includes(req.query.decision) ? req.query.decision : null;

    const params = [req.params.org_id];
    let where = 'org_id = $1';
    if (decision) {
      params.push(decision);
      where += ` AND decision = $${params.length}`;
    }
    params.push(limit);
    const { rows } = await pool.query(
      `SELECT id, timestamp, user_sub, org_id, action, resource, decision
         FROM audit_logs WHERE ${where} ORDER BY timestamp DESC LIMIT $${params.length}`,
      params
    );

    if (format === 'csv') {
      const header = 'id,timestamp,user_sub,org_id,action,resource,decision\n';
      const lines = rows
        .map((r) => [r.id, r.timestamp.toISOString(), r.user_sub, r.org_id, r.action, r.resource, r.decision]
          .map(csvCell).join(','))
        .join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="audit_logs.csv"');
      return res.send(header + lines);
    }

    res.json(rows);
  })
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});