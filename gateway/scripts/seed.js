// gateway/scripts/seed.js
const { Pool } = require('pg');
const { Client } = require('pg');
require('dotenv').config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const FGA_API_URL = process.env.FGA_API_URL || 'http://openfga:8080';
const FGA_STORE_ID = process.env.FGA_STORE_ID;

const KC_INTERNAL_URL = process.env.KEYCLOAK_URL || 'http://keycloak:8081';
const KC_ADMIN_URL = process.env.KEYCLOAK_ADMIN_URL || 'http://keycloak:8081';
const KC_ADMIN_USER = process.env.KEYCLOAK_ADMIN || 'admin';
const KC_ADMIN_PASS = process.env.KEYCLOAK_ADMIN_PASSWORD || 'adminpassword';
const REALM = process.env.KEYCLOAK_REALM || 'dat';

// 🔴 Username → sub resolution: do not assume the realm JSON's `id` field survives import.
async function getAdminToken() {
  const res = await fetch(`${KC_ADMIN_URL}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: KC_ADMIN_USER,
      password: KC_ADMIN_PASS,
    }).toString(),
  });
  if (!res.ok) throw new Error(`admin token failed: ${res.status} ${await res.text()}`);
  return (await res.json()).access_token;
}

async function fetchSubByUsername(adminToken, username) {
  const res = await fetch(`${KC_ADMIN_URL}/admin/realms/${REALM}/users?username=${encodeURIComponent(username)}&exact=true`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  if (!res.ok) throw new Error(`lookup ${username} failed: ${res.status}`);
  const users = await res.json();
  if (users.length === 0) throw new Error(`user ${username} not found in realm ${REALM}`);
  return users[0].id;   // ← the actual sub claim
}

const USERS = [
  { username: 'master', email: 'master@platform.local', first: 'Platform', last: 'Admin', role: 'super_admin' },
  { username: 'alice',  email: 'alice@acme.edu',  first: 'Alice', last: 'Admin' },
  { username: 'bob',    email: 'bob@acme.edu',    first: 'Bob',   last: 'Learner' },
  { username: 'carol',  email: 'carol@acme.edu',  first: 'Carol', last: 'Instructor' },
  { username: 'dave',   email: 'dave@globex.com', first: 'Dave',  last: 'Outsider' },
];

const ORGS = [
  {
    id: 'organization:acme', name: 'Acme Corp', domain: 'acme.edu',
    members: [
      ['alice', 'admin'],
      ['carol', 'instructor'],
      ['bob',   'learner'],
    ],
    courses: [
      ['course:cs101', 'Introduction to Cryptology', 'Fundamentals of block ciphers'],
      ['course:cs201', 'Applied Key Management', 'Rotation, escrow and HSMs'],
    ],
  },
  {
    id: 'organization:globex', name: 'Globex Institute', domain: 'globex.com',
    members: [['dave', 'admin']],
    courses: [['course:gx100', 'Globex Onboarding', 'Internal training for Globex staff']],
  },
];

async function writeFgaTupleDirectly(user, relation, object) {
  if (!FGA_STORE_ID) { console.warn('no FGA_STORE_ID'); return; }
  const res = await fetch(`${FGA_API_URL}/stores/${FGA_STORE_ID}/write`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ writes: { tuple_keys: [{ user, relation, object }] } }),
  });
  if (!res.ok) {
    const text = await res.text();
    if (!text.includes('already exists')) console.error(`tuple fail ${user} ${relation} ${object}:`, text);
  }
}

async function seed() {
  // 1. Wait for DB
  const client = await pool.connect();
  let retries = 30;
  while (retries-- > 0) {
    try { await client.query('SELECT 1 FROM user_profiles LIMIT 1'); break; }
    catch (e) { if (e.code === '42P01') { await new Promise(r => setTimeout(r, 1000)); } else throw e; }
  }
  if (retries <= 0) throw new Error('db tables not ready');

  // 2. Resolve real subs from Keycloak
  console.log('resolving subs from Keycloak admin API...');
  const adminToken = await getAdminToken();
  const subByUsername = {};
  for (const u of USERS) {
    subByUsername[u.username] = await fetchSubByUsername(adminToken, u.username);
    console.log(`  ${u.username} → ${subByUsername[u.username]}`);
  }

  // 3. Seed profiles + tuples
  await client.query('BEGIN');
  for (const u of USERS) {
    const sub = subByUsername[u.username];
    await client.query(
      `INSERT INTO user_profiles (sub, email, first_name, last_name)
       VALUES ($1, $2, $3, $4) ON CONFLICT (sub) DO NOTHING`,
      [sub, u.email, u.first, u.last],
    );
  }

  const masterSub = subByUsername.master;
  console.log(`assigning super_admin on platform:root to user:${masterSub}`);
  await writeFgaTupleDirectly(`user:${masterSub}`, 'super_admin', 'platform:root');

  for (const org of ORGS) {
    await client.query(
      `INSERT INTO organizations (id, name, domain, is_active) VALUES ($1, $2, $3, TRUE) ON CONFLICT DO NOTHING`,
      [org.id, org.name, org.domain],
    );
    await writeFgaTupleDirectly('platform:root', 'platform', org.id);
    await writeFgaTupleDirectly('user:*', 'tenant_active', org.id);

    for (const [username, role] of org.members) {
      const sub = subByUsername[username];
      await client.query(
        `INSERT INTO tenant_memberships (user_sub, org_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
        [sub, org.id, role],
      );
      await writeFgaTupleDirectly(`user:${sub}`, role, org.id);
    }

    for (const [id, title, description] of org.courses) {
      await client.query(
        `INSERT INTO courses (id, org_id, title, description) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
        [id, org.id, title, description],
      );
      await writeFgaTupleDirectly(org.id, 'org', id);
    }
  }

  await client.query('COMMIT');
  console.log('seed complete');
  client.release();
  await pool.end();
}

seed().catch((e) => { console.error('seed failed:', e); process.exit(1); });