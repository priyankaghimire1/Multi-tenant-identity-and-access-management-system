// gateway/scripts/seed.js
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const FGA_API_URL = process.env.FGA_API_URL || 'http://openfga:8080';
const FGA_STORE_ID = process.env.FGA_STORE_ID;
const SUPER_ADMIN_SUB = process.env.SUPER_ADMIN_SUB || 'super-admin-000';

// Subjects match the fixed user ids in keycloak/realm/multitenant-realm.json
const USERS = [
  { sub: 'super-admin-000', email: 'master@platform.local', first: 'Platform', last: 'Admin' },
  { sub: 'alice-sub-123', email: 'alice@acme.edu', first: 'Alice', last: 'Admin' },
  { sub: 'bob-sub-456', email: 'bob@acme.edu', first: 'Bob', last: 'Learner' },
  { sub: 'carol-sub-789', email: 'carol@acme.edu', first: 'Carol', last: 'Instructor' },
  { sub: 'dave-sub-012', email: 'dave@globex.com', first: 'Dave', last: 'Outsider' }
];

const ORGS = [
  {
    id: 'organization:acme', name: 'Acme Corp', domain: 'acme.edu',
    members: [
      ['alice-sub-123', 'admin'],
      ['carol-sub-789', 'instructor'],
      ['bob-sub-456', 'learner']
    ],
    courses: [
      ['course:cs101', 'Introduction to Cryptology', 'Fundamentals of block ciphers'],
      ['course:cs201', 'Applied Key Management', 'Rotation, escrow and HSMs']
    ]
  },
  {
    id: 'organization:globex', name: 'Globex Institute', domain: 'globex.com',
    members: [['dave-sub-012', 'admin']],
    courses: [['course:gx100', 'Globex Onboarding', 'Internal training for Globex staff']]
  }
];

// Helper to write tuples directly to OpenFGA
async function writeFgaTupleDirectly(user, relation, object) {
  if (!FGA_STORE_ID) {
    console.warn("No FGA_STORE_ID set, skipping direct OpenFGA write.");
    return;
  }
  const res = await fetch(`${FGA_API_URL}/stores/${FGA_STORE_ID}/write`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      writes: { tuple_keys: [{ user, relation, object }] }
    })
  });
  if (!res.ok) {
    const text = await res.text();
    // Ignore "already exists" errors on multiple runs
    if (!text.includes('already exists')) {
      console.error(`Failed to write tuple ${user} ${relation} ${object}:`, text);
    }
  }
}

async function seed() {
  const client = await pool.connect();
  try {
    // Wait for the database tables to be created by init.sql
    let retries = 30;
    while (retries > 0) {
      try {
        await client.query('SELECT 1 FROM user_profiles LIMIT 1');
        break; // It worked! Tables exist.
      } catch (err) {
        if (err.code === '42P01') { // Undefined table
          console.log('Waiting for database tables (init.sql)...');
          await new Promise(r => setTimeout(r, 1000));
          retries--;
        } else {
          throw err;
        }
      }
    }
    if (retries === 0) throw new Error('Database tables not found after 30s');

    await client.query('BEGIN');
    console.log('Seeding database and OpenFGA...');

    // 1. User profiles (idempotent)
    for (const u of USERS) {
      await client.query(
        `INSERT INTO user_profiles (sub, email, first_name, last_name)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
        [u.sub, u.email, u.first, u.last]
      );
    }

    // 2. Seed super_admin directly to OpenFGA
    console.log(`Assigning super_admin on platform:root to user:${SUPER_ADMIN_SUB}`);
    await writeFgaTupleDirectly(`user:${SUPER_ADMIN_SUB}`, 'super_admin', 'platform:root');

    // 3. Organizations, platform links, members, courses
    for (const org of ORGS) {
      await client.query(
        `INSERT INTO organizations (id, name, domain, is_active)
         VALUES ($1, $2, $3, TRUE) ON CONFLICT DO NOTHING`,
        [org.id, org.name, org.domain]
      );

      await writeFgaTupleDirectly('platform:root', 'platform', org.id);
      await writeFgaTupleDirectly('user:*', 'tenant_active', org.id);

      for (const [sub, role] of org.members) {
        await client.query(
          `INSERT INTO tenant_memberships (user_sub, org_id, role)
           VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
          [sub, org.id, role]
        );
        await writeFgaTupleDirectly(`user:${sub}`, role, org.id);
      }

      for (const [id, title, description] of org.courses) {
        await client.query(
          `INSERT INTO courses (id, org_id, title, description)
           VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
          [id, org.id, title, description]
        );
        await writeFgaTupleDirectly(org.id, 'org', id);
      }
    }

    await client.query('COMMIT');
    console.log('Seed complete. All tuples written directly to OpenFGA.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Seed failed:', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

seed();