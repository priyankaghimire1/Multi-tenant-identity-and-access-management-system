const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Subjects match the fixed user ids in keycloak/realm/multitenant-realm.json
const USERS = [
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

async function seed() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    console.log('Seeding organizations, users, memberships and courses...');

    for (const u of USERS) {
      await client.query(
        `INSERT INTO user_profiles (sub, email, first_name, last_name)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
        [u.sub, u.email, u.first, u.last]
      );
    }

    const outbox = (type, payload) =>
      client.query('INSERT INTO outbox_events (event_type, payload) VALUES ($1, $2)', [type, payload]);

    for (const org of ORGS) {
      const inserted = await client.query(
        `INSERT INTO organizations (id, name, domain, is_active)
         VALUES ($1, $2, $3, TRUE) ON CONFLICT DO NOTHING RETURNING id`,
        [org.id, org.name, org.domain]
      );
      if (inserted.rowCount === 0) {
        console.log(`${org.id} already seeded, skipping`);
        continue; // re-running must not enqueue duplicate tuple writes
      }

      await outbox('TENANT_ACTIVE', {
        action: 'WRITE', user: 'user:*', relation: 'tenant_active', object: org.id
      });

      for (const [sub, role] of org.members) {
        await client.query(
          'INSERT INTO tenant_memberships (user_sub, org_id, role) VALUES ($1, $2, $3)',
          [sub, org.id, role]
        );
        await outbox('ROLE_' + role.toUpperCase(), {
          action: 'WRITE', user: `user:${sub}`, relation: role, object: org.id
        });
      }

      for (const [id, title, description] of org.courses) {
        await client.query(
          'INSERT INTO courses (id, org_id, title, description) VALUES ($1, $2, $3, $4)',
          [id, org.id, title, description]
        );
        await outbox('COURSE_BIND', {
          action: 'WRITE', user: org.id, relation: 'org', object: id
        });
      }
    }

    await client.query('COMMIT');
    console.log('Database seeded successfully.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Seed failed:', err);
  } finally {
    client.release();
    pool.end();
  }
}

seed();