const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function seed() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    console.log('Seeding initial organizations and users...');

    const orgId = 'organization:acme';
    const aliceSub = 'alice-sub-123';
    const bobSub = 'bob-sub-456';
    const courseId = 'course:cs101';

    // 1. Orgs
    await client.query(
      `INSERT INTO organizations (id, name, domain, is_active)
       VALUES ($1, 'Acme Corp', 'acme.edu', TRUE)
       ON CONFLICT (id) DO NOTHING`,
      [orgId]
    );

    // 2. Users
    await client.query(
      `INSERT INTO user_profiles (sub, email, first_name, last_name)
       VALUES ($1, 'alice@acme.edu', 'Alice', 'Admin'),
              ($2, 'bob@acme.edu', 'Bob', 'Learner')
       ON CONFLICT (sub) DO NOTHING`,
      [aliceSub, bobSub]
    );

    // 3. Outbox Tuples
    await client.query(
      `INSERT INTO outbox_events (event_type, payload) VALUES
       ('TENANT_ACTIVE', '{"action": "WRITE", "user": "user:*", "relation": "tenant_active", "object": "organization:acme"}'),
       ('ROLE_ADMIN', '{"action": "WRITE", "user": "user:alice-sub-123", "relation": "admin", "object": "organization:acme"}'),
       ('ROLE_LEARNER', '{"action": "WRITE", "user": "user:bob-sub-456", "relation": "learner", "object": "organization:acme"}'),
       ('COURSE_BIND', '{"action": "WRITE", "user": "organization:acme", "relation": "org", "object": "course:cs101"}')`
    );

    // 4. Course Entry
    await client.query(
      `INSERT INTO courses (id, org_id, title, description)
       VALUES ($1, $2, 'Introduction to Cryptology', 'Fundamentals of block ciphers')
       ON CONFLICT (id) DO NOTHING`,
      [courseId, orgId]
    );

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