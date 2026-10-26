const { OpenFgaClient } = require('@openfga/sdk');
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const fgaClient = new OpenFgaClient({
  apiUrl: process.env.FGA_API_URL || 'http://localhost:8080',
  storeId: process.env.FGA_STORE_ID,
  authorizationModelId: process.env.FGA_MODEL_ID
});

/**
 * Checks ReBAC permissions in OpenFGA
 */
async function checkRelation(user, relation, objectId) {
  try {
    const { allowed } = await fgaClient.check({
      user,
      relation,
      object: objectId
    });
    return !!allowed;
  } catch (error) {
    console.error('OpenFGA Check Error:', error);
    return false;
  }
}

async function checkPermission(userSub, relation, objectId) {
  return checkRelation(`user:${userSub}`, relation, objectId);
}

/**
 * Background worker to consume transactional outbox events and mirror them to OpenFGA
 */
async function processOutboxQueue() {
  const client = await pool.connect();
  try {
    const { rows: events } = await client.query(
      'SELECT id, payload FROM outbox_events WHERE processed = FALSE ORDER BY created_at ASC LIMIT 25 FOR UPDATE SKIP LOCKED'
    );

    for (const event of events) {
      const { action, user, relation, object } = event.payload;

      if (action === 'WRITE') {
        await fgaClient.writeTuples([{ user, relation, object }]);
      } else if (action === 'DELETE') {
        await fgaClient.deleteTuples([{ user, relation, object }]);
      }

      await client.query('UPDATE outbox_events SET processed = TRUE WHERE id = $1', [event.id]);
    }
  } catch (err) {
    console.error('Outbox sync worker error:', err);
  } finally {
    client.release();
  }
}

// Poll outbox every 1 second
setInterval(processOutboxQueue, 1000);

module.exports = {
  fgaClient,
  checkPermission,
  checkRelation,
  pool
};