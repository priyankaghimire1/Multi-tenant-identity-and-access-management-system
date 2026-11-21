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

async function checkRelation(user, relation, objectId, contextualTuples = []) {
  try {
    const result = await fgaClient.check({
      user,
      relation,
      object: objectId,
    });

    console.log('[OpenFGA check]', {
      user,
      relation,
      object: objectId,
      allowed: result.allowed,
    });

    return result.allowed === true;
  } catch (error) {
    console.error('[OpenFGA check failed]', {
      user,
      relation,
      object: objectId,
      message: error.message,
      status: error.statusCode,
      response: error.response?.data,
    });

    throw error;
  }
}


async function checkPermission(userSub, relation, objectId, contextualTuples = []) {
  return checkRelation(`user:${userSub}`, relation, objectId, contextualTuples);
}

/**
 * Background worker to consume transactional outbox events and mirror them to OpenFGA
 *
 * NOTE: The @openfga/sdk requires the `{ writes: { tuple_keys: [...] } }` /
 * `{ deletes: { tuple_keys: [...] } }` envelope. Calling `writeTuples([...])`
 * or `deleteTuples([...])` with a bare array does NOT work — it silently
 * no-ops, which is why tuples were never being mirrored before.
 */
let outboxRunning = false;

async function processOutboxQueue() {
  if (outboxRunning) return;          // never overlap runs
  outboxRunning = true;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');      // SKIP LOCKED only works inside a transaction
    const { rows: events } = await client.query(
      `SELECT id, payload FROM outbox_events
        WHERE processed = FALSE ORDER BY created_at ASC LIMIT 25
        FOR UPDATE SKIP LOCKED`
    );

    for (const event of events) {
      const { action, user, relation, object } = event.payload;
      const tuple = { user, relation, object };
      try {
        if (action === 'WRITE') await fgaClient.write({ writes: [tuple] });
        else if (action === 'DELETE') await fgaClient.write({ deletes: [tuple] });
        else throw new Error(`unknown action: ${action}`);
      } catch (err) {
        const text = [
          err.message,
          err.apiErrorMessage,
          JSON.stringify(err.responseData || err.response?.data || ''),
        ].join(' ');
        const benign =
          (action === 'WRITE' && /already exist/i.test(text)) ||
          (action === 'DELETE' && /does not exist/i.test(text));
        if (!benign) {
          console.error(`[Outbox] FAILED ${action} ${user} ${relation} ${object}:`, text);
          continue;                   // stays unprocessed, so it retries
        }
        console.log(`[Outbox] Already in desired state: ${action} ${user} ${relation} ${object}`);
      }
      await client.query('UPDATE outbox_events SET processed = TRUE WHERE id = $1', [event.id]);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[Outbox] worker error:', err);
  } finally {
    client.release();
    outboxRunning = false;
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