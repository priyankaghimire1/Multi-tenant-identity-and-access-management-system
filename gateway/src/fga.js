import { readFile } from 'node:fs/promises';

const API_URL = process.env.FGA_API_URL;
const API_KEY = process.env.FGA_API_KEY;
const STORE_NAME = process.env.FGA_STORE_NAME || 'multitenant-iam';

let storeId = null;
let modelId = null;

async function call(method, path, body) {
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${API_KEY}`,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = new Error(`OpenFGA ${method} ${path} -> ${res.status} ${text}`);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Find-or-create the store and make sure an authorization model exists. */
export async function init() {
  for (let attempt = 1; ; attempt++) {
    try {
      const { stores } = await call('GET', '/stores');
      let store = stores.find((s) => s.name === STORE_NAME);
      if (!store) store = await call('POST', '/stores', { name: STORE_NAME });
      storeId = store.id;
      break;
    } catch (e) {
      if (attempt >= 20) throw e;
      console.log(`[fga] waiting for OpenFGA (${attempt}): ${e.message}`);
      await sleep(2000);
    }
  }

  const latest = await call(
    'GET',
    `/stores/${storeId}/authorization-models?page_size=1`,
  );
  if (latest.authorization_models?.length) {
    modelId = latest.authorization_models[0].id;
    console.log(`[fga] using existing model ${modelId}`);
  } else {
    const model = JSON.parse(
      await readFile(new URL('../model.json', import.meta.url), 'utf8'),
    );
    const created = await call(
      'POST',
      `/stores/${storeId}/authorization-models`,
      model,
    );
    modelId = created.authorization_model_id;
    console.log(`[fga] created model ${modelId}`);
  }
  console.log(`[fga] store ${storeId} ready`);
}

/** Replace the model with the contents of model.json (used after you edit it). */
export async function pushModel() {
  const model = JSON.parse(
    await readFile(new URL('../model.json', import.meta.url), 'utf8'),
  );
  const created = await call(
    'POST',
    `/stores/${storeId}/authorization-models`,
    model,
  );
  modelId = created.authorization_model_id;
  return modelId;
}

export async function check(user, relation, object) {
  const res = await call('POST', `/stores/${storeId}/check`, {
    authorization_model_id: modelId,
    tuple_key: { user, relation, object },
  });
  return res.allowed === true;
}

export async function write(tuples) {
  try {
    await call('POST', `/stores/${storeId}/write`, {
      authorization_model_id: modelId,
      writes: { tuple_keys: tuples },
    });
  } catch (e) {
    // Writing a tuple that already exists is fine (seed is re-runnable)
    if (e.body?.code === 'write_failed_due_to_invalid_input' &&
        /already exist/i.test(e.body?.message || '')) return;
    throw e;
  }
}

export const getStoreId = () => storeId;
