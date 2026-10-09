// Seeds tenant memberships for the demo users defined in the Keycloak realm.
// Run:  docker compose exec gateway node scripts/seed.js
import { init, write, check } from '../src/fga.js';

// These ids are the fixed Keycloak user ids from keycloak/realm/multitenant-realm.json
const ALICE = '11111111-1111-4111-8111-111111111111';
const BOB = '22222222-2222-4222-8222-222222222222';
const CAROL = '33333333-3333-4333-8333-333333333333';

await init();

await write([
  { user: `user:${ALICE}`, relation: 'admin', object: 'tenant:acme' },
  { user: `user:${BOB}`, relation: 'member', object: 'tenant:acme' },
  { user: `user:${CAROL}`, relation: 'admin', object: 'tenant:globex' },
]);

console.log('alice member of acme  :', await check(`user:${ALICE}`, 'member', 'tenant:acme'));
console.log('bob   member of acme  :', await check(`user:${BOB}`, 'member', 'tenant:acme'));
console.log('carol member of acme  :', await check(`user:${CAROL}`, 'member', 'tenant:acme'));
console.log('carol member of globex:', await check(`user:${CAROL}`, 'member', 'tenant:globex'));
