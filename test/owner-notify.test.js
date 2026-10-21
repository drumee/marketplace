/**
 * Offline checks for who an office save notifies its owner about
 * (service/lib/owner-notify.js). No database, document server or session:
 *   node test/owner-notify.test.js
 */
const assert = require('assert');
const Module = require('module');

// Stub the private runtime: only toArray and sysEnv are used here.
const realLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === '@drumee/server-essentials') {
    return {
      toArray: (v) => (v == null ? [] : (Array.isArray(v) ? v : [v])),
      sysEnv: () => ({ server_home: '/nonexistent' }),
    };
  }
  return realLoad.call(this, request, ...rest);
};
const { saveParticipants, prepareOfficeSave, notifyOfficeSave } = require('../service/lib/owner-notify');
Module._load = realLoad;

let checks = 0;
async function check(what, fn) { await fn(); checks++; console.log('  ok  ' + what); }

(async () => {
  await check('the authors of the changes, named, deduplicated', () => {
    const data = { history: { changes: [
      { user: { id: 'u1', name: 'Ann' } },
      { user: { id: 'u2', name: 'Bob' } },
      { user: { id: 'u1', name: 'Ann' } },
    ] } };
    assert.deepStrictEqual(saveParticipants(data, 'u9'), [{ id: 'u1', name: 'Ann' }, { id: 'u2', name: 'Bob' }]);
  });
  await check('no history: the saver stands for the changes', () => {
    assert.deepStrictEqual(saveParticipants({}, 'u9'), [{ id: 'u9', name: '' }]);
  });
  await check('anonymous visitors and malformed ids are left out', () => {
    const data = { history: { changes: [
      { user: { id: 'ffffffffffffffff', name: 'Guest' } },
      { user: { id: "x' OR 1", name: 'x' } },
    ] } };
    assert.deepStrictEqual(saveParticipants(data, null), []);
  });
  await check('without the server-team modules nothing happens and nothing throws', async () => {
    const svc = { warn() { throw new Error('should not warn'); } };
    assert.strictEqual(await prepareOfficeSave(svc, { hub_id: 'h', nid: 'n', file: '/nope.docx', ext: 'docx', editors: [{ id: 'u1' }] }), null);
    await notifyOfficeSave(svc, { hub_id: 'h', nid: 'n', prepared: null });
  });
  console.log(`\n${checks} checks passed`);
})().catch((e) => { console.error(e); process.exit(1); });
