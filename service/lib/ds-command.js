const { request } = require('https');
const Jwt = require('jsonwebtoken');

/**
 * POST an order to the document server's Command Service (meta, forcesave, …)
 * and return its parsed JSON reply ({ error: 0 } on success).
 *
 * Deliberately NOT built on @drumee/server-essentials Network.request: its
 * non-outfile path dereferences a block-scoped `chunk` from another handler,
 * so any JSON reply crashes it — and a command needs the reply.
 */
function sendDsCommand(documentServerUrl, payload, secret, timeoutMs = 5000) {
  return new Promise((resolvePromise, rejectPromise) => {
    let target;
    try {
      target = new URL('/coauthoring/CommandService.ashx', documentServerUrl);
    } catch (e) {
      return rejectPromise(e);
    }
    const body = JSON.stringify({ ...payload, token: Jwt.sign(payload, secret) });
    const req = request(target, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (e) {
          rejectPromise(e);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('document server command timed out')));
    req.on('error', rejectPromise);
    req.end(body);
  });
}

module.exports = { sendDsCommand };
