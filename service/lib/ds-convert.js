const { request } = require('https');
const Jwt = require('jsonwebtoken');

/**
 * Convert a document through the document server's conversion service and return
 * the URL of the converted file (or null on failure).
 *
 * Binary MS formats (.xls/.doc/.ppt) cannot be co-edited: opening one directly
 * makes the editor convert it to OOXML in its cache, notice the config still
 * declares the legacy type, and loop "version changed / reload" forever. The
 * integration must convert up front and open the native file instead — exactly
 * how Word/Google upgrade a legacy file on open.
 *
 * @param {string} documentServerUrl e.g. https://euroffice.drumee.io
 * @param {object} payload { filetype, outputtype, key, title, url }
 * @param {string} secret EurOffice JWT secret
 * @param {number} timeoutMs per-request timeout
 * @returns {Promise<string|null>} fileUrl of the converted document, or null
 */
async function convertDocument(documentServerUrl, payload, secret, timeoutMs = 20000) {
  let target;
  try {
    target = new URL('/converter', documentServerUrl);
  } catch (e) {
    return null;
  }

  const post = (body) => new Promise((resolvePromise, rejectPromise) => {
    const json = JSON.stringify(body);
    const req = request(target, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Content-Length': Buffer.byteLength(json),
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try { resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { rejectPromise(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('conversion timed out')));
    req.on('error', rejectPromise);
    req.end(json);
  });

  // async:false asks the server to block until done, but a large file can still
  // come back as {percent, endConvert:false} — poll a few times before giving up.
  for (let attempt = 0; attempt < 6; attempt++) {
    const body = { ...payload, async: false };
    body.token = Jwt.sign(body, secret);
    const reply = await post(body);
    if (reply && reply.error) return null;
    if (reply && reply.endConvert && reply.fileUrl) return reply.fileUrl;
    // brief spin without a timer dependency
    await new Promise((r) => setImmediate(r));
  }
  return null;
}

module.exports = { convertDocument };
