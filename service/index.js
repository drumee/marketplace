const { resolve } = require('path');
const { Mfs } = require('@drumee/server-core');
const { sysEnv, Attr, Permission, Constants } = require('@drumee/server-essentials');
const { template } = require('lodash');
const Jwt = require('jsonwebtoken'); // Make sure this is installed

const { credential_dir } = sysEnv();
const keyPath = resolve(credential_dir, 'crypto/secret.json');
const { readFileSync } = require('jsonfile');
const { onlyoffice: oo_secret, drumee: drumee_secret } = readFileSync(keyPath);
const {
  ORIGINAL,
} = Constants;

class OnlyOffice extends Mfs {

  /**
 *
 */
  async sendHtml(data) {
    const { main_domain } = sysEnv()
    const { readFileSync } = require('fs');
    const tpl = resolve(__dirname, 'templates/index.html');
    let html = readFileSync(tpl);
    html = String(html).trim().toString();
    const content = template(html)(data);

    this.output.set_header("Access-Control-Allow-Origin", `*.${main_domain}`);
    this.output.set_header("Pragma", "no-cache");
    this.output.html(content);
  }

  /**
   * 
   */
  async html() {
    const nid = this.input.get(Attr.nid)
    const uid = this.uid;
    const hub_id = this.input.get(Attr.hub_id)
    const socket_id = this.input.get(Attr.socket_id)
    const { filename, extension, privilege } = this.granted_node();


    // Generate unique session key
    const sessionKey = `${nid}_${Date.now()}`;

    // Generate signed URLs for ONLYOFFICE
    const documentUrl = this.generateSignedUrl(nid, hub_id, sessionKey);
    const callbackUrl = this.generateSignedUrl(nid, hub_id, sessionKey, 'write');

    // Get user info
    const firstname = await this.user.get(Attr.firstname);

    // Return the configuration
    const confObject = {
      document: {
        fileType: extension,
        key: sessionKey,
        title: filename,
        url: documentUrl,
        documentType: "word"
      },
      editorConfig: {
        mode: privilege & Permission.write ? 'edit' : 'view',
        callbackUrl: callbackUrl,
        user: {
          id: uid,
          name: firstname
        }
      },
      documentServerUrl: 'https://oo.drumee.io'
    };

    // Sign the ENTIRE config as the token
    const token = Jwt.sign(
      confObject,
      oo_secret
    );

    // Add token to config sent to frontend
    confObject.token = token;

    this.sendHtml(confObject)
  }

  /**
   * 
   * @param {*} nid 
   * @param {*} hub_id 
   * @param {*} sessionKey 
   * @returns 
   */
  generateSignedUrl(nid, hub_id, sessionKey, method = 'read') {
    const signature = require('crypto')
      .createHmac('sha256', drumee_secret)
      .update(`${this.uid}:${nid}:${hub_id}:${sessionKey}`)
      .digest('hex');
    return `${this.input.homepath()}svc/onlyoffice.${method}?uid=${this.uid}&nid=${nid}&hub_id=${hub_id}&sessionKey=${sessionKey}&signature=${signature}`;
  }

  /**
   * 
   * @param {*} sessionKey 
   * @returns 
   */
  async read() {
    const authHeader = this.input.headers()['authorization'];
    const token = authHeader.substring(7);
    this.debug("AAA:90", token)
    try {
      // Verify the token and extract payload
      const decoded = Jwt.verify(token, oo_secret);
      let p = new URL(decoded.payload.url).searchParams
      // The token payload contains the URL being requested
      // You can log or validate against this URL
      console.log('Token payload:', p);
      let uid = p.get(Attr.uid)
      let nid = p.get(Attr.nid)
      let hub_id = p.get(Attr.hub_id)
      let sessionKey = p.get('sessionKey')
      let args = `${uid}:${nid}:${hub_id}:${sessionKey}`;
      const signature = require('crypto')
        .createHmac('sha256', drumee_secret)
        .update(args)
        .digest('hex');
      // Extract session info if available in token
      this.debug("AAA122", args, signature, p.get('signature'))
      if (!p.get('signature') || p.get('signature') != signature) {
        console.error('Invalid signature', p, args);
        return this.exception.unauthorized("Permission denied")
      }
      const db_name = await this.yp.await_func("get_db_name", hub_id)
      let node = await this.yp.await_proc(`${db_name}.mfs_access_node`, uid, nid);
      this.debug("AAAA:1313", node)
      if (node.privilege & Permission.read) {
        await this.send_media(node, ORIGINAL);
      }else{
        return this.exception.unauthorized("Permission denied")
      }
    } catch (jwtError) {
      console.error('JWT validation failed:', jwtError.message);
      return this.exception.unauthorized("Invalid authorization token")
    }
  }


  /**
   * 
   * @param {*} sessionKey 
   * @returns 
   */
  async generateCallbackUrl(sessionKey) {
    const token = require('jsonwebtoken').sign(
      { sessionKey },
      oo_secret,
      { expiresIn: '1h' }
    );

    return `${this.input.homepath()}svc/onlyoffice.write?nid=${nid}&hub_id=${hub_id}&signature=${signature}`;
  }


  /**
   * 
   * @param {*} ctx 
   */
  async handleCallback(ctx) {
    try {
      const { token } = ctx.request.query;
      const { status, url, key } = ctx.request.body;

      // Verify token and get session
      const { sessionKey } = require('jsonwebtoken').verify(token, oo_secret);

      // Get session from database
      const session = await this.drumee.db.collection('onlyoffice_sessions').findOne({
        key: sessionKey
      });

      if (!session) {
        ctx.throw(404, 'Session not found');
      }

      // Handle different save statuses
      if (status === 2 || status === 6) {
        // Document ready for saving - download it
        const response = await require('axios')({
          method: 'GET',
          url: url,
          responseType: 'stream'
        });

        // Save to Drumee filesystem
        await this.drumee.file.write(session.nid, response.data, {
          metadata: {
            savedBy: session.uid,
            savedAt: new Date(),
            sessionId: sessionKey
          }
        });

        // Update session status
        await this.drumee.db.collection('onlyoffice_sessions').update(
          { key: sessionKey },
          { $set: { savedAt: new Date(), status: 'saved' } }
        );
      }

      ctx.body = { error: 0 };
    } catch (error) {
      console.error('Callback error:', error);
      ctx.body = { error: 1, message: error.message };
    }
  }
}

module.exports = OnlyOffice;