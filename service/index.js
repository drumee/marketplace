const { resolve } = require('path');
const { Mfs } = require('@drumee/server-core');
const { Cache, sysEnv, Attr, Permission, Constants, getFileinfo } = require('@drumee/server-essentials');
const { template } = require('lodash');
const Jwt = require('jsonwebtoken'); // Make sure this is installed

const { credential_dir } = sysEnv();
const keyPath = resolve(credential_dir, 'crypto/secret.json');
const { readFileSync } = require('jsonfile');
const { onlyoffice: oo_secret, drumee: drumee_secret } = readFileSync(keyPath);
const {
  ORIGINAL,
  FILESIZE
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
  async checkSanity() {
    const authHeader = this.input.headers()['authorization'];
    const token = authHeader.substring(7);
    try {
      // Verify the token and extract payload
      const decoded = Jwt.verify(token, oo_secret);
      let p = new URL(decoded.payload.url).searchParams

      // Extract parameters from token payload
      let uid = p.get(Attr.uid)
      let nid = p.get(Attr.nid)
      let hub_id = p.get(Attr.hub_id)
      let sessionKey = p.get('sessionKey')
      let args = `${uid}:${nid}:${hub_id}:${sessionKey}`;
      const signature = require('crypto')
        .createHmac('sha256', drumee_secret)
        .update(args)
        .digest('hex');
      // Check signature to ensure URL integrity
      if (!p.get('signature') || p.get('signature') != signature) {
        this.warn('Invalid signature', p, args);
        return this.exception.unauthorized("Permission denied")
      }
      const db_name = await this.yp.await_func("get_db_name", hub_id)
      let node = await this.yp.await_proc(`${db_name}.mfs_access_node`, uid, nid);
      if (node.privilege & Permission.read) {
        return { ...node, uid, nid, hub_id, sessionKey };
      }
      this.exception.unauthorized("Permission denied")
      return false

    } catch (jwtError) {
      this.warn('JWT validation failed:', jwtError.message);
      this.exception.unauthorized("Invalid authorization token")
      return false;
    }
  }

  /**
   * 
   * @param {*} sessionKey 
   * @returns 
   */
  async read() {
    const node = await this.checkSanity();
    if (!node) return;
    await this.send_media(node, ORIGINAL);
  }


  /**
 * replace existing media by uploaded file
 * @param {*} nid 
 * @param {*} incoming_file 
 * @param {*} filename 
 * @returns 
 */
  async replace(nid, incoming_file, filename) {
    let node = this.granted_node();
    if (/^(folder|root)$/.test(node.filetype)) {
      this.warn("COULD NOT REPLACE FOLDER", this.input.use(Attr.filepath), node);
      this.exception.user("TARGET_IS_FOLDER_OR_ROOT");
      return;
    }
    let md5Hash = this.input.get("md5Hash");
    let { metadata } = node;
    metadata = this.cleanJson(metadata);
    metadata.md5Hash = md5Hash;
    let privilege = node.permission;
    let home_dir = node.home_dir;
    let mfs_root = node.mfs_root;
    let data = await this.before_store(incoming_file, filename, {
      nid: node.parent_id,
    });
    data.rtime = Math.floor(new Date().getTime() / 1000);
    data.publish_time = data.rtime;
    if (data.filename) {
      data.user_filename = data.filename.replace(`.${data.extension}`, "");
    }

    await this.db.await_proc("mfs_set_node_attr", nid, data, 0);
    await this.db.await_proc("mfs_set_metadata", nid, metadata, 0);
    node.metadata = metadata;
    await this.after_store(
      node.pid,
      incoming_file,
      { ...node, privilege, home_dir, mfs_root, md5Hash },
    );
    node = await this.db.await_proc("mfs_access_node", this.uid, nid);
    if (node.filetype == Attr.document) {
      Document.rebuildInfo(
        node,
        this.uid,
        this.input.get(Attr.socket_id)
      )
    }
    this.output.data({
      ...node,
      replace: 1,
    });
  }

  /**
 * 
 * @param {*} incoming_file 
 * @param {*} data 
 * @returns 
 */
  async after_store(pid, incoming_file, data) {
    const base = resolve(data.mfs_root, data.id);
    mkdirSync(base, { recursive: true });
    const ext = data.extension.toLowerCase();
    let orig = `${base}/orig.${ext}`;
    this.granted_node(data);
    if (data.filetype == Attr.document && data.extension != Attr.pdf) {
      if (!this.handlePdf(incoming_file, data)) {
        data.error = 1;
      }
      return data;
    }
    if (data.filetype == Attr.form) {
      let content = await this.handleForm(pid, incoming_file, data);
      return content;
    }

    if (!mv(incoming_file, orig) || !existsSync(orig)) {
      this.warn(`${__filename}:337 ${orig} not found`);
      this.exception.user(FAILED_CREATE_FILE);
      return { ...data, error: 1 };
    }

    // Force information generation
    if (data.filetype == Attr.document && data.extension == Attr.pdf) {
      Document.getInfo(data);
    }

    data.position = this.input.get(Attr.position) || 0;

    return data;
  }

  /**
* Preapre data for storage
* @param {*} incoming_file 
* @param {*} filename 
* @param {*} parent 
* @returns 
*/
  async store(node) {
    const incoming_file = this.input.need(Attr.uploaded_file)
    if (!existsSync(incoming_file)) {
      return this.output.data({ error: "Uploaded file not found" });
    }

    if (node.filetype !== Attr.document) {
      this.warn("TARGET IS NOT A DOCUMENT", this.input.use(Attr.filepath), node);
      this.output.data({ error: "File type is not supported" });
      return;
    }

    let md5Hash = this.input.get("md5Hash");
    let { metadata } = node;
    metadata = this.cleanJson(metadata);
    metadata.md5Hash = md5Hash;
    node.publish_time = Math.floor(new Date().getTime() / 1000);;

    node.metadata = metadata;
    await this.db.await_proc("mfs_set_node_attr", node.id, node, 0);
    await this.db.await_proc("mfs_set_metadata", node.id, metadata, 0);
    Document.rebuildInfo(
      node,
      this.uid,
      this.input.get(Attr.socket_id)
    )
  }

  /**
   * 
   * @param {*} sessionKey 
   * @returns 
   */
  async write() {
    const node = await this.checkSanity();
    await this.store(node);
    if (!node) return;
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
      this.warn('Callback error:', error);
      ctx.body = { error: 1, message: error.message };
    }
  }
}

module.exports = OnlyOffice;