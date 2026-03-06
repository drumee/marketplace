const { resolve } = require('path');
const {
  RedisStore, sysEnv, Attr, Permission, Constants, Network, toArray
} = require('@drumee/server-essentials');
const { template } = require('lodash');
const Jwt = require('jsonwebtoken'); // Make sure this is installed
const {
  Generator,
  Document,
  FileIo,
  Mfs,
  MfsTools,
} = require("@drumee/server-core");

const { credential_dir, server_home } = sysEnv();
const OFFLINE_DIR = resolve(server_home, "offline", "media");
const keyPath = resolve(credential_dir, 'crypto/secret.json');
const { readFileSync, writeFileSync } = require('jsonfile');
const { onlyoffice: oo_secret, drumee: drumee_secret } = readFileSync(keyPath);
const {
  ORIGINAL,
} = Constants;

const {
  mkdirSync,
  readFileSync: readFile,
  existsSync,
} = require("fs");
const { mv, cleanSeen } = MfsTools;

class OnlyOffice extends Mfs {

  /**
 *
 */
  async sendHtml(data) {
    const { main_domain } = sysEnv()
    const tpl = resolve(__dirname, 'templates/index.html');
    let html = readFile(tpl);
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
    const uid = this.uid;
    const { hub_id, nid, filename, extension, privilege } = this.granted_node();

    // Generate unique session key
    // Store the node as pre-authorized for future access based on sessionKey
    const sessionKey = this.randomString();
    let args = { sessionKey, hub_id, nid, uid: uid, expiry: 36000 };
    await this.yp.await_proc('mfs_add_autorized_node', args);

    // Sign the sessionKey to ensure with wonn't be forged
    const signature = this.signString(sessionKey);

    let query = `signature=${signature}&sessionKey=${sessionKey}`;

    // Get user info
    const firstname = await this.user.get(Attr.firstname);

    // Return the configuration
    const confObject = {
      document: {
        fileType: extension,
        key: sessionKey,
        title: filename,
        url: `${this.input.homepath()}svc/onlyoffice.read?${query}`
      },
      editorConfig: {
        mode: privilege & Permission.write ? 'edit' : 'view',
        callbackUrl: `${this.input.homepath()}svc/onlyoffice.callback?key=${sessionKey}`,
        user: {
          id: uid,
          name: firstname
        }
      },
      customization: {
        forcesave: true,  // Enable Save button and intermediate versions
      },
      // Your custom Drumee data
      drumeeContext: {
        nid,
        hub_id
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
  signString(query) {
    return require('crypto')
      .createHmac('sha256', drumee_secret)
      .update(query)
      .digest('hex');
  }

  /**
   * 
   * @param {*} sessionKey 
   * @returns 
   */
  extractContent() {
    const authHeader = this.input.headers()['authorization'];
    const token = authHeader.substring(7);
    try {
      // Verify the token and extract payload
      const decoded = Jwt.verify(token, oo_secret);
      return new URL(decoded.payload.url).searchParams

    } catch (jwtError) {
      this.warn('JWT[154] validation failed:', jwtError.message, oo_secret, token);
      this.exception.unauthorized("Invalid authorization token")
      return {};
    }
  }

  /**
   * 
   * @param {*} sessionKey 
   * @returns 
   */
  async read() {
    const authHeader = this.input.headers()['authorization'];
    const token = authHeader.substring(7);
    try {
      // Verify the token and extract payload
      const decoded = Jwt.verify(token, oo_secret);
      let p = new URL(decoded.payload.url).searchParams
      // Extract parameters from token payload
      const sessionKey = p.get('sessionKey')
      const signature = require('crypto')
        .createHmac('sha256', drumee_secret)
        .update(sessionKey)
        .digest('hex');

      // Check signature to ensure URL integrity
      if (!p.get('signature') || p.get('signature') != signature) {
        this.warn('Invalid signature', signature, p, decoded.payload.url);
        return this.exception.unauthorized("Permission denied")
      }

      let node = await this.yp.await_proc(`mfs_get_autorized_node`, sessionKey);
      if (!node.length) {
        this.warn('Node info not found');
        return this.exception.unauthorized("Permission denied")
      }
      if (node[0].privilege & Permission.read) {
        await this.send_media(node[0], ORIGINAL);
        return;
      }
      this.exception.unauthorized("Permission denied")

    } catch (jwtError) {
      this.warn('JWT[154] validation failed:', jwtError.message, oo_secret, token);
      this.exception.unauthorized("Invalid authorization token")
    }

  }

  /**
   * 
   * @param {*} args 
   */
  async sendNodeAttributes(node) {
    let recipients = await this.yp.await_proc("entity_sockets", {
      hub_id: node.hub_id,
    });
    let payload = this.payload(node, { service: "media.replace" });
    for (let r of toArray(recipients)) {
      await RedisStore.sendData(payload, r);
    }
  }



  /**
  *
  * @param {*} dir
  * @param {*} filter
  */
  async importFile(node, ctx) {
    if (!node) {
      this.warn("importFile failed. Node not found");
      return
    }
    const base = resolve(node.home_dir, node.nid)
    const outfile = resolve(base, `orig.${node.ext}`)
    this.debug(`Downloading ${this.input.get(Attr.url)} => ${outfile}.`);
    let opt = {
      method: 'GET',
      outfile,
      url: this.input.get(Attr.url),
    };
    let res = await Network.request(opt);
    let { md5Hash } = res;
    let metadata = {};
    if (node.metadata) {
      metadata = cleanSeen(node.metadata);
    }
    node.publish_time = Math.floor(res.mtimeMs / 1000);
    res.filesize = res.size;
    metadata.md5Hash = md5Hash;
    this.debug("AAA:204", res)
    const { db_name, uid } = ctx;
    await this.yp.await_proc(`${db_name}.mfs_set_node_attr`, node.id, node, 0);
    await this.yp.await_proc(`${db_name}.mfs_set_metadata`, node.id, metadata, 0);
    Document.rebuildInfo(
      node,
      uid,
      this.input.get(Attr.socket_id)
    );
    await this.sendNodeAttributes(node)
  }

  /**
   * Callback endpoint from onlyoffice
   * Always return 200 with {error: 0} to acknowledge receipt
   * @param {*} sessionKey 
   * @returns 
   */
  async callback() {
    try {
      Jwt.verify(this.input.get(Attr.token), oo_secret);
    } catch (jwtError) {
      this.warn('JWT[154] validation failed:', jwtError.message, oo_secret, token);
      this.exception.unauthorized("Invalid authorization token")
      return
    }

    switch (this.input.get(Attr.status)) {
      case 6: // MustForceSave (force save during editing)
      case 2: // MustSave (normal save after closing)
        let node = await this.yp.await_proc(`mfs_get_autorized_node`, this.input.get(Attr.key)) || [];
        this.debug("AAA:201", node)
        if (this.input.get(Attr.url)) {
          await this.importFile(...node);
        }
        break;

      case 3: // Corrupted (error during save)
      case 7: // Force save error
        this.warn('Document save error:', callbackData);
        // Log error but still acknowledge
        break;

      case 4: // Closed with no changes
        this.debug('Document closed with no changes');
        break;

      case 1: // Editing in progress
        // Just acknowledge, no action needed
        break;

      default:
        this.debug('Unhandled status:', callbackData.status);

    }
    this.output.json({ error: 0 })
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
    if (!this.import(incoming_file, node)) {
      this.output.data({ error: "Failed to import" });
      return
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
    );
  }


  /**
   *
   * @param {*} node
   */
  import(incoming_file, node) {
    const base = resolve(node.mfs_root, node.id);
    const ext = node.extension.toLowerCase();
    let orig = join(base, `orig.${ext}`);
    let info = join(base, "info.json");
    mkdirSync(base, { recursive: true });
    let docInfo = { buildState: Attr.working };
    if (!mv(incoming_file, orig)) {
      this.exception.server('FILE_ERROR');
      return false
    }
    rmSync(info, { force: true });
    writeFileSync(info, docInfo);
    let socket_id = this.input.get(Attr.socket_id);
    let args = {
      node,
      uid: this.uid,
      socket_id,
    };

    let cmd = resolve(OFFLINE_DIR, "to-pdf.js");
    let child = Spawn(cmd, [JSON.stringify(args)], SPAWN_OPT);
    child.unref();
    return true
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

  /**
   * 
   */
  test() {
    this.debug('AAA:402', this.granted_node(), this.randomString(), OFFLINE_DIR)
  }
}

module.exports = OnlyOffice;

/**
 * 
 
// In your Drumee backend callback endpoint
app.post('/api/onlyoffice/callback', async (req, res) => {
  try {
    const { status, url, key } = req.body;
    
    this.debug(`Callback received - Status: ${status}, Key: ${key}`);
    
    // Always return 200 with {error: 0} to acknowledge receipt
    // The actual processing should happen asynchronously
    
    // For debugging, log what you received
    if (status === 2 || status === 6) {
      this.debug(`Document ready to download from: ${url}`);
      
      // Start async processing without blocking the response
      processDocumentSave(url, key).catch(err => {
        this.warn('Async save failed:', err);
        // Log error but don't change the response - ONLYOFFICE already got 200
      });
    }
    
    // IMPORTANT: Respond immediately with success
    res.json({ error: 0 });
    
  } catch (error) {
    this.warn('Callback handler error:', error);
    // Still return 200 with error=0? No - if we caught an exception, 
    // ONLYOFFICE should retry
    res.status(500).json({ error: 1, message: error.message });
  }
});

// Separate async function for actual document saving
async function processDocumentSave(url, key) {
  try {
    // Download the document from the provided URL
    const response = await fetch(url, {
      headers: {
        // If your ONLYOFFICE requires JWT for downloads
        'Authorization': `Bearer ${process.env.ONLYOFFICE_JWT_SECRET}`
      }
    });
    
    if (!response.ok) {
      throw new Error(`Download failed: ${response.status}`);
    }
    
    // Get the file as a buffer or stream
    const fileBuffer = await response.buffer();
    
    // Get session info from your database using the key
    const session = await db.collection('onlyoffice_sessions').findOne({ key });
    
    if (!session) {
      throw new Error(`No session found for key: ${key}`);
    }
    
    // Save to Drumee filesystem
    await drumee.file.write(session.fileId, fileBuffer, {
      metadata: {
        savedBy: session.userId,
        savedAt: new Date(),
        version: await getNextVersion(session.fileId)
      }
    });
    
    this.debug(`Document ${session.fileId} saved successfully`);
    
  } catch (error) {
    this.warn('Async document save failed:', error);
    // Here you might want to implement retry logic or alerting
  }
}
 **/