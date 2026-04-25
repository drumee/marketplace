const { resolve, join } = require('path');
const {
  RedisStore, sysEnv, Attr, Permission, Constants, Network, toArray, Cache
} = require('@drumee/server-essentials');
const { template, isString } = require('lodash');
const Jwt = require('jsonwebtoken'); // Make sure this is installed
const {
  Document,
  Mfs,
  MfsTools
} = require("@drumee/server-core");
const { move_node, copy_node } = MfsTools;
const { credential_dir } = sysEnv();
const keyPath = resolve(credential_dir, 'crypto/secret.json');
const { readFileSync } = require('jsonfile');
const { EurOffice: eo_secret, drumee: drumee_secret } = readFileSync(keyPath);
const {
  ORIGINAL,
} = Constants;

const {
  readFileSync: readFile,
} = require("fs");

class EurOffice extends Mfs {

  /**
 *
 */
  async sendHtml(data) {
    const { main_domain } = sysEnv()
    const tpl = resolve(__dirname, 'templates/euroffice.html');
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
    const { hub_id, nid, filename, extension, privilege, mtime, md5Hash } = this.granted_node();

    // The session key is used by only office unique id for colaboration. 
    const sessionKey = `${hub_id}.${nid}.${mtime}`;

    // Sign the sessionKey to ensure with wonn't be forged
    const signature = this.signString(`${sessionKey}/${this.uid}`);

    let query = `signature=${signature}&sessionKey=${sessionKey}&uid=${this.uid}`;

    // Get user info
    const fullname = this.user.get(Attr.fullname) || this.user.get(Attr.profile).email;

    // Return the configuration
    const confObject = {
      document: {
        fileType: extension,
        key: sessionKey,
        title: filename,
        url: `${this.input.homepath()}svc/euroffice.read?${query}`
      },
      editorConfig: {
        mode: privilege & Permission.write ? 'edit' : 'view',
        callbackUrl: `${this.input.homepath()}svc/euroffice.callback?key=${sessionKey}`,
        user: {
          id: uid,
          name: fullname
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
      documentServerUrl: Cache.getSysConf('eurofficeServerUrl')
    };

    // Sign the ENTIRE config as the token
    const token = Jwt.sign(
      confObject,
      eo_secret
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
      const decoded = Jwt.verify(token, eo_secret);
      return new URL(decoded.payload.url).searchParams

    } catch (jwtError) {
      this.warn('JWT[154] validation failed:', jwtError.message, eo_secret, token);
      this.exception.unauthorized("Invalid authorization token")
      return {};
    }
  }

  /**
   * 
   */
  async getNode(sessionKey, uid, permission) {
    let [hub_id, nid] = sessionKey.split(".");
    const db_name = await this.yp.await_func('get_db_name', hub_id);
    const node = await this.yp.await_proc(`${db_name}.mfs_access_node`, uid, nid);
    if (!node || !node.privilege || !(node.privilege & permission)) {
      this.warn('Node info not found');
      this.exception.unauthorized("Permission denied")
      return null;
    }
    return { node, db_name, hub_id, nid, uid };
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
      const decoded = Jwt.verify(token, eo_secret);
      let p = new URL(decoded.payload.url).searchParams
      // Extract parameters from token payload
      const sessionKey = p.get('sessionKey')
      const uid = p.get(Attr.uid);
      const payload = `${sessionKey}/${uid}`
      const signature = require('crypto')
        .createHmac('sha256', drumee_secret)
        .update(payload)
        .digest('hex');

      // Check signature to ensure URL integrity
      if (!p.get('signature') || p.get('signature') != signature) {
        this.warn('Invalid signature', signature, p, decoded.payload.url);
        return this.exception.unauthorized("Permission denied")
      }
      let { node } = await this.getNode(sessionKey, uid, Permission.read)
      if (node) {
        await this.send_media(node, ORIGINAL);
      }
    } catch (jwtError) {
      this.warn('JWT[154] validation failed:', jwtError.message, eo_secret, token);
      this.exception.unauthorized("Invalid authorization token")
    }

  }

  /**
   * 
   * @param {*} args 
   */
  async sendNodeAttributes(node, service = "media.replace") {
    let recipients = await this.yp.await_proc("entity_sockets", {
      hub_id: node.hub_id,
    });
    let payload = this.payload(node, { service });
    for (let r of toArray(recipients)) {
      await RedisStore.sendData(payload, r);
    }
  }



  /**
  *
  * @param {*} dir
  * @param {*} filter
  */
  async importFile(url, sessionKey, uid) {
    let { node, db_name } = await this.getNode(sessionKey, uid, Permission.write)
    if (!node) return

    const base = resolve(node.home_dir, node.nid)
    const outfile = resolve(base, `orig.${node.ext}`)
    this.debug(`Downloading ${this.input.get(Attr.url)} => ${outfile}.`);
    let opt = {
      method: 'GET',
      outfile,
      url
    };
    let res = await Network.request(opt);
    let { md5Hash } = res;
    if (node.metadata) {
      if (isString(node.metadata)) {
        node.metadata = JSON.parse(node.metadata)
      }
      delete node.metadata._seen_
      // node.metadata = cleanSeen(node.metadata)
    } else {
      node.metadata = {}
    }
    node.publish_time = Math.floor(res.mtimeMs / 1000);
    node.metadata.md5Hash = md5Hash;
    node.md5Hash = md5Hash;
    node.filesize = res.size;
    node.mtime = node.publish_time;
    await this.yp.await_proc(`${db_name}.mfs_set_node_attr`, node.id, node, 0);
    await this.yp.await_proc(`${db_name}.mfs_set_metadata`, node.id, { md5Hash }, 0);
    Document.rebuildInfo(
      node,
      uid,
      this.input.get(Attr.socket_id)
    );
    await this.sendNodeAttributes(node)
  }

  /**
   * 
   */
  async handleError() {
    this.warn("AAA:244:handleError", this.input.body())
  }

  /**
   * 
   */
  async handleCollaboration() {
    this.debug("AAA:251:handleCollaboration", this.input.body())
  }

  /**
   * 
   */
  async handleClosure(data) {
    const { actions, notmodified, history, key, url } = data;
    if (notmodified) return;
    for (let action of actions) {
      switch (action.type) {
        case 0:
          if (url) await this.importFile(url, key, action.userid);
          break;
        case 1:
          this.debug("New user joining")
          break;
        case 2:
      }
    }
  }

  /**
   * Callback endpoint from EurOffice
   * Always return 200 with {error: 0} to acknowledge receipt
   * @param {*} sessionKey 
   * @returns 
   */
  async callback() {
    let data = {};
    try {
      data = Jwt.verify(this.input.get(Attr.token), eo_secret);
    } catch (jwtError) {
      this.warn('JWT[154] validation failed:', jwtError.message, eo_secret, token);
      this.exception.unauthorized("Invalid authorization token")
      return
    }
    switch (data.status) {
      case 6: // MustForceSave (force save during editing)
      case 2: // MustSave (normal save after closing)
        await this.handleClosure(data)
        break;

      case 3: // Corrupted (error during save)
      case 7: // Force save error
        this.handleError(data);
        // Log error but still acknowledge
        break;

      case 4: // Closed with no changes
        this.debug('Document closed with no changes');
        break;

      case 1: // Editing in progress
        this.handleCollaboration(data)
        break;

      default:
        this.debug('Unhandled status:', this.input.body());

    }
    this.output.json({ error: 0 })
  }

  /**
   * 
   */
  async new_doc() {
    const name = this.input.need(Attr.name);
    const { hub_id, nid: pid } = this.granted_node();
    let { db_name, path } = JSON.parse(Cache.getSysConf('doc_templates'));
    let filepath = join(path, name);
    let src = await this.yp.await_proc(`${db_name}.mfs_access_node`, this.uid, filepath)
    let source = [{ hub_id: src.hub_id, nid: src.nid }]
    let data = await this.db.await_proc('mfs_copy_all', source, this.uid, pid, hub_id)
    let copied;
    for (let node of data) {
      switch (node.action) {
        case "copy":
          let src = { nid: node.nid, mfs_root: node.src_mfs_root };
          let dest = { nid: node.des_id, mfs_root: node.des_mfs_root };
          try {
            copy_node(src, dest, 0);
          } catch (e) {
            this.warn("COPY FAILED ", e);
          }
          break;
        case "show":
          copied = await this.db.await_proc("mfs_access_node", this.uid, node.nid)
          await this.sendNodeAttributes(copied, "media.new")
          break;
      }
    }
    this.output.data(copied)
  }

}

module.exports = EurOffice;
