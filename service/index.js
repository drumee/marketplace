const { resolve } = require('path');
const {
  RedisStore, sysEnv, Attr, Permission, Constants, Network, toArray, Cache
} = require('@drumee/server-essentials');
const { template, isString} = require('lodash');
const Jwt = require('jsonwebtoken'); // Make sure this is installed
const {
  Document,
  FileIo,
  Mfs,
  MfsTools,
} = require("@drumee/server-core");

const { credential_dir } = sysEnv();
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
      documentServerUrl: Cache.getSysConf('documentServerUrl')
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
    if (node.metadata) {
      if (isString(node.metadata)) {
        node.metadata = JSON.parse(node.metadata)
      }
      delete node.metadata._seen_
    } else {
      node.metadata = {}
    }
    node.publish_time = Math.floor(res.mtimeMs / 1000);
    node.metadata.md5Hash = md5Hash;
    node.filesize = res.size;
    const { db_name, uid } = ctx;
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
        await this.yp.await_proc(`mfs_cleanup_autorized_node`)
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

}

module.exports = OnlyOffice;
