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
  async html(src) {
    const uid = this.uid;
    // Secure-share recipient: derive everything from the SHARE TOKEN, not the session.
    // The editor iframe does NOT carry an authorized session for an ANONYMOUS recipient
    // (the share/guest cookie isn't sent cross-site to the editor endpoint), so
    // this.granted_node() throws "Insufficient privilege". Resolve the node AS THE SHARE
    // CREATOR (the file owner) via the token, node-scoped to the shared subtree.
    // Read-only unless the share grants can_edit; the SAVE callback re-checks can_edit
    // and writes as the creator. Desk/normal requests carry no token → granted_node.
    const _shareToken = this.input.use('token', null);
    // The recipient's email — the key for per-recipient approved grants (mirror
    // dmz.js: authenticated → user.profile.email, lowercased/trimmed).
    const _recipientEmail = String(((this.user && this.user.get(Attr.profile)) || {}).email || '').toLowerCase().trim() || null;
    let _caps = null;
    let _node = src || null;
    if (!_node && _shareToken) {
      try {
        _caps = await this._secureShareCaps(_shareToken, _recipientEmail);
        if (_caps && _caps.valid && _caps.creator_id && _caps.db_name) {
          const _inNid = this.input.use(Attr.nid);
          // Node-scope: deny opening a node outside the shared subtree (a crafted
          // foreign nid would otherwise resolve via the creator). Deny ONLY on a
          // positive out-of-scope result; FAIL OPEN on any error.
          let _outOfScope = false;
          try {
            const _r = await this.yp.await_proc(`${_caps.db_name}.mfs_node_in_subtree`, _caps.node_id, _inNid);
            const _row = Array.isArray(_r) ? _r[0] : _r;
            if (_row && Number(_row.in_scope) === 0) _outOfScope = true;
          } catch (e) {
            this.warn('[euroffice.html] node-scope check unavailable (fail-open):', e && e.message);
          }
          if (_outOfScope) {
            this.warn('[euroffice.html] node outside share subtree — denied');
            return this.exception.unauthorized('Permission denied');
          }
          // Resolve the document as the CREATOR — the recipient session may be
          // unauthorized at the editor endpoint. Returns the same fields granted_node
          // would (hub_id/nid/filename/extension/privilege/mtime).
          _node = await this.yp.await_proc(`${_caps.db_name}.mfs_access_node`, _caps.creator_id, _inNid);
        }
      } catch (e) {
        this.warn('[euroffice.html] share caps/node lookup failed:', e && e.message);
      }
    }
    // Desk / non-token request (an authenticated user opening their own doc), or a
    // token request that didn't resolve: resolve via the SESSION uid on the request's
    // hub DB and deny without read access. We can't use granted_node here — the
    // euroffice.html ACL is now public-api (so anonymous share recipients can reach this
    // method at all), which means the ACL hasn't pre-resolved the mfs context.
    if (!_node) {
      const _hubId = this.input.use(Attr.hub_id);
      const _inNid = this.input.use(Attr.nid);
      const _db = _hubId ? await this.yp.await_func('get_db_name', _hubId) : null;
      if (_db && _inNid) {
        const _n = await this.yp.await_proc(`${_db}.mfs_access_node`, this.uid, _inNid);
        if (_n && _n.privilege && (_n.privilege & Permission.read)) _node = _n;
      }
    }
    if (!_node) return this.exception.unauthorized('Permission denied');
    const { hub_id, nid, filename, extension, privilege, mtime, md5Hash } = _node;
    // Mode: for a share request the resolved node is the creator's (full priv), so
    // derive the mode from the token caps; otherwise from the node privilege.
    let mode = privilege & Permission.write ? 'edit' : 'view';
    if (_shareToken) {
      mode = (_caps && _caps.canEdit) ? 'edit' : 'view';
    }
    // The content fetch (euroffice.read) and save must run as the file OWNER. For a
    // share request the recipient session isn't authorized on the node, so sign the
    // read URL with the CREATOR's uid; the editor's *displayed* user stays `uid`.
    const _ownerUid = (_shareToken && _caps && _caps.valid && _caps.creator_id)
      ? _caps.creator_id : this.uid;
    // Tamper-proof save-authorization for the (anonymous) save callback: it can't look
    // up the recipient's per-recipient grant, so html signs the decision (canEdit +
    // node identity + creator) with eo_secret. A view-only recipient's token says
    // canEdit:false and can't be forged to true; expires so a stale token can't be
    // replayed after access changes.
    let _cdt = '';
    if (_shareToken && _caps && _caps.valid) {
      _cdt = Jwt.sign(
        { nid, node_id: _caps.node_id, db_name: _caps.db_name, canEdit: !!_caps.canEdit, creator_id: _caps.creator_id },
        eo_secret,
        { expiresIn: '12h' }
      );
    }
    // The session key is used by only office unique id for colaboration.
    const sessionKey = `${hub_id}.${nid}.${mtime}`;

    // Sign the sessionKey to ensure with wonn't be forged. Use the OWNER uid (creator
    // for a share request) so euroffice.read resolves the content as the file owner.
    const signature = this.signString(`${sessionKey}/${_ownerUid}`);

    let query = `signature=${signature}&sessionKey=${sessionKey}&uid=${_ownerUid}`;

    // Get user info. Guard the profile read — an anonymous share recipient has no
    // profile (this path is now reachable for anonymous, which previously failed at
    // granted_node before this line).
    const fullname = this.user.get(Attr.fullname)
      || ((this.user.get(Attr.profile) || {}).email)
      || 'Guest';

    // Map the app theme forwarded by the frontend onto the OnlyOffice uiTheme.
    const uiTheme = this.input.use('theme', 'light') === 'dark' ? 'theme-dark' : 'theme-light';

    // Return the configuration
    const confObject = {
      document: {
        fileType: extension,
        key: sessionKey,
        title: filename,
        url: `${this.input.homepath()}svc/euroffice.read?${query}`
      },
      editorConfig: {
        mode,
        callbackUrl: `${this.input.homepath()}svc/euroffice.callback?key=${sessionKey}${_cdt ? `&cdt=${encodeURIComponent(_cdt)}` : ''}`,
        user: {
          id: uid,
          name: fullname
        },
        customization: {
          uiTheme
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
   */
  async preload() {
    const uid = this.uid;
    const name = this.input.need(Attr.name);

    let { db_name, path } = JSON.parse(Cache.getSysConf('doc_templates'));
    let filepath = join(path, name);
    let src = await this.yp.await_proc(`${db_name}.mfs_access_node`, this.uid, filepath)

    await this.html(src)
    
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
   * Resolve a secure-share token's capabilities + identity. Drives the editor mode
   * (read-only unless can_edit), the node-scope check, and the save-as-creator write
   * — so the editor never trusts the creator-bound session for the edit decision.
   * Returns { valid, canEdit, node_id, hub_id, db_name, creator_id }.
   */
  async _secureShareCaps(token, email) {
    const res = await this.yp.await_proc('secure_share_info', token);
    const info = Array.isArray(res) ? res[0] : res;
    if (!info || info.validity !== 'TICKET_OK') {
      return { valid: false, canEdit: false };
    }
    // Base caps from the token — mirror dmz.js parsing (array | JSON string | enum).
    let caps = [];
    const rawCaps = info.capabilities;
    if (Array.isArray(rawCaps)) caps = rawCaps.slice();
    else if (typeof rawCaps === 'string') {
      try { const p = JSON.parse(rawCaps); if (Array.isArray(p)) caps = p; } catch (e) {}
    }
    if (!caps.length && info.permission_level && info.permission_level !== 'can_view') {
      caps = [info.permission_level];
    }
    // UNION the recipient's APPROVED per-recipient grants (keyed on email), exactly as
    // dmz.js login does. An approval is stored as an access-request grant, NOT in the
    // token's base caps — so without this the editor never sees a granted can_edit.
    if (email) {
      try {
        const grants = toArray(await this.yp.await_proc('secure_share_get_access_grant', token, email));
        for (const g of grants) {
          String((g && g.granted_level) || '').split(',').map((s) => s.trim()).filter(Boolean)
            .forEach((l) => { if (!caps.includes(l)) caps.push(l); });
        }
      } catch (e) {
        this.warn('[euroffice] get_access_grant failed:', e && e.message);
      }
    }
    const canEdit = caps.includes('can_edit');
    return {
      valid: true,
      canEdit,
      node_id: info.node_id,
      hub_id: info.hub_id,
      db_name: info.db_name,
      creator_id: info.creator_id,
    };
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
    // NULL-GUARD before destructuring: getNode returns null when the uid lacks write
    // on the node (e.g. a recipient's own uid) → destructuring null would crash the
    // callback (was the euroffice.callback TypeError). The share save passes the
    // creator's uid (handleClosure), so this normally finds the node.
    const _res = await this.getNode(sessionKey, uid, Permission.write)
    if (!_res || !_res.node) return
    const { node, db_name } = _res

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
  async handleClosure(data, overrideUid) {
    const { actions, notmodified, history, key, url } = data;
    if (notmodified) return;
    for (let action of actions) {
      switch (action.type) {
        case 0:
          // For a secure-share save, write as the share CREATOR (file owner) —
          // the recipient's own uid has no ACL on the creator's node. overrideUid
          // is set by callback() only after the share-token can_edit + node-scope
          // checks pass; a normal desk save passes no overrideUid (action.userid).
          if (url) await this.importFile(url, key, overrideUid || action.userid);
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
    // Secure-share recipient SAVE gating. The callback is an anonymous doc-server
    // call, so it can't look up the recipient's per-recipient grant — instead it
    // verifies the tamper-proof decision token (cdt) html signed (eo_secret): a save
    // (MustSave/MustForceSave) is only honored when cdt.canEdit is true AND the saved
    // node matches the signed nid; the write is then performed as the share CREATOR.
    // A normal desk save carries no cdt and is unaffected.
    let _saveUid = null;
    const _cdtRaw = this.input.use('cdt', null);
    if (_cdtRaw && (data.status === 2 || data.status === 6)) {
      let _d = null;
      try { _d = Jwt.verify(_cdtRaw, eo_secret); }
      catch (e) { this.warn('[euroffice.callback] cdt verify failed:', e && e.message); }
      if (!_d || !_d.canEdit) {
        this.warn('[euroffice.callback] save rejected: not editable per signed decision');
        return this.output.json({ error: 0 });
      }
      // Confine the save to the node html signed. Both nids come from eo_secret-signed
      // sources (data.key = doc-server token, _d.nid = html), so a crafted save with a
      // different key is rejected.
      const _nid = String(data.key || '').split('.')[1];
      if (_nid && _d.nid && _nid !== _d.nid) {
        this.warn('[euroffice.callback] save rejected: node mismatch');
        return this.output.json({ error: 0 });
      }
      _saveUid = _d.creator_id || null;
    }
    switch (data.status) {
      case 6: // MustForceSave (force save during editing)
      case 2: // MustSave (normal save after closing)
        await this.handleClosure(data, _saveUid)
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
    // Secure-share recipient: creating a document is a WRITE. When a share token is
    // present, don't trust the session — require that the share grants can_edit and
    // CONFINE the new doc's destination (pid) to the shared subtree. The copy then
    // runs as the share CREATOR (file owner), exactly like the editor save path
    // (handleClosure overrideUid): a signed-in recipient is bound to their OWN uid
    // (dmz.js node-grant binding), so running as the creator guarantees the copy is
    // authorized on the creator's folder and the new file is creator-owned (uniform
    // with all share content). Desk requests carry no token → operate as this.uid,
    // unchanged.
    const _shareToken = this.input.use('token', null);
    let _opUid = this.uid;
    if (_shareToken) {
      const _recipientEmail = String(((this.user && this.user.get(Attr.profile)) || {}).email || '').toLowerCase().trim() || null;
      let _caps = null;
      try {
        _caps = await this._secureShareCaps(_shareToken, _recipientEmail);
      } catch (e) {
        this.warn('[euroffice.new_doc] share caps lookup failed:', e && e.message);
        return this.exception.unauthorized('Permission denied');
      }
      if (!_caps || !_caps.valid || !_caps.canEdit) {
        this.warn('[euroffice.new_doc] create denied: share does not grant can_edit');
        return this.exception.unauthorized('Permission denied');
      }
      // Node-scope: the destination folder MUST be inside the shared subtree (a
      // crafted foreign pid would otherwise resolve via the creator-bound session).
      // Deny ONLY on a positive out-of-scope result; FAIL OPEN on any error (the SP
      // may be absent on some instances → behave as today). Mirrors html().
      if (_caps.node_id && _caps.db_name) {
        let _outOfScope = false;
        try {
          const _r = await this.yp.await_proc(`${_caps.db_name}.mfs_node_in_subtree`, _caps.node_id, pid);
          const _row = Array.isArray(_r) ? _r[0] : _r;
          if (_row && Number(_row.in_scope) === 0) _outOfScope = true;
        } catch (e) {
          this.warn('[euroffice.new_doc] node-scope check unavailable (fail-open):', e && e.message);
        }
        if (_outOfScope) {
          this.warn('[euroffice.new_doc] destination outside share subtree — denied');
          return this.exception.unauthorized('Permission denied');
        }
      }
      // Operate as the creator from here on (template read, copy, read-back).
      if (_caps.creator_id) _opUid = _caps.creator_id;
    }
    let { db_name, path } = JSON.parse(Cache.getSysConf('doc_templates'));
    let filepath = join(path, name);
    let src = await this.yp.await_proc(`${db_name}.mfs_access_node`, _opUid, filepath)
    let source = [{ hub_id: src.hub_id, nid: src.nid }]
    let data = await this.db.await_proc('mfs_copy_all', source, _opUid, pid, hub_id)
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
          copied = await this.db.await_proc("mfs_access_node", _opUid, node.nid)
          await this.sendNodeAttributes(copied, "media.new")
          break;
      }
    }
    this.output.data(copied)
  }

}

module.exports = EurOffice;
