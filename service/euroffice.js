const { resolve, join } = require('path');
const {
  RedisStore, sysEnv, Attr, Permission, Constants, Network, toArray, Cache
} = require('@drumee/server-essentials');
const { isString } = require('lodash');
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
const { unlinkSync, renameSync, openSync, readSync, closeSync } = require('fs');
const { WRITE: PERMISSION_WRITE } = require("./lib/permission-bits");
const { buildEditorConfig } = require("./lib/editor-config");
const { renderEditorPage } = require("./lib/editor-page");
const { sendDsCommand } = require("./lib/ds-command");
const { convertDocument } = require("./lib/ds-convert");
const { EurOffice: eo_secret, drumee: drumee_secret } = readFileSync(keyPath);
const {
  ORIGINAL,
} = Constants;


class EurOffice extends Mfs {

  /**
 *
 */
  async sendHtml(data, integration = null) {
    const { main_domain } = sysEnv()
    const content = renderEditorPage(data, integration);

    // "*.domain" is not a valid Allow-Origin value; echo the caller's origin
    // when it belongs to this deployment (hub subdomains included).
    const origin = this.input.headers()['origin'] || '';
    if (origin === `https://${main_domain}` || origin.endsWith(`.${main_domain}`)) {
      this.output.set_header("Access-Control-Allow-Origin", origin);
      this.output.set_header("Vary", "Origin");
    }
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
    const { hub_id, nid, privilege, md5Hash } = _node;
    let { filename, extension, mtime } = _node;
    // Mode: for a share request the resolved node is the creator's (full priv), so
    // derive the mode from the token caps; otherwise from the node privilege.
    let mode = privilege & PERMISSION_WRITE ? 'edit' : 'view';
    // Edit on a SHARE request requires a genuine signed-in recipient — never an
    // anonymous opener. A public can_edit link otherwise hands edit to any visitor,
    // and the save callback runs as the creator (the recipient is creator-bound).
    // Two guards together are airtight and fail closed:
    //  - signed_in==1  blocks the no-session anon (uid=nobody, signed_in=0);
    //  - uid!=creator  blocks the creator-bound anon (anon recipients are bound to
    //                  the creator, so a creator-bound session reads as signed-in).
    // A genuine recipient is rebound to their OWN uid, so it passes both.
    // (Do NOT use this.user.isAnonymous() here — its internal this.user is undefined
    //  in the worker context and it throws.)
    const _signedIn = !!(this.user && this.user.get('signed_in') == 1);
    const _distinctFromCreator = !!(_caps && _caps.creator_id && String(this.uid) !== String(_caps.creator_id));
    // Genuine OWNER opening their own link: dmz.login signs a short-lived
    // owner_edit_token (with the shared `drumee` secret) ONLY for an authenticated
    // owner (is_authenticated && uid===creator). Verifying it lets the creator follow
    // the link's edit permission WITHOUT weakening the anonymous block above — an
    // anonymous creator-bound session never receives a valid token and cannot forge
    // one (server-signed), so it still resolves to view-only here. Bound to THIS share
    // (token + creator) and short-lived, so it cannot be replayed for another share.
    let _verifiedOwner = false;
    const _otoken = this.input.use('otoken', null);
    if (_otoken && _caps && _caps.valid && _caps.creator_id) {
      try {
        const _o = Jwt.verify(_otoken, drumee_secret);
        if (_o && _o.kind === 'ss_owner'
          && String(_o.token) === String(_shareToken)
          && String(_o.owner_uid) === String(_caps.creator_id)) {
          _verifiedOwner = true;
        }
      } catch (e) {
        this.warn('[euroffice.html] owner token verify failed:', e && e.message);
      }
    }
    // Edit iff the link grants it AND the opener is either a genuine signed-in
    // recipient (distinct from the creator) OR the cryptographically-verified owner.
    // On a view-only link canEdit is false → view for everyone (faithful preview).
    const _editAllowed = !!(_caps && _caps.canEdit && ((_signedIn && _distinctFromCreator) || _verifiedOwner));
    if (_shareToken) {
      mode = _editAllowed ? 'edit' : 'view';
    }

    // Legacy binary formats (.xls/.doc/.ppt) cannot be co-edited: the editor
    // converts them to OOXML in its cache, sees the config still declares the
    // legacy type, and loops "version changed / reload" forever. Upgrade to the
    // modern equivalent on open (as Word/Google do) and open the native file.
    // Desk edit sessions only; ANY failure falls back to opening as-is, and a
    // modern format never enters this block.
    const LEGACY_UPGRADE = { xls: 'xlsx', doc: 'docx', ppt: 'pptx', xlt: 'xltx', dot: 'dotx', pot: 'potx' };
    const _legacyExt = String(extension || '').toLowerCase();
    if (mode === 'edit' && !_shareToken && LEGACY_UPGRADE[_legacyExt]) {
      try {
        const _modernExt = LEGACY_UPGRADE[_legacyExt];
        const _base0 = resolve(_node.home_dir, nid);
        // A file labelled .xls/.doc/.ppt whose bytes are actually a ZIP (PK\x03\x04)
        // is already OOXML, only mislabelled — a leftover from the earlier
        // wrote-xlsx-into-orig.xls bug. Relabel it in place (no conversion), which
        // also self-heals any such file a tester still has.
        let _mislabelled = false;
        try {
          const _mb = Buffer.alloc(4);
          const _fd = openSync(resolve(_base0, `orig.${_legacyExt}`), 'r');
          try { readSync(_fd, _mb, 0, 4, 0); } finally { closeSync(_fd); }
          _mislabelled = _mb.toString('hex') === '504b0304';
        } catch (e) { /* fall through to conversion */ }
        if (_mislabelled) {
          const _dbName = _node.db_name || _node.actual_db;
          try { renameSync(resolve(_base0, `orig.${_legacyExt}`), resolve(_base0, `orig.${_modernExt}`)); } catch (e) { /* keep going */ }
          _node.extension = _modernExt;
          _node.ext = _modernExt;
          if (isString(_node.mimetype) && _node.mimetype.includes('/')) {
            _node.mimetype = `${_node.mimetype.split('/')[0]}/${_modernExt}`;
          }
          await this.yp.await_proc(`${_dbName}.mfs_set_node_attr`, _node.id, _node, 0);
          extension = _modernExt;
          this.debug(`[euroffice.html] relabelled mislabelled ${_legacyExt} -> ${_modernExt} for ${nid}`);
          // Skip the document-server conversion below.
          throw { __handled__: true };
        }
        const _cvKey = `${hub_id}.${nid}.${mtime}`;
        const _cvSig = this.signString(`${_cvKey}/${this.uid}`);
        const _srcUrl = `${this.input.homepath()}svc/euroffice.read?signature=${_cvSig}&sessionKey=${_cvKey}&uid=${this.uid}`;
        const _fileUrl = await convertDocument(
          Cache.getSysConf('eurofficeServerUrl'),
          { filetype: _legacyExt, outputtype: _modernExt, key: `cv.${_cvKey}`, title: `${filename}.${_legacyExt}`, url: _srcUrl },
          eo_secret
        );
        if (_fileUrl) {
          const _dbName = _node.db_name || _node.actual_db;
          const _base = resolve(_node.home_dir, nid);
          const _res = await Network.request({ method: 'GET', outfile: resolve(_base, `orig.${_modernExt}`), url: _fileUrl });
          try { unlinkSync(resolve(_base, `orig.${_legacyExt}`)); } catch (e) { /* already gone */ }
          _node.extension = _modernExt;
          _node.ext = _modernExt;
          if (isString(_node.mimetype) && _node.mimetype.includes('/')) {
            _node.mimetype = `${_node.mimetype.split('/')[0]}/${_modernExt}`;
          }
          if (isString(_node.metadata)) { try { _node.metadata = JSON.parse(_node.metadata); } catch (e) { _node.metadata = {}; } }
          _node.metadata = _node.metadata || {};
          delete _node.metadata._seen_;
          _node.metadata.md5Hash = _res.md5Hash;
          _node.md5Hash = _res.md5Hash;
          _node.filesize = _res.size;
          _node.publish_time = Math.floor(_res.mtimeMs / 1000);
          _node.mtime = _node.publish_time;
          await this.yp.await_proc(`${_dbName}.mfs_set_node_attr`, _node.id, _node, 0);
          await this.yp.await_proc(`${_dbName}.mfs_set_metadata`, _node.id, { md5Hash: _res.md5Hash }, 0);
          // The editor now opens the native file: refresh the locals the config uses.
          extension = _modernExt;
          mtime = _node.mtime;
          this.debug(`[euroffice.html] upgraded ${_legacyExt} -> ${_modernExt} for ${nid}`);
        } else {
          this.warn(`[euroffice.html] conversion of ${_legacyExt} returned no file; opening as-is`);
        }
      } catch (e) {
        if (!(e && e.__handled__)) {
          this.warn('[euroffice.html] legacy conversion failed, opening as-is:', e && e.message);
        }
      }
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
        { nid, node_id: _caps.node_id, db_name: _caps.db_name, canEdit: _editAllowed, creator_id: _caps.creator_id },
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

    // Return the configuration. Shared with the onlyoffice service so both
    // editors are configured identically — see lib/editor-config, which also
    // pins the editor UI language (always English, by decision).
    const confObject = buildEditorConfig({
      extension,
      filename,
      sessionKey,
      mode,
      uid,
      fullname,
      uiTheme,
      readUrl: `${this.input.homepath()}svc/euroffice.read?${query}`,
      callbackUrl: `${this.input.homepath()}svc/euroffice.callback?key=${sessionKey}${_cdt ? `&cdt=${encodeURIComponent(_cdt)}` : ''}`,
      nid,
      hub_id,
      documentServerUrl: Cache.getSysConf('eurofficeServerUrl'),
    });

    // Sign the ENTIRE config as the token
    const token = Jwt.sign(
      confObject,
      eo_secret
    );

    // Add token to config sent to frontend
    confObject.token = token;

    // File-menu integrations (Save Copy as…, Rename) — desk edit sessions only:
    // a share session is creator-bound and routes writes through signed grants,
    // which neither integration carries yet.
    //
    // The service URLs are RELATIVE on purpose. The editor page may be served
    // from a hub subdomain (team-x.<domain>/-/<ep>/svc/euroffice.html) while
    // homepath() names the main domain — an absolute URL would make the
    // handlers' fetch cross-origin, the session cookie would stay behind, and
    // the call would arrive anonymous and be denied. Relative to the page,
    // "euroffice.save_as" always lands on the same origin and endpoint.
    let integration = null;
    if (mode === 'edit' && !_shareToken) {
      integration = {
        nid,
        hub_id,
        ext: extension,
        docKey: sessionKey,
        saveAsUrl: 'euroffice.save_as',
        renameUrl: 'media.rename',
        retitleUrl: 'euroffice.retitle',
      };
    }
    this.sendHtml(confObject, integration)
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
      this.warn('JWT[154] validation failed:', jwtError.message);
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
      this.warn('JWT[154] validation failed:', jwtError.message);
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
  async importFile(url, sessionKey, uid, savedType) {
    // NULL-GUARD before destructuring: getNode returns null when the uid lacks write
    // on the node (e.g. a recipient's own uid) → destructuring null would crash the
    // callback (was the euroffice.callback TypeError). The share save passes the
    // creator's uid (handleClosure), so this normally finds the node.
    const _res = await this.getNode(sessionKey, uid, PERMISSION_WRITE)
    if (!_res || !_res.node) return
    const { node, db_name } = _res

    // The format the document server actually produced. A legacy file (.xls/.doc/
    // .ppt) is opened by converting it to its modern equivalent, and the editor
    // only EVER saves the modern format back — so writing those bytes into the
    // legacy-named orig.xls left the content and the extension disagreeing, and
    // the next open came up read-only ("format does not match"). Follow the saved
    // format instead: promote the node to it, exactly as MS/Google upgrade a
    // legacy file on first save.
    const _srcExt = String(node.ext || '').toLowerCase();
    let _outExt = String(savedType || '').toLowerCase();
    if (!_outExt) {
      try { _outExt = new URL(url).pathname.split('.').pop().toLowerCase(); } catch (e) { /* keep source */ }
    }
    if (!/^[a-z0-9]{1,8}$/.test(_outExt)) _outExt = _srcExt;
    const _promoted = _outExt && _outExt !== _srcExt;

    const base = resolve(node.home_dir, node.nid)
    const outfile = resolve(base, `orig.${_outExt || node.ext}`)
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
    if (_promoted) {
      // Drop the stale legacy file and move the node onto the modern extension.
      try { unlinkSync(resolve(base, `orig.${_srcExt}`)); } catch (e) { /* already gone */ }
      node.extension = _outExt;
      node.ext = _outExt;
      if (isString(node.mimetype) && node.mimetype.includes('/')) {
        node.mimetype = `${node.mimetype.split('/')[0]}/${_outExt}`;
      }
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
    const { actions, notmodified, history, key, url, filetype } = data;
    if (notmodified) return;
    // A status-2/6 callback is not guaranteed to carry an actions array;
    // without the guard the save is lost to a TypeError.
    for (let action of actions || []) {
      switch (action.type) {
        case 0:
          // For a secure-share save, write as the share CREATOR (file owner) —
          // the recipient's own uid has no ACL on the creator's node. overrideUid
          // is set by callback() only after the share-token can_edit + node-scope
          // checks pass; a normal desk save passes no overrideUid (action.userid).
          if (url) await this.importFile(url, key, overrideUid || action.userid, filetype);
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
      this.warn('JWT[154] validation failed:', jwtError.message);
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

  /**
   * "Save Copy as…" — the editor hands us the download URL of the copy it just
   * assembled; create a sibling of the source document and fill it with that
   * content. v1 keeps the copy in the source's own format (no conversion).
   */
  async save_as() {
    const granted = this.granted_node();
    const node = await this.db.await_proc('mfs_access_node', this.uid, granted.nid);
    if (!node || !node.nid) return this.exception.unauthorized('Permission denied');
    const { hub_id } = node;
    const pid = node.parent_id || node.pid;

    const srcUrl = String(this.input.need(Attr.url));
    const title = String(this.input.need('title') || '').trim();
    const ext = String(node.ext || '').toLowerCase();
    const fileType = String(this.input.use('file_type', ext) || ext).toLowerCase();
    if (!/^[a-z0-9]{1,8}$/.test(fileType)) return this.exception.user('UNSUPPORTED_FORMAT');

    // The only host this service will ever fetch is the document server itself.
    let parsed = null;
    try { parsed = new URL(srcUrl); } catch (e) { /* refused below */ }
    const dsBase = Cache.getSysConf('eurofficeServerUrl');
    if (!parsed || !dsBase || parsed.origin !== new URL(dsBase).origin) {
      this.warn('[euroffice.save_as] refused a url outside the document server');
      return this.exception.unauthorized('Permission denied');
    }
    if (!title || /[\/\\]/.test(title) || /^\.+$/.test(title)) {
      return this.exception.user('INVALID_FILENAME');
    }

    // A sibling copy of the source node — same recipe as new_doc's template copy.
    const data = await this.db.await_proc('mfs_copy_all', [{ hub_id, nid: node.nid }], this.uid, pid, hub_id);
    let copied = null;
    for (let n of data) {
      switch (n.action) {
        case 'copy':
          try {
            copy_node({ nid: n.nid, mfs_root: n.src_mfs_root }, { nid: n.des_id, mfs_root: n.des_mfs_root }, 0);
          } catch (e) {
            this.warn('COPY FAILED ', e);
          }
          break;
        case 'show':
          copied = await this.db.await_proc('mfs_access_node', this.uid, n.nid);
          break;
      }
    }
    if (!copied || !copied.nid) return this.exception.user('COPY_FAILED');

    // Name the copy as asked (the proc de-duplicates), then overwrite its
    // content with the state the editor handed us — the importFile steps. The
    // copy takes the CHOSEN output format (Save Copy as… may pick xlsx/ods/pdf/…
    // from a legacy .xls), so its stored file and extension follow file_type,
    // never the source's.
    let base = title;
    for (const suffix of [`.${fileType}`, `.${ext}`]) {
      if (base.toLowerCase().endsWith(suffix)) {
        base = base.slice(0, -suffix.length).trim() || title;
        break;
      }
    }
    await this.db.await_proc('mfs_rename', copied.nid, base);
    copied = await this.db.await_proc('mfs_access_node', this.uid, copied.nid);

    const outfile = resolve(copied.home_dir, copied.nid, `orig.${fileType}`);
    const res = await Network.request({ method: 'GET', outfile, url: srcUrl });
    copied = await this.db.await_proc('mfs_access_node', this.uid, copied.nid);
    if (isString(copied.metadata)) copied.metadata = JSON.parse(copied.metadata);
    copied.metadata = copied.metadata || {};
    delete copied.metadata._seen_;
    if (fileType !== String(copied.ext || '').toLowerCase()) {
      // mfs_copy_all cloned the SOURCE file (orig.<srcExt>); drop it and move
      // the copy onto the chosen format.
      try { unlinkSync(resolve(copied.home_dir, copied.nid, `orig.${copied.ext}`)); } catch (e) { /* none */ }
      if (isString(copied.mimetype) && copied.mimetype.includes('/')) {
        copied.mimetype = `${copied.mimetype.split('/')[0]}/${fileType}`;
      }
      copied.extension = fileType;
      copied.ext = fileType;
    }
    copied.publish_time = Math.floor(res.mtimeMs / 1000);
    copied.metadata.md5Hash = res.md5Hash;
    copied.md5Hash = res.md5Hash;
    copied.filesize = res.size;
    copied.mtime = copied.publish_time;
    await this.db.await_proc('mfs_set_node_attr', copied.id, copied, 0);
    await this.db.await_proc('mfs_set_metadata', copied.id, { md5Hash: res.md5Hash }, 0);
    Document.rebuildInfo(copied, this.uid, this.input.get(Attr.socket_id));
    await this.sendNodeAttributes(copied, 'media.new');
    this.output.data(copied);
  }

  /**
   * Mirror a rename into the LIVE editing session (Command Service `meta`), so
   * every open editor retitles without a reopen. The storage rename itself is
   * media.rename — this endpoint only tells the document server about it.
   */
  async retitle() {
    const granted = this.granted_node();
    const key = String(this.input.need('key'));
    const title = String(this.input.need('title') || '').trim();
    // The key must denote the very node this session was granted on — no
    // cross-document meta pushes.
    const [kHub, kNid] = key.split('.');
    if (kHub !== granted.hub_id || kNid !== granted.nid) {
      return this.exception.unauthorized('Permission denied');
    }
    if (!title) return this.exception.user('INVALID_FILENAME');
    let reply = null;
    try {
      reply = await sendDsCommand(
        Cache.getSysConf('eurofficeServerUrl'),
        { c: 'meta', key, meta: { title } },
        eo_secret
      );
    } catch (e) {
      // Harmless degradation: the file IS renamed; open editors just keep the
      // old title until they reopen.
      this.warn('[euroffice.retitle] command service unreachable:', e && e.message);
    }
    this.output.data({ error: reply ? reply.error : -1 });
  }

}

module.exports = EurOffice;
