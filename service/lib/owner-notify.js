/**
 * @license
 * Copyright 2024 Thidima SA. All Rights Reserved.
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.gnu.org/licenses/agpl-3.0.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =============================================================================
 */

/**
 * Tell a document's owner who edited it and who commented on it, when the
 * editor saves.
 *
 * The notification itself is server-team's (service/lib/file-owner-notify.js),
 * and so is reading the comments stored inside a docx/xlsx/pptx
 * (offline/media/office-comments.js): both are loaded from server_home, like
 * lib/fitted-source loads normalize-docx-sections, so there is one definition
 * of each. On a server without them this does nothing.
 *
 * Usage, around the write of the saved bytes:
 *   const prepared = await prepareOfficeSave(svc, { hub_id, nid, file, ext, editors });  // BEFORE overwriting
 *   ... write ...
 *   notifyOfficeSave(svc, { hub_id, nid, file, ext, prepared });
 *
 * Never throws and never fails a save.
 */
const { resolve } = require('path');
const { sysEnv, toArray } = require('@drumee/server-essentials');

// A save that brings this many new comments at once (a pasted, already
// commented document) notifies about the newest ones only.
const MAX_COMMENTS_PER_SAVE = 5;
const ID_RE = /^[0-9a-zA-Z_-]{1,32}$/;
const ANONYMOUS_UID = 'ffffffffffffffff';

// A server-team without the two modules (deployed after this plugin) is
// retried now and then rather than given up on until the next restart.
const RETRY_MS = 5 * 60 * 1000;
let _mods = null;
let _failedAt = 0;
function modules() {
  if (_mods) return _mods;
  if (_failedAt && Date.now() - _failedAt < RETRY_MS) return null;
  try {
    const { server_home } = sysEnv();
    _mods = {
      notify: require(resolve(server_home, 'service', 'lib', 'file-owner-notify')),
      comments: require(resolve(server_home, 'offline', 'media', 'office-comments')),
    };
  } catch (e) {
    _mods = null;
    _failedAt = Date.now();
  }
  return _mods;
}

/**
 * Run BEFORE the save overwrites the stored document. Finds the owner and,
 * only when somebody else took part in the save, reads the stored document's
 * comments -- so the common case, an owner editing their own document, costs
 * one lookup and never reads the file.
 * @returns {Promise<Object|null>} what notifyOfficeSave needs, or null when
 *   there is nobody to tell anything
 */
async function prepareOfficeSave(svc, { hub_id, nid, file, ext, editors }) {
  const m = modules();
  if (!m) return null;
  try {
    const people = toArray(editors);
    const owner = await m.notify.ownerOf(svc.yp, hub_id, nid);
    if (!owner || !people.some((p) => p && p.id !== owner)) return null;
    const before = m.comments.isOfficeDocument(ext) ? await m.comments.readComments(file, ext) : null;
    return { owner, people, before };
  } catch (e) {
    svc.warn('[euroffice] owner notification skipped:', e && e.message);
    return null;
  }
}

/**
 * The people behind this save, as { id, name }: who made its changes
 * (history.changes, with their editor names). Without a history, `fallback`
 * -- the saver -- stands for them; with one, the saver is not added, since the
 * last one to leave a session may only have been reading. Anonymous visitors
 * and malformed ids are left out.
 */
function saveParticipants(data, fallback) {
  const byId = new Map();
  const add = (id, name) => {
    id = id == null ? '' : String(id);
    if (!ID_RE.test(id) || id === ANONYMOUS_UID) return;
    const cur = byId.get(id);
    if (!cur) byId.set(id, { id, name: name || '' });
    else if (!cur.name && name) cur.name = name;
  };
  const history = (data && data.history) || {};
  for (const c of toArray(history.changes)) {
    if (c && c.user) add(c.user.id, c.user.name);
  }
  if (!byId.size) add(fallback);
  return [...byId.values()];
}

/**
 * @param {Object} svc the euroffice service (yp, payload, warn)
 * @param {Object} args
 *   hub_id, nid  the saved document
 *   file, ext    where its new bytes now are
 *   prepared     prepareOfficeSave()'s answer; null = nothing to do
 */
async function notifyOfficeSave(svc, { hub_id, nid, file, ext, prepared }) {
  const m = modules();
  if (!m || !prepared) return;
  try {
    const { notifyFileOwner, FILE_EDITED, FILE_COMMENTED } = m.notify;
    const { people, before } = prepared;
    // The editor names the comment author by the display name it was opened
    // with; fill in the ones the history did not carry.
    for (const p of people) {
      if (p.name) continue;
      try {
        const u = toArray(await svc.yp.await_proc('get_user', p.id))[0];
        if (u && u.fullname) p.name = u.fullname;
      } catch (e) { /* stays unnamed: only a userId match can find them */ }
    }

    const commenters = new Set();
    // An unreadable stored document (null) cannot be compared: announcing
    // every comment it holds as new would be wrong, so comments are skipped.
    if (Array.isArray(before)) {
      const after = await m.comments.readComments(file, ext);
      const added = m.comments.newComments(before, after).slice(-MAX_COMMENTS_PER_SAVE);
      for (const c of added) {
        const actor = m.comments.attributeComment(c, people);
        if (!actor) continue;
        commenters.add(actor);
        await notifyFileOwner(svc, { event: FILE_COMMENTED, hub_id, nid, actor, comment: c.text, source: 'office' });
      }
    }
    // Adding a comment is itself a change of the document, so whoever only
    // commented is told about as a commenter, not also as an editor.
    for (const p of people) {
      if (commenters.has(p.id)) continue;
      await notifyFileOwner(svc, { event: FILE_EDITED, hub_id, nid, actor: p.id, source: 'office' });
    }
  } catch (e) {
    svc.warn('[euroffice] owner notification skipped:', e && e.message);
  }
}

module.exports = { prepareOfficeSave, saveParticipants, notifyOfficeSave };
