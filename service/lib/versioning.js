// service/lib/versioning.js
//
// Version snapshots for documents saved through an external office editor
// (EurOffice / OnlyOffice).
//
// Everywhere else in Drumee a version is taken by media.js `_snapshot_version`,
// which runs on the media service just before media.save / media.replace
// overwrites the blob. The office editors never go through those services: the
// document server hands back a URL and the plugin downloads it straight over
// `orig.{ext}` (see euroffice.importFile). So editing a .docx or .xlsx left no
// history at all, while a note edited in the built-in markdown editor did —
// the same "Version history" row of the pricing table covering one and not the
// other.
//
// The ordering matters and is the whole reason this is not a one-liner. The
// snapshot has to capture the bytes that are ABOUT TO BE REPLACED, but whether
// a version is warranted at all is only knowable after the download, by
// comparing the new md5 with the stored one. Taking the copy afterwards would
// snapshot the new content; skipping the copy until the md5 is known would find
// the old content already gone. So: stash first, decide after.
//
//   const pending = await stashCurrent(node)      // before the download
//   ... download overwrites orig.{ext} ...
//   await commitVersion(ctx, { node, db_name, pending, newMd5, uid })
//
// commitVersion drops the stash when nothing changed, so an editor session that
// closes without edits (or one the document server re-posts) costs nothing.
//
// Rows land in the node's own `file_version` table, which is what
// file_version_list / _purge_expired already read — so the retention policy
// (now plan-driven, capped by quota.$.history_length) applies to office
// documents automatically, with no worker change.

const { resolve } = require('path');
const {
  existsSync, mkdirSync, copyFileSync, renameSync, unlinkSync,
} = require('fs');

// Where a node keeps its versions. Mirrors media.js so both writers agree.
function versionsDir(node) {
  const root = node.mfs_root || node.home_dir;
  return resolve(root, node.id || node.nid, 'versions');
}

function origPath(node) {
  const root = node.mfs_root || node.home_dir;
  const ext = node.extension || node.ext;
  return resolve(root, node.id || node.nid, `orig.${ext}`);
}

/**
 * Copy the file as it stands right now to a side location, so the download may
 * safely overwrite the original. Returns the stash path, or null when there is
 * nothing to preserve (a brand-new node has no blob yet).
 *
 * Never throws: a snapshot must not be able to fail a document save.
 */
async function stashCurrent(node) {
  try {
    const ext = node.extension || node.ext;
    if (!node || !(node.id || node.nid) || !ext) return null;
    const src = origPath(node);
    if (!existsSync(src)) return null;
    const dir = versionsDir(node);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    // Not the final name: the version id only exists once the row is created.
    const stash = resolve(dir, `.pending-${Date.now()}-${process.pid}.${ext}`);
    copyFileSync(src, stash);
    return stash;
  } catch (e) {
    return null;
  }
}

/**
 * Turn a stash into a version row, or discard it.
 *
 * @param {Object} ctx      the calling service (needs .yp and .warn)
 * @param {Object} o
 * @param {Object} o.node   node as returned by mfs_access_node
 * @param {string} o.db_name the node's database
 * @param {string} o.pending stash path from stashCurrent (may be null)
 * @param {string} o.newMd5  md5 of the freshly downloaded content
 * @param {string} o.uid     who saved
 * @param {number} o.oldSize size of the previous content, when known
 * @returns {Promise<number|null>} the file_version id, or null
 */
async function commitVersion(ctx, { node, db_name, pending, newMd5, uid, oldSize } = {}) {
  if (!pending) return null;
  const drop = () => { try { if (existsSync(pending)) unlinkSync(pending); } catch (e) { /* nothing to do */ } };
  try {
    // Same rule as media.js: identical bytes are not a new version. The
    // document server re-posts on every session close, so without this a user
    // who opened a file and closed it would accrue a version each time.
    if (newMd5 && node.md5Hash && newMd5 === node.md5Hash) {
      drop();
      return null;
    }
    const ext = node.extension || node.ext;
    const nid = node.id || node.nid;
    const filename = node.user_filename || node.filename || '';
    // The size of what is being archived, i.e. the PREVIOUS content. node
    // still carries it at this point because the caller updates the row after.
    const filesize = parseInt(oldSize != null ? oldSize : node.filesize, 10) || 0;

    const reserved = await ctx.yp.await_proc(
      `${db_name}.file_version_create`, nid, filename, filesize, '', uid
    );
    const row = Array.isArray(reserved) ? reserved[0] : reserved;
    if (!row || !row.id) { drop(); return null; }
    const versionId = row.id;

    const dest = resolve(versionsDir(node), `${versionId}.${ext}`);
    renameSync(pending, dest);
    await ctx.yp.await_run(
      `UPDATE ${db_name}.file_version SET file_path = ? WHERE id = ?`,
      [dest, versionId]
    );

    // Charge the archived bytes to the hub, the way media.js does — version
    // history consumes the customer's quota and the figure must say so.
    const hub_id = node.hub_id;
    if (filesize > 0 && hub_id) {
      try {
        await ctx.yp.await_run(
          `UPDATE yp.disk_usage SET size = GREATEST(0, IFNULL(size, 0) + ?) WHERE hub_id = ?`,
          [filesize, hub_id]
        );
      } catch (e) {
        ctx.warn && ctx.warn('[VERSION] disk_usage update failed:', e && e.message);
      }
    }
    return versionId;
  } catch (e) {
    ctx.warn && ctx.warn('[VERSION] office snapshot failed:', e && e.message);
    drop();
    return null;
  }
}

module.exports = { stashCurrent, commitVersion };
