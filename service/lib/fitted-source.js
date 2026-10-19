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
 * Which copy of a document the editor should be handed.
 *
 * A table wider than the printable page is cut at the page edge — the document
 * server renders faithfully, exactly as Word does, so the right-hand columns
 * simply are not drawn. Drumee already has an answer for this: the preview
 * pipeline (server-team offline/media/normalize-docx-sections.js) rewrites the
 * page geometry (orientation, margins, and the page width itself when nothing
 * else is enough) of a COPY, kept at `<nid>/fitted/orig.<ext>`. Content is
 * identical — only page geometry differs.
 *
 * The editor cannot wait for the preview pipeline: a document is opened
 * straight into the editor, so on a first open no preview has run and no
 * fitted copy exists. `ensureFitted` builds it on the spot, from the same
 * module the preview uses, so the geometry is still decided in ONE place.
 *
 * A fitted copy only counts while it is at least as new as the original: a
 * save from the editor (or a new upload) rewrites the original, and until the
 * copy is rebuilt the original is the honest source — never an older copy that
 * would silently drop the latest edits.
 *
 * Deliberately a NODE CLONE rather than a second send path: node content is
 * addressed as `<mfs_root>/<nid>/<format>.<ext>` and resolved through
 * `get_node_content`, which honours `target_nid`. Pointing a clone at the
 * sub-directory reuses the whole existing send — headers, accel redirect,
 * download filename — and cannot drift from it.
 */
const { existsSync, statSync, mkdirSync, renameSync, rmSync } = require('fs');
const { dirname, resolve } = require('path');
const { sysEnv } = require('@drumee/server-essentials');
const { MfsTools } = require('@drumee/server-core');

const { get_node_content } = MfsTools;

/** Sub-directory written by the preview pipeline (server-team to-pdf.js). */
const FITTED_DIR = 'fitted';
const WORDPROCESSING_EXT = new Set(['docx', 'docm', 'dotx', 'dotm']);

// "Nothing overflows" is the common answer and costs a full unzip + parse, so
// remember it per original version (path + mtime + size) instead of
// re-deriving it on every open.
const NO_FIT_CACHE_MAX = 1000;
const _noFit = new Map();

let _normalize; // resolved lazily: undefined = not tried, null = unavailable
function normalizer() {
  if (_normalize === undefined) {
    try {
      const { server_home } = sysEnv();
      _normalize = require(resolve(server_home, 'offline', 'media', 'normalize-docx-sections')).normalizeWideSections;
    } catch (e) {
      _normalize = null;
    }
  }
  return _normalize;
}

function fittedClone(node) {
  return { ...node, target_nid: `${node.id || node.nid}/${FITTED_DIR}` };
}

/** Original and fitted paths, or null when the node is not a wordprocessing doc. */
function paths(node) {
  if (!node || !(node.id || node.nid) || !(node.mfs_root || node.target_mfs_root)) return null;
  const ext = String(node.ext || node.extension || '').toLowerCase();
  if (!WORDPROCESSING_EXT.has(ext)) return null;
  const orig = get_node_content({ ...node, ext });
  const fitted = get_node_content({ ...fittedClone(node), ext });
  if (!orig || !fitted) return null;
  return { orig, fitted };
}

/** True when the fitted copy exists and is not older than the original. */
function isFresh(p) {
  try {
    if (!existsSync(p.fitted)) return false;
    return statSync(p.fitted).mtimeMs >= statSync(p.orig).mtimeMs;
  } catch (e) {
    return false;
  }
}

/**
 * Make sure a current fitted copy exists when the document needs one.
 * @param {Object} node the node resolved for this editor session
 * @returns {Promise<boolean>} true when the editor should be handed the fitted copy
 */
async function ensureFitted(node) {
  let tmp = null;
  try {
    const p = paths(node);
    if (!p || !existsSync(p.orig)) return false;
    if (isFresh(p)) return true;
    const st = statSync(p.orig);
    const sig = `${p.orig}:${st.mtimeMs}:${st.size}`;
    if (_noFit.has(sig)) return false;
    const normalize = normalizer();
    if (!normalize) return false;

    const dir = dirname(p.fitted);
    mkdirSync(dir, { recursive: true });
    // Build beside the target and rename into place, so a concurrent open (or
    // the preview pipeline) never reads a half-written copy.
    tmp = `${p.fitted}.${process.pid}.${Date.now()}.tmp`;
    const res = await normalize(p.orig, tmp);
    if (res && res.changed) {
      renameSync(tmp, p.fitted);
      tmp = null;
      return true;
    }
    rmSync(dir, { recursive: true, force: true });
    if (_noFit.size >= NO_FIT_CACHE_MAX) _noFit.delete(_noFit.keys().next().value);
    _noFit.set(sig, true);
  } catch (e) {
    /* any doubt about the derived copy -> serve the stored original */
  } finally {
    if (tmp) rmSync(tmp, { force: true });
  }
  return false;
}

/**
 * @param {Object} node the node resolved for this editor session
 * @returns {Object} `node`, or a clone addressing the page-fitted copy
 */
function editorSource(node) {
  try {
    const p = paths(node);
    if (p && isFresh(p)) return fittedClone(node);
  } catch (e) {
    /* any doubt about the derived copy -> serve the stored original */
  }
  return node;
}

module.exports = { editorSource, ensureFitted, FITTED_DIR };
