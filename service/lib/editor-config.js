const { documentTypeOf } = require('./doc-type');

/**
 * The editor UI is ALWAYS English — product decision (2026-08-22). Left to its
 * own devices the document server picks its own default (the French-toolbar
 * incident); pinning the value here means no session language, profile
 * setting, or query parameter can change it.
 */
const EDITOR_LANG = 'en';

/**
 * Build the document-server config, ready to be signed.
 *
 * Both editor services build the SAME object here. They used to build one each,
 * and the copies had already drifted — only euroffice forwarded the UI language,
 * so which editor the `doc_editor` sysconf named decided whether the toolbars
 * came up in the session's language. Anything that belongs in "the editor should
 * behave the same everywhere" belongs in this function.
 *
 * The caller signs the returned object and hands it to renderEditorPage, which
 * emits it verbatim — so there is exactly one description of the editor, and the
 * token and the browser config cannot disagree.
 */
function buildEditorConfig(opt) {
  const {
    extension, filename, sessionKey, mode, uid, fullname,
    uiTheme, readUrl, callbackUrl, nid, hub_id, documentServerUrl,
  } = opt;

  // Selects which editor the document server loads, and with it the chrome the
  // user gets: the spreadsheet status bar (sheet tabs and the "+" add-sheet
  // button), the text ruler, the slide list, the right-hand settings panel. It
  // was absent from the signed config, and the template referenced it as
  // `document.documentType` — a property that did not exist on the object, and
  // not where the document server reads it from (it is top level).
  const documentType = documentTypeOf(extension);
  const canEdit = mode === 'edit';

  return {
    document: {
      fileType: extension,
      key: sessionKey,
      title: filename,
      // Spelled out rather than left to the document server's defaults, and
      // derived from the same `mode` the editor is opened in. When the two
      // disagree the editor draws editable chrome over a document the permission
      // layer will not let you manipulate — dragging a row or column by its
      // header, the fill handle, moving a selection are the first gestures it
      // refuses — which reads as "drag and drop is broken" rather than as "this
      // document is read-only". `edit: false` also withdraws the viewer's
      // "Edit document" button, which previously offered a read-only user an
      // editing session whose saves the callback would then reject in silence.
      permissions: {
        edit: canEdit,
        download: true,
        print: true,
      },
      url: readUrl,
    },
    documentType,
    // Match the box the host page gives the editor (see templates/editor.html).
    width: '100%',
    height: '100%',
    editorConfig: {
      mode,
      lang: EDITOR_LANG,
      callbackUrl,
      user: {
        id: uid,
        name: fullname,
      },
      customization: {
        uiTheme,
        // The Save button. `forcesave` used to sit in a `customization` block at
        // the TOP level of the config, which is not where the document server
        // reads it from — it reads `editorConfig.customization` — and the old
        // template did not copy that block to the browser at all. Genuinely
        // absent, the editor autosaves silently and leaves the Save button
        // permanently disabled. Enabled, the button stays live and each press
        // forces a save-and-version through the callback.
        forcesave: true,
        // Open with the right-hand settings panel collapsed, as Word and Google
        // Workspace do. It is still one click away on its icon rail.
        hideRightMenu: true,
        // Text documents open fitted to the width of the frame (-2), so a page
        // wider than the window is scaled to fit instead of running off the
        // right edge. Spreadsheets and slides keep their natural zoom, which is
        // what Excel and Sheets do.
        ...(documentType === 'word' ? { zoom: -2 } : {}),
      },
    },
    // Your custom Drumee data
    drumeeContext: {
      nid,
      hub_id,
    },
    documentServerUrl,
  };
}

module.exports = { buildEditorConfig, EDITOR_LANG };
