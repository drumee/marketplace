/**
 * Offline checks for the office-editor host page and config.
 *
 * These cover the parts that broke silently before: a config field that never
 * reached the browser, and a documentType the template referenced but the server
 * never set. Neither needs a database, a document server or a session — run with
 *   node test/editor-config.test.js
 */
const assert = require('assert');
const { documentTypeOf } = require('../service/lib/doc-type');
const { renderEditorPage } = require('../service/lib/editor-page');
const { buildEditorConfig, EDITOR_LANG } = require('../service/lib/editor-config');

let checks = 0;
function check(what, fn) { fn(); checks++; console.log('  ok  ' + what); }

/**
 * The real config the services build — this calls the same function
 * service/euroffice.js and service/onlyoffice.js call, so the assertions below
 * bind to production behaviour rather than to a copy of it.
 */
function buildConfig({ ext = 'docx', filename = 'Report.docx', mode = 'edit', lang = 'en' } = {}) {
  const config = buildEditorConfig({
    extension: ext,
    filename,
    sessionKey: 'hub1.node1.1700000000',
    mode,
    uid: '4242',
    fullname: 'Test User',
    uiTheme: 'theme-light',
    lang,
    readUrl: 'https://host/svc/euroffice.read?signature=deadbeef',
    callbackUrl: 'https://host/svc/euroffice.callback?key=hub1.node1.1700000000',
    nid: 'node1',
    hub_id: 'hub1',
    documentServerUrl: 'https://docs.example.org',
  });
  // The services add the signature after building, exactly as here.
  config.token = 'signed.jwt.value';
  return config;
}

/** Pull the object the browser will actually evaluate back out of the page. */
function configFromPage(html) {
  const m = html.match(/\n\s*var config = (\{.*\});\n/);
  assert.ok(m, 'the page must declare `var config = {...};`');
  // The page escapes `<` as < so a filename cannot close the script block;
  // a JS engine would undo that when evaluating the literal, so undo it here.
  return JSON.parse(m[1].replace(/\\u003c/g, '<'));
}

console.log('\ndocumentTypeOf covers every extension the desk offers for editing');
// Mirrors ui-team src/drumee/builtins/player/document/editable.js. A wrong family
// here loads the wrong editor app entirely.
const EDITABLE = {
  word: ['doc', 'docx', 'docm', 'dotx', 'dotm', 'odt', 'ott', 'rtf'],
  cell: ['xlsx', 'xls', 'xlsm', 'xltx', 'xltm', 'xlsb', 'ods', 'ots'],
  slide: ['pptx', 'ppt', 'pptm', 'potx', 'potm', 'ppsx', 'ppsm', 'odp', 'otp'],
};
for (const family of Object.keys(EDITABLE)) {
  for (const ext of EDITABLE[family]) {
    check(`${ext} -> ${family}`, () => assert.strictEqual(documentTypeOf(ext), family));
  }
}
check('pdf -> pdf', () => assert.strictEqual(documentTypeOf('pdf'), 'pdf'));
check('leading dot and upper case are tolerated', () => {
  assert.strictEqual(documentTypeOf('.XLSX'), 'cell');
});
check('an unknown extension falls back to word, never undefined', () => {
  assert.strictEqual(documentTypeOf('wat'), 'word');
  assert.strictEqual(documentTypeOf(undefined), 'word');
});

console.log('\nthe host page is a real, full-height document');
const page = renderEditorPage(buildConfig({ ext: 'xlsx', filename: 'Budget.xlsx' }));
check('starts with a doctype, so the browser is in standards mode', () => {
  assert.ok(/^<!doctype html>/i.test(page));
});
check('html and body are given a definite height', () => {
  assert.ok(/html,\s*\n?\s*body\s*\{[^}]*height:\s*100%/.test(page));
});
check('the body margin is zeroed', () => {
  assert.ok(/html,\s*\n?\s*body\s*\{[^}]*margin:\s*0/.test(page));
});
check('the editor iframe is block-level, killing the baseline descender gap', () => {
  assert.ok(/iframe\s*\{[^}]*display:\s*block/.test(page.replace(/\/\*[\s\S]*?\*\//g, '')));
});

console.log('\nthe browser config carries what the editor actually reads');
const cell = configFromPage(page);
check('documentType is top level and correct for a spreadsheet', () => {
  assert.strictEqual(cell.documentType, 'cell');
  assert.strictEqual(cell.document.documentType, undefined);
});
check('forcesave sits in editorConfig.customization, not at the top level', () => {
  assert.strictEqual(cell.editorConfig.customization.forcesave, true);
  assert.strictEqual(cell.customization, undefined);
});
check('the right panel starts collapsed', () => {
  assert.strictEqual(cell.editorConfig.customization.hideRightMenu, true);
});
check('a spreadsheet keeps its natural zoom', () => {
  assert.strictEqual(cell.editorConfig.customization.zoom, undefined);
});
check('a text document opens fitted to the frame width', () => {
  const word = configFromPage(renderEditorPage(buildConfig({ ext: 'docx' })));
  assert.strictEqual(word.editorConfig.customization.zoom, -2);
});

console.log('\nthe page and the signed token cannot drift apart');
check('every field of the signed object reaches the browser verbatim', () => {
  const signed = buildConfig({ ext: 'pptx', filename: 'Deck.pptx' });
  const sent = configFromPage(renderEditorPage(signed));
  // The old template re-listed fields by hand and quietly dropped the rest.
  assert.deepStrictEqual(sent, signed);
});

console.log('\npermissions track the mode the editor is opened in');
check('edit mode grants edit', () => {
  assert.strictEqual(configFromPage(renderEditorPage(buildConfig({ mode: 'edit' })))
    .document.permissions.edit, true);
});
check('view mode withholds it, so no "Edit document" escape hatch is offered', () => {
  assert.strictEqual(configFromPage(renderEditorPage(buildConfig({ mode: 'view' })))
    .document.permissions.edit, false);
});

console.log('\na hostile filename cannot break out of the page');
check('</script> in a filename neither closes the block nor injects markup', () => {
  const nasty = '</script><img src=x onerror=alert(1)>.docx';
  const html = renderEditorPage(buildConfig({ filename: nasty }));
  const body = html.slice(html.indexOf('<body>'));
  assert.ok(!/<img src=x/.test(body), 'no raw markup in the body');
  assert.ok(!/<\/script><img/.test(html), 'the script block is not closed early');
  assert.strictEqual(configFromPage(html).document.title, nasty, 'the title survives intact');
});
check('the <title> element is HTML-escaped', () => {
  const html = renderEditorPage(buildConfig({ filename: '<b>x</b>.docx' }));
  assert.ok(/<title>&lt;b&gt;x&lt;\/b&gt;\.docx<\/title>/.test(html));
});

console.log('\nthe editor UI language is always English, by decision');
check('the pinned language is English', () => {
  assert.strictEqual(EDITOR_LANG, 'en');
});
check('no session or query language can change it', () => {
  assert.strictEqual(buildConfig({ lang: 'fr' }).editorConfig.lang, 'en');
  assert.strictEqual(buildConfig({ lang: 'FR-CA' }).editorConfig.lang, 'en');
  assert.strictEqual(buildConfig({ lang: undefined }).editorConfig.lang, 'en');
});

console.log('\nFile-menu integrations (Save Copy as…, Rename)');
// Relative on purpose — resolved against the page URL so the fetch stays on
// the SAME origin as the served page (hub subdomains included) and carries the
// session cookie. An absolute main-domain URL arrives anonymous and is denied.
const INTEGRATION = {
  nid: 'node1',
  hub_id: 'hub1',
  ext: 'docx',
  docKey: 'hub1.node1.1700000000',
  saveAsUrl: 'euroffice.save_as',
  renameUrl: 'media.rename',
  retitleUrl: 'euroffice.retitle',
};
check('an edit session page wires both editor events', () => {
  const html = renderEditorPage(buildConfig(), INTEGRATION);
  assert.ok(/onRequestSaveAs/.test(html));
  assert.ok(/onRequestRename/.test(html));
  assert.ok(/euroffice\.save_as/.test(html));
  assert.ok(/media\.rename/.test(html));
});
check('without an integration block the page declares no events', () => {
  const html = renderEditorPage(buildConfig());
  assert.ok(!/onRequestSaveAs/.test(html));
  assert.ok(!/config\.events/.test(html));
});
check('the signed config itself never carries events', () => {
  const config = buildConfig();
  assert.strictEqual(config.events, undefined);
});

console.log('\nboth services are configured by the same builder');
check('euroffice and onlyoffice call buildEditorConfig, not a local literal', () => {
  const fs = require('fs');
  for (const f of ['service/euroffice.js', 'service/onlyoffice.js']) {
    const src = fs.readFileSync(require('path').join(__dirname, '..', f), 'utf8');
    assert.ok(/buildEditorConfig\(\{/.test(src), f + ' must build its config through the shared builder');
    assert.ok(!/^\s*customization: \{/m.test(src),
      f + ' must not reintroduce a top-level customization block');
  }
});
check('neither service still points at a deleted template', () => {
  const fs = require('fs');
  for (const f of ['service/euroffice.js', 'service/onlyoffice.js']) {
    const src = fs.readFileSync(require('path').join(__dirname, '..', f), 'utf8');
    // Quote-anchored: a path in code, not the word in an explanatory comment.
    assert.ok(!/['"]templates\/(index|euroffice|onlyoffice)\.html['"]/.test(src),
      f + ' references a template file that no longer exists');
  }
  assert.ok(fs.existsSync(require('path').join(__dirname, '..', 'service/templates/editor.html')));
});

console.log(`\n${checks} checks passed\n`);
