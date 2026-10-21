/**
 * Offline checks: a document opened from a comment notification is opened ON
 * that comment (editorConfig.actionLink), and nothing else changes.
 *   node test/editor-config-comment.test.js
 */
const assert = require('assert');
const { buildEditorConfig, commentGuidOf } = require('../service/lib/editor-config');

const base = { extension: 'docx', filename: 'a.docx', sessionKey: 'h.n.1', mode: 'edit', uid: 'u', fullname: 'U', uiTheme: 't', readUrl: 'r', callbackUrl: 'c', nid: 'n', hub_id: 'h', documentServerUrl: 'd' };

const plain = buildEditorConfig(base);
assert.strictEqual(plain.editorConfig.actionLink, undefined, 'no comment, no actionLink');

const docx = buildEditorConfig({ ...base, commentGuid: '708DA857' });
assert.deepStrictEqual(docx.editorConfig.actionLink, { action: { type: 'comment', data: '708DA857' } });
const xlsx = buildEditorConfig({ ...base, extension: 'xlsx', commentGuid: '{00B2000D-00B1-4AAB-B0FF-00A4008A0022}' });
assert.strictEqual(xlsx.editorConfig.actionLink.action.data, '{00B2000D-00B1-4AAB-B0FF-00A4008A0022}');

// Everything else is exactly what it was.
const { actionLink, ...rest } = docx.editorConfig;
assert.deepStrictEqual(rest, plain.editorConfig);

// Only the two id shapes the editor uses get through.
for (const bad of ['', null, '"><script>', 'GHIJKLMN', '123456789', '{not-a-guid}', 'javascript:x']) {
  assert.strictEqual(commentGuidOf(bad), null, String(bad));
  assert.strictEqual(buildEditorConfig({ ...base, commentGuid: bad }).editorConfig.actionLink, undefined);
}
console.log('editor-config comment: ok');
