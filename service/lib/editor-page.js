const { resolve } = require('path');
const { readFileSync } = require('fs');
const { template } = require('lodash');

const TEMPLATE = resolve(__dirname, '..', 'templates', 'editor.html');

/**
 * Serialize the editor config for injection into a <script> block.
 *
 * `<` is escaped so a filename containing `</script>` cannot close the block,
 * and the two Unicode line terminators are escaped because they are legal in
 * JSON but terminate a JavaScript line.
 */
function toScriptJson(config) {
  return JSON.stringify(config)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Render the document-server host page for a signed editor config.
 *
 * Both editor services (euroffice and onlyoffice) render the SAME template from
 * here. They used to carry a copy each — one of which pointed at a template file
 * that no longer existed, so that path threw ENOENT before it could reply — and
 * the copies had already drifted apart (only one of them forwarded
 * `editorConfig.lang`). One template is also what makes "the two editors behave
 * identically" true by construction rather than by review.
 *
 * @param {*} config the config object that was signed into `config.token`
 * @returns {string} a complete HTML document
 */
function renderEditorPage(config, integration = null) {
  const html = String(readFileSync(TEMPLATE)).trim();
  // The document server writes its iframe over this element, so the id only has
  // to be unique and valid. Derive it from the user id as before, but keep it to
  // characters that are safe unquoted in a CSS selector and an HTML attribute.
  const uid = String((config.editorConfig && config.editorConfig.user && config.editorConfig.user.id) || 'x');
  const placeholderId = `editor-${uid.replace(/[^A-Za-z0-9_-]/g, '') || 'x'}`;
  return template(html)({
    ...config,
    placeholderId,
    configJson: toScriptJson(config),
    // Menu integrations (Save Copy as…, Rename). Event handlers are functions,
    // so they can never be part of the signed config — the template attaches
    // them around it when this block is present.
    integrationJson: integration ? toScriptJson(integration) : null,
  });
}

module.exports = { renderEditorPage, toScriptJson };
