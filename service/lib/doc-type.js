/**
 * Map a file extension onto the OnlyOffice editor family.
 *
 * `documentType` is what selects the editor the document server loads, and with
 * it the chrome the user gets: the spreadsheet status bar (sheet tabs and the
 * "+" add-sheet button), the text ruler, the presentation slide list, and the
 * right-hand settings panel.
 *
 * It was never part of the config we signed. The template referenced it as
 * `document.documentType` — a property that does not exist on the object, so
 * lodash interpolated an empty string, in a place OnlyOffice no longer reads it
 * from (it is a TOP-LEVEL key, sibling of `document`). The editor therefore fell
 * back to guessing from `fileType` on every open.
 *
 * Extension lists follow the document server's own conversion table. Anything
 * unknown is treated as a text document, which is the document server's own
 * fallback.
 */
const FAMILIES = {
  word: [
    'doc', 'docm', 'docx', 'docxf', 'dot', 'dotm', 'dotx', 'epub', 'fb2',
    'fodt', 'htm', 'html', 'mht', 'mhtml', 'md', 'odt', 'oform', 'ott', 'rtf',
    'stw', 'sxw', 'txt', 'wps', 'wpt', 'xml',
  ],
  cell: [
    'csv', 'et', 'ett', 'fods', 'numbers', 'ods', 'ots', 'sxc', 'xls', 'xlsb',
    'xlsm', 'xlsx', 'xlt', 'xltm', 'xltx',
  ],
  slide: [
    'dps', 'dpt', 'fodp', 'key', 'odp', 'otp', 'pot', 'potm', 'potx', 'pps',
    'ppsm', 'ppsx', 'ppt', 'pptm', 'pptx', 'sxi',
  ],
  pdf: ['djvu', 'oxps', 'pdf', 'xps'],
};

const INDEX = {};
for (const family of Object.keys(FAMILIES)) {
  for (const ext of FAMILIES[family]) INDEX[ext] = family;
}

/**
 * @param {*} extension file extension, with or without a leading dot
 * @returns {string} one of 'word' | 'cell' | 'slide' | 'pdf'
 */
function documentTypeOf(extension) {
  const ext = String(extension || '').toLowerCase().replace(/^\./, '').trim();
  return INDEX[ext] || 'word';
}

module.exports = { documentTypeOf };
