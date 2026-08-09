/**
 * Correct permission bit values, pinned locally.
 *
 * This plugin depends on `@drumee/server-essentials` at `^1.2.29`, which
 * predates the 1.3.0 bit migration. In 1.2.x `Permission.write` is `0b0000100`
 * (= 4); in 1.3.x that bit became `download` and write moved to `0b0001000`
 * (= 8). The host runtime and the UI both run the 1.3.x model.
 *
 * Reading `Permission.write` from the bundled 1.2.x package therefore tested the
 * DOWNLOAD bit, so a member whose privilege was `chat` (0b0000111) satisfied it
 * and was handed the document editor in EDIT mode — and passed the write check
 * on the save callback too. A `view` member (0b0000011) failed it, which is why
 * the bug looked like "only chat can edit".
 *
 * Pinning the value here fixes it without bumping the dependency, which would
 * shift every other constant in the plugin at once. The dependency range is
 * still the underlying problem and should be raised separately.
 *
 * `Permission.read` (0b0000010) is IDENTICAL in both versions and is still read
 * from the package — only `write` moved.
 */
const WRITE = 0b0001000;

module.exports = { WRITE };
