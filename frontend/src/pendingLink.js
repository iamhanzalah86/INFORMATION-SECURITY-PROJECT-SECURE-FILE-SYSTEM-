// Remembers a share link opened by a visitor, so that after they log in or sign up
// (in the same browser tab) they land back on the link and get access to the file.
const KEY = 'sv_pending_link';

export function rememberLink(token) {
  try { sessionStorage.setItem(KEY, token); } catch (e) { /* storage unavailable */ }
}
export function forgetLink() {
  try { sessionStorage.removeItem(KEY); } catch (e) { /* storage unavailable */ }
}
/** Path of the waiting share link ("/s/<token>"), or null. */
export function pendingLinkPath() {
  try {
    const t = sessionStorage.getItem(KEY);
    return t && /^[A-Za-z0-9_-]{20,200}$/.test(t) ? `/s/${t}` : null;
  } catch (e) {
    return null;
  }
}
