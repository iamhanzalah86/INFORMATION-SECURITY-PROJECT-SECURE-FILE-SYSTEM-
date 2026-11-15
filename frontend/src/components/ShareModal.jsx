import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import Icon from './Icon';
import { timeAgo } from '../hooks';
import { api } from '../api';

/** Owner's sharing dialog: give another user read-only access to one file, or take it back. */
export default function ShareModal({ file, onClose, onChanged }) {
  const [shares, setShares] = useState(null);
  const [who, setWho] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState(null); // { text, bad }
  const [links, setLinks] = useState([]);
  const [days, setDays] = useState(7);
  const [fresh, setFresh] = useState(null); // full URL of the link just created (shown once)
  const [copied, setCopied] = useState(false);
  const inputRef = useRef(null);

  const load = useCallback(async () => {
    try {
      setShares((await api.listShares(file.id)).shares);
      setLinks((await api.listLinks(file.id)).links);
    }
    catch (err) { setShares([]); setNote({ text: err.message, bad: true }); }
  }, [file.id]);

  useEffect(() => {
    load();
    const prev = document.activeElement;
    if (inputRef.current) inputRef.current.focus();
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); };
  }, [load, onClose]);

  const run = async (fn) => {
    setBusy(true);
    try {
      const res = await fn();
      setNote({ text: res.message, bad: false });
      await load();
      onChanged();
    } catch (err) {
      setNote({ text: err.message, bad: true });
    }
    setBusy(false);
  };

  const add = (e) => {
    e.preventDefault();
    const value = who.trim();
    if (!value || busy) return;
    run(async () => { const res = await api.shareFile(file.id, value); setWho(''); return res; });
  };

  const makeLink = () => run(async () => {
    const res = await api.createLink(file.id, days);
    setFresh(`${window.location.origin}/s/${res.token}`);
    setCopied(false);
    return res;
  });

  const copy = async () => {
    try { await navigator.clipboard.writeText(fresh); setCopied(true); }
    catch (e) { setNote({ text: 'Select the link and copy it manually.', bad: true }); }
  };

  const expiresIn = (iso) => {
    const hrs = Math.max(0, (new Date(iso.endsWith('Z') ? iso : `${iso}Z`).getTime() - Date.now()) / 3600000);
    return hrs < 24 ? `${Math.max(1, Math.round(hrs))} hr` : `${Math.round(hrs / 24)} day${Math.round(hrs / 24) === 1 ? '' : 's'}`;
  };

  return createPortal(
    <div className="modal-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="card modal-card share-card" role="dialog" aria-modal="true" aria-labelledby="share-title">
        <button type="button" className="flash-x share-x" aria-label="Close" onClick={onClose}><Icon name="x" /></button>
        <div className="modal-ico ico-brand"><Icon name="share" /></div>
        <h3 id="share-title">Share '{file.original_filename}'</h3>
        <p>They can download a verified copy. They cannot change, delete or re-share it, and you can remove access at any time.</p>

        <form className="share-form" onSubmit={add}>
          <div className="input-wrap"><Icon name="user" />
            <input ref={inputRef} className="input" value={who} onChange={(e) => setWho(e.target.value)} placeholder="Username or email" aria-label="Username or email" autoComplete="off" /></div>
          <button className="btn btn-primary" type="submit" disabled={busy || !who.trim()}><Icon name="share" /> Share</button>
        </form>
        {note && <div className={`share-note${note.bad ? ' bad' : ''}`} role="status">{note.text}</div>}

        <div className="share-list">
          <div className="share-list-head">Share with a link</div>
          <div className="share-form">
            <select className="select" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Link expiry">
              <option value={1}>Expires in 1 day</option>
              <option value={7}>Expires in 7 days</option>
              <option value={30}>Expires in 30 days</option>
            </select>
            <button type="button" className="btn" disabled={busy} onClick={makeLink}><Icon name="share" /> Create link</button>
          </div>
          {fresh && (
            <div className="link-fresh">
              <input className="input" readOnly value={fresh} aria-label="Share link" onFocus={(e) => e.target.select()} />
              <button type="button" className="btn btn-primary" onClick={copy}><Icon name={copied ? 'check' : 'copy'} /> {copied ? 'Copied' : 'Copy'}</button>
              <small>Anyone with this link can read the file after signing in. Copy it now: it is shown only once.</small>
            </div>
          )}
          {links.map((l) => (
            <div key={l.id} className="share-row">
              <span className="avatar link-av"><Icon name="share" /></span>
              <div className="grow"><b>Link · expires in {expiresIn(l.expires_at)}</b><small>Created {timeAgo(l.created_at)} · opened by {l.uses}</small></div>
              <button type="button" className="btn btn-sm btn-danger" disabled={busy} onClick={() => run(() => api.revokeLink(file.id, l.id))}>Turn off</button>
            </div>
          ))}
        </div>

        <div className="share-list">
          <div className="share-list-head">People with access</div>
          {shares === null ? <div className="muted share-empty">Loading…</div>
            : shares.length === 0 ? <div className="muted share-empty">Only you can open this file.</div>
              : shares.map((s) => (
                <div key={s.id} className="share-row">
                  <span className="avatar">{s.username[0].toUpperCase()}</span>
                  <div className="grow"><b>{s.username}</b><small>Shared {timeAgo(s.created_at)}</small></div>
                  <button type="button" className="btn btn-sm btn-danger" disabled={busy} onClick={() => run(() => api.revokeShare(file.id, s.id))}>Remove</button>
                </div>
              ))}
        </div>
      </div>
    </div>,
    document.body,
  );
}
