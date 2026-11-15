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
  const inputRef = useRef(null);

  const load = useCallback(async () => {
    try { setShares((await api.listShares(file.id)).shares); }
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
