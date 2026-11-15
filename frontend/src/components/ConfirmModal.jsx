import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import Icon from './Icon';

/** Glass confirm dialog (replaces the browser's plain confirm()). Defaults suit a delete; pass icon / busyLabel for other actions. */
export default function ConfirmModal({
  title, children, confirmLabel = 'Delete', busyLabel = 'Deleting…', icon = 'trash', busy = false, onConfirm, onCancel,
}) {
  const cancelRef = useRef(null);
  useEffect(() => {
    const prev = document.activeElement;
    if (cancelRef.current) cancelRef.current.focus();
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); };
  }, [onCancel]);

  return createPortal(
    <div className="modal-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <div className="card modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <div className="modal-ico ico-bad"><Icon name={icon} /></div>
        <h3 id="modal-title">{title}</h3>
        <p>{children}</p>
        <div className="modal-actions">
          <button className="btn" type="button" ref={cancelRef} onClick={onCancel}>Cancel</button>
          <button className="btn btn-danger" type="button" onClick={onConfirm} disabled={busy}>
            <Icon name={icon} /> {busy ? busyLabel : confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
