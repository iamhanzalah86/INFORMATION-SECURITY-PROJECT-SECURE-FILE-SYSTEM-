import { useState } from 'react';
import Icon from './Icon';

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (err) { /* ignore */ }
    ta.remove();
    return ok;
  }
}

function HashChip({ hash }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    if (await copyText(hash)) {
      setDone(true);
      setTimeout(() => setDone(false), 1600);
    }
  };
  return (
    <span className="hash-chip" title={hash}>
      <code>{hash.slice(0, 12)}…</code>
      <button type="button" className="copy-btn" onClick={copy} aria-label="Copy full hash">
        <Icon name={done ? 'check' : 'copy'} />
      </button>
    </span>
  );
}

/** Shows text, turning any 64-character SHA-256 hash into a short, copyable chip. */
export default function HashText({ text }) {
  const parts = String(text || '').split(/([a-f0-9]{64})/gi);
  return (
    <>
      {parts.map((p, i) => (/^[a-f0-9]{64}$/i.test(p) ? <HashChip key={i} hash={p} /> : <span key={i}>{p}</span>))}
    </>
  );
}
