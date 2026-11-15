import { useEffect, useState } from 'react';

/** "Resend code" button with a countdown. Pass seconds={60} like data-resend="60". */
export default function ResendButton({ seconds = 60, onClick, children = 'Resend code' }) {
  const [left, setLeft] = useState(seconds);
  useEffect(() => {
    if (left <= 0) return undefined;
    const t = setTimeout(() => setLeft((l) => l - 1), 1000);
    return () => clearTimeout(t);
  }, [left]);
  return (
    <button
      className="btn btn-ghost btn-block" type="button" disabled={left > 0}
      onClick={() => { onClick && onClick(); setLeft(seconds); }}
    >
      {left > 0 ? `${children} (${left}s)` : children}
    </button>
  );
}
