import { useEffect, useRef } from 'react';
import Icon from './Icon';
import { useFlash } from '../context';

function Flash({ id, category, message, onDone }) {
  const ref = useRef(null);
  // auto-dismiss success flashes after 6s with a fade (same as app.js)
  useEffect(() => {
    if (category !== 'success') return undefined;
    const t1 = setTimeout(() => {
      if (ref.current) { ref.current.style.transition = 'opacity .4s'; ref.current.style.opacity = '0'; }
    }, 6000);
    const t2 = setTimeout(() => onDone(id), 6450);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, [id, category, onDone]);

  return (
    <div ref={ref} className={`flash flash-${category}`}>
      <Icon name={category === 'success' ? 'check' : category === 'error' ? 'alert' : 'info'} />
      <span>{message}</span>
      <button type="button" className="flash-x" aria-label="Dismiss" onClick={() => onDone(id)}><Icon name="x" /></button>
    </div>
  );
}

export default function Flashes() {
  const { flashes, remove } = useFlash();
  if (!flashes.length) return null;
  return (
    <div className="flashes" role="status">
      {flashes.map((f) => <Flash key={f.id} {...f} onDone={remove} />)}
    </div>
  );
}
