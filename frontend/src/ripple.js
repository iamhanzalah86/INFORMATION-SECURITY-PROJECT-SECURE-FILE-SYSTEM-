// Soft click ripple on every .btn (event delegation, no per-button code needed).
document.addEventListener(
  'pointerdown',
  (e) => {
    const btn = e.target.closest && e.target.closest('.btn');
    if (!btn || btn.disabled || e.button > 0) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const r = btn.getBoundingClientRect();
    const size = Math.max(r.width, r.height) * 2;
    const s = document.createElement('span');
    s.className = 'ripple';
    s.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - r.left - size / 2}px;top:${e.clientY - r.top - size / 2}px`;
    btn.appendChild(s);
    const done = () => s.remove();
    s.addEventListener('animationend', done);
    setTimeout(done, 900);
  },
  { passive: true },
);
