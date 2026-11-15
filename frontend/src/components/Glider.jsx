import { useLayoutEffect, useRef } from 'react';

/**
 * Liquid sliding "glass thumb" for tab-like rows (same effect as the reference video).
 *
 * Usage:
 *   const ref = useRef(null);
 *   useGlider(ref, activeKey);
 *   <div ref={ref} className="filter glass-tabs has-glider"><Glider /> ...buttons... </div>
 *
 * The active child is the one with class "active" or "on". When it changes, the thumb
 * stretches across both tabs and then settles with a small spring overshoot.
 */
export function Glider() {
  return <span className="glider" aria-hidden="true" />;
}

const px = (r) => ({
  left: `${r.left}px`, top: `${r.top}px`, width: `${r.width}px`, height: `${r.height}px`,
});
const same = (a, b) =>
  a.left === b.left && a.top === b.top && a.width === b.width && a.height === b.height;

export function useGlider(ref, activeKey, { duration = 560 } = {}) {
  const last = useRef(null);
  const placeRef = useRef(() => {});
  const observed = useRef(null);
  const observer = useRef(null);

  // runs after every render: cheap, and skips animation unless the position changed
  useLayoutEffect(() => {
    const box = ref.current;
    if (!box) return undefined;
    const glider = Array.from(box.children).find((c) => c.classList.contains('glider'));
    if (!glider) return undefined;

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const place = (animate) => {
      const el = Array.from(box.children).find(
        (c) => c !== glider && (c.classList.contains('active') || c.classList.contains('on')),
      );
      if (!el) { glider.classList.remove('ready'); last.current = null; return; }

      const next = { left: el.offsetLeft, top: el.offsetTop, width: el.offsetWidth, height: el.offsetHeight };
      const prev = last.current;
      Object.assign(glider.style, px(next));
      glider.classList.add('ready');
      last.current = next;
      if (!animate || reduced || !prev || same(prev, next) || !glider.animate) return;

      glider.getAnimations().forEach((a) => a.cancel());
      const l = Math.min(prev.left, next.left);
      const t = Math.min(prev.top, next.top);
      const r = Math.max(prev.left + prev.width, next.left + next.width);
      const b = Math.max(prev.top + prev.height, next.top + next.height);
      const horizontal = Math.abs(next.left - prev.left) >= Math.abs(next.top - prev.top);
      // stretched along the direction of travel, slightly squashed across it
      const mid = horizontal
        ? { left: l, width: r - l, top: next.top + 3, height: Math.max(next.height - 6, 1) }
        : { top: t, height: b - t, left: next.left + 3, width: Math.max(next.width - 6, 1) };

      glider.animate(
        [
          { ...px(prev), easing: 'cubic-bezier(.45,0,.55,1)' },
          { ...px({ ...next, ...mid }), offset: 0.4, easing: 'cubic-bezier(.34,1.35,.5,1)' },
          px(next),
        ],
        { duration },
      );
    };

    placeRef.current = place;
    place(true);

    // keep it aligned on resize / font load without animating
    if (observed.current !== box) {
      if (observer.current) observer.current.disconnect();
      observed.current = box;
      if ('ResizeObserver' in window) {
        observer.current = new ResizeObserver(() => placeRef.current(false));
        observer.current.observe(box);
      }
      if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => placeRef.current(false));
    }
    return undefined;
  });

  useLayoutEffect(() => () => { if (observer.current) observer.current.disconnect(); }, []);
  // activeKey is read by callers only to trigger a re-render; the effect above reacts to it
  return activeKey;
}
