// Renders a timestamp in the viewer's local time (same formats app.js produced).
export default function Time({ value, mode = 'full' }) {
  if (!value) return <>—</>;
  const iso = typeof value === 'string' && !/[zZ]|[+-]\d\d:?\d\d$/.test(value) ? `${value}Z` : value;
  const d = new Date(iso);
  if (isNaN(d)) return <>—</>;
  const text = mode === 'date'
    ? d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
    : d.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  return <time dateTime={d.toISOString()}>{text}</time>;
}
