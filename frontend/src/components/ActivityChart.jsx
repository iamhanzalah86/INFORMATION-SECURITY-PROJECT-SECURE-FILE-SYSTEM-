// Small 7-day activity chart (inline SVG, colours come from the theme variables).
export default function ActivityChart({ activity }) {
  const W = 320, H = 150, base = 118, top = 14, bw = 28;
  const max = Math.max(1, ...activity.map((d) => d.total));
  const step = W / activity.length;
  const total = activity.reduce((s, d) => s + d.total, 0);
  const alerts = activity.reduce((s, d) => s + d.alerts, 0);
  const label = (iso) => new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined, { weekday: 'short', timeZone: 'UTC' });

  return (
    <div className="card-pad chart-wrap">
      <div className="chart-sum">
        <div><b>{total}</b><small>events</small></div>
        <div><b className={alerts ? 'bad' : ''}>{alerts}</b><small>alerts</small></div>
      </div>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Security events over the last 7 days">
        <line className="chart-axis" x1="0" x2={W} y1={base + 0.5} y2={base + 0.5} />
        {activity.map((d, i) => {
          const x = i * step + (step - bw) / 2;
          const h = (d.total / max) * (base - top);
          const hAlert = d.total ? (d.alerts / d.total) * h : 0;
          const hOk = h - hAlert;
          return (
            <g key={d.date} className="bar-group">
              <title>{`${label(d.date)}: ${d.total} event${d.total === 1 ? '' : 's'}${d.alerts ? `, ${d.alerts} alert${d.alerts === 1 ? '' : 's'}` : ''}`}</title>
              <rect className="bar-hit" x={x - 4} y={top} width={bw + 8} height={base - top} />
              {d.total === 0 && <rect className="bar-empty" x={x} y={base - 3} width={bw} height="3" rx="1.5" />}
              {hOk > 0 && <rect className="bar-ok" style={{ animationDelay: `${i * 55}ms` }} x={x} y={base - hOk} width={bw} height={hOk} rx="6" />}
              {hAlert > 0 && <rect className="bar-bad" style={{ animationDelay: `${i * 55 + 120}ms` }} x={x} y={base - h} width={bw} height={hAlert} rx="6" />}
              <text className="bar-label" x={x + bw / 2} y={H - 8} textAnchor="middle">{label(d.date)}</text>
            </g>
          );
        })}
      </svg>
      {total === 0 && <p className="muted chart-note">No activity in the last 7 days.</p>}
    </div>
  );
}
