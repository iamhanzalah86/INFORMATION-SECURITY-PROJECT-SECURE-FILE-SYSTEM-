// Shimmering placeholders shown while data loads (they sit inside normal glass cards).
const Bar = ({ w = '100%', h = 14, r, mt = 0 }) => (
  <div className="skel" style={{ width: w, height: h, borderRadius: r, marginTop: mt }} />
);

export function DashboardSkeleton() {
  return (
    <>
      <div className="page-head"><div><Bar w={260} h={30} /><Bar w={360} h={14} mt={12} /></div></div>
      <section className="stats">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="card stat">
            <div className="skel" style={{ width: 46, height: 46, borderRadius: 14, flex: 'none' }} />
            <div style={{ flex: 1 }}><Bar w="45%" h={24} /><Bar w="75%" h={12} mt={9} /></div>
          </div>
        ))}
      </section>
      <section className="grid-2">
        <div className="card card-pad" style={{ minHeight: 250 }}><Bar w="40%" h={18} /><Bar h={150} r={16} mt={18} /></div>
        <div className="card card-pad" style={{ minHeight: 250, display: 'grid', placeItems: 'center' }}>
          <div className="skel" style={{ width: 130, height: 130, borderRadius: '50%' }} />
        </div>
      </section>
      <TableSkeleton />
    </>
  );
}

export function TableSkeleton({ rows = 4 }) {
  return (
    <section className="card card-pad" style={{ marginBottom: 20 }}>
      <Bar w="22%" h={18} />
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} style={{ display: 'flex', gap: 14, alignItems: 'center', marginTop: 20 }}>
          <div className="skel" style={{ width: 40, height: 40, borderRadius: 12, flex: 'none' }} />
          <div style={{ flex: 1 }}><Bar w={`${55 - i * 6}%`} h={14} /><Bar w="30%" h={11} mt={8} /></div>
          <Bar w={70} h={24} r={99} />
        </div>
      ))}
    </section>
  );
}
