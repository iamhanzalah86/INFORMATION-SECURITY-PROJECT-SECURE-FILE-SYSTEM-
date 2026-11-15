import { useEffect, useRef, useState } from 'react';
import Icon from '../components/Icon';
import Time from '../components/Time';
import HashText from '../components/HashText';
import { TableSkeleton } from '../components/Skeleton';
import { Glider, useGlider } from '../components/Glider';
import { eventCategory, eventTitle, useTitle } from '../hooks';
import { api } from '../api';

const FILTERS = [['all', 'All'], ['alerts', 'Alerts'], ['files', 'Files'], ['scans', 'Scans'], ['account', 'Account']];

// Ported from security_events.html
export default function SecurityEvents() {
  useTitle('Security events');
  const [events, setEvents] = useState(null);
  const [filter, setFilter] = useState('all');
  const filterRef = useRef(null);
  useGlider(filterRef, filter);

  useEffect(() => { api.getEvents().then(setEvents); }, []);
  if (!events) {
    return (
      <>
        <div className="page-head"><div><h1>Security events</h1><p>Loading your audit trail…</p></div></div>
        <TableSkeleton rows={6} />
      </>
    );
  }

  const rows = events.filter((e) => filter === 'all' || eventCategory(e.event_type) === filter);

  return (
    <>
      <div className="page-head">
        <div><h1>Security events</h1><p>Your most recent {events.length} audit-trail entries.</p></div>
      </div>

      <section className="card">
        <div className="card-head">
          <div className="filter glass-tabs has-glider" ref={filterRef}>
            <Glider />
            {FILTERS.map(([key, label]) => (
              <button key={key} className={`pill${filter === key ? ' on' : ''}`} type="button" onClick={() => setFilter(key)}>{label}</button>
            ))}
          </div>
        </div>
        {events.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>When</th><th>Event</th><th className="hide-sm">File</th><th>Details</th></tr></thead>
              <tbody id="events-body">
                {rows.map((e) => {
                  const c = eventCategory(e.event_type);
                  return (
                    <tr key={e.id} data-cat={c}>
                      <td className="muted" style={{ whiteSpace: 'nowrap' }}><Time value={e.timestamp} /></td>
                      <td>
                        <span
                          className={`badge ${c === 'alerts' ? 'badge-bad' : c === 'files' || c === 'scans' ? 'badge-ok' : ''}`}
                          style={c === 'account' ? { background: 'var(--info-soft)', color: 'var(--info)' } : undefined}
                        >{eventTitle(e.event_type)}</span>
                      </td>
                      <td className="hide-sm">{e.file_id ? <span className="tag">#{e.file_id}</span> : <span className="muted">—</span>}</td>
                      <td style={{ overflowWrap: 'anywhere', minWidth: 220 }}><HashText text={e.description} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty"><div className="big"><Icon name="activity" /></div><b>No events yet</b>Security events will appear here as you use your vault.</div>
        )}
      </section>
    </>
  );
}
