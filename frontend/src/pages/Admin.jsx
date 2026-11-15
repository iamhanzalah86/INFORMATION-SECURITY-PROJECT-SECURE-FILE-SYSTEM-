import { useCallback, useEffect, useRef, useState } from 'react';
import { Navigate } from 'react-router-dom';
import Icon from '../components/Icon';
import Time from '../components/Time';
import HashText from '../components/HashText';
import ConfirmModal from '../components/ConfirmModal';
import { TableSkeleton } from '../components/Skeleton';
import { Glider, useGlider } from '../components/Glider';
import { useAuth, useFlash } from '../context';
import { eventCategory, eventTitle, timeAgo, useTitle } from '../hooks';
import { api } from '../api';

const FILTERS = [['all', 'All'], ['alerts', 'Alerts'], ['files', 'Files'], ['scans', 'Scans'], ['account', 'Account']];
const ROLE_LABEL = { user: 'User', analyst: 'Security analyst', admin: 'Administrator' };

/**
 * Admin console (role-based access control).
 *  - analyst: read-only monitoring of every account's security events
 *  - admin:   the same, plus assigning roles and disabling accounts
 * The server enforces this (app/rbac.py); hiding things here is only for tidiness.
 */
export default function Admin() {
  useTitle('Admin');
  const { user } = useAuth();
  const { flash, clear } = useFlash();
  const isAdmin = user.role === 'admin';
  const isStaff = isAdmin || user.role === 'analyst';

  const [overview, setOverview] = useState(null);
  const [users, setUsers] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [confirm, setConfirm] = useState(null); // account about to be disabled
  const [filter, setFilter] = useState('all');
  const filterRef = useRef(null);
  useGlider(filterRef, filter);

  const load = useCallback(async () => {
    setOverview(await api.adminOverview());
    if (isAdmin) setUsers((await api.adminUsers()).users);
  }, [isAdmin]);

  useEffect(() => {
    if (isStaff) load().catch((err) => flash(err.message, 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, isStaff]);

  if (!isStaff) return <Navigate to="/dashboard" replace />;

  if (!overview) {
    return (
      <>
        <div className="page-head"><div><h1>Admin console</h1><p>Loading system overview…</p></div></div>
        <TableSkeleton rows={5} />
      </>
    );
  }

  const act = async (id, fn) => {
    setBusyId(id);
    clear();
    try {
      const res = await fn();
      flash(res.message, 'success');
      await load();
    } catch (err) {
      flash(err.message, 'error');
    }
    setBusyId(null);
  };

  const { stats, events, permissions } = overview;
  const rows = events.filter((e) => filter === 'all' || eventCategory(e.event_type) === filter);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Admin console</h1>
          <p>{isAdmin ? 'Manage accounts and monitor security across the whole system.' : 'Read-only security monitoring across the whole system.'}</p>
        </div>
        <span className="tag role-pill"><Icon name="key" /> Signed in as {ROLE_LABEL[user.role]}</span>
      </div>

      <section className="stats">
        <div className="card stat">
          <div className="ico ico-brand"><Icon name="users" /></div>
          <div><div className="num">{stats.users}</div><div className="lbl">Accounts</div>
            <div className={`sub${stats.disabled ? ' bad' : ''}`}>{stats.disabled ? `${stats.disabled} disabled` : 'All active'}</div></div>
        </div>
        <div className="card stat">
          <div className="ico ico-info"><Icon name="folder" /></div>
          <div><div className="num">{stats.files}</div><div className="lbl">Encrypted files</div>
            <div className="sub">Across all accounts</div></div>
        </div>
        <div className="card stat">
          <div className={`ico ${stats.tampered ? 'ico-bad' : 'ico-ok'}`}><Icon name="shield" /></div>
          <div><div className="num">{stats.tampered}</div><div className="lbl">Tampered files</div>
            <div className={`sub${stats.tampered ? ' bad' : ''}`}>{stats.tampered ? 'Owners must recover' : 'All clear'}</div></div>
        </div>
        <div className="card stat">
          <div className={`ico ${stats.alerts_24h ? 'ico-warn' : 'ico-ok'}`}><Icon name="activity" /></div>
          <div><div className="num">{stats.events_24h}</div><div className="lbl">Events in 24 hours</div>
            <div className={`sub${stats.alerts_24h ? ' bad' : ''}`}>{stats.alerts_24h} alert{stats.alerts_24h === 1 ? '' : 's'}</div></div>
        </div>
      </section>

      {isAdmin && users && (
        <section className="card" style={{ marginBottom: 20 }}>
          <div className="card-head"><h2><Icon name="users" /> Accounts &amp; roles</h2><span className="muted" style={{ fontSize: 13 }}>Admins cannot open other people's files.</span></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>User</th><th>Role</th><th>Status</th><th className="hide-sm">Files</th><th className="hide-sm">Last login</th><th style={{ textAlign: 'right' }}>Action</th></tr></thead>
              <tbody>
                {users.map((u) => {
                  const self = u.id === user.id;
                  return (
                    <tr key={u.id}>
                      <td><div className="fname"><span className="avatar">{u.username[0].toUpperCase()}</span><div><b>{u.username}{self && <span className="muted"> (you)</span>}</b><small>{u.email}</small></div></div></td>
                      <td>
                        <select
                          className="select" aria-label={`Role of ${u.username}`} value={u.role} disabled={self || busyId === u.id}
                          onChange={(e) => act(u.id, () => api.adminSetRole(u.id, e.target.value))}
                        >
                          {Object.keys(ROLE_LABEL).map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                        </select>
                      </td>
                      <td>
                        {u.disabled ? <span className="badge badge-bad">Disabled</span>
                          : u.is_verified ? <span className="badge badge-ok">Active</span>
                            : <span className="badge badge-plain" style={{ background: 'var(--warn-soft)', color: 'var(--warn)' }}>Unverified</span>}
                      </td>
                      <td className="hide-sm">{u.files}</td>
                      <td className="hide-sm muted">{u.last_login_at ? timeAgo(u.last_login_at) : 'never'}</td>
                      <td>
                        <div className="row-actions">
                          {!self && (u.disabled
                            ? <button type="button" className="btn btn-sm" disabled={busyId === u.id} onClick={() => act(u.id, () => api.adminSetDisabled(u.id, false))}><Icon name="check" /> Enable</button>
                            : <button type="button" className="btn btn-sm btn-danger" disabled={busyId === u.id} onClick={() => setConfirm(u)}><Icon name="lock" /> Disable</button>)}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="card" style={{ marginBottom: 20 }}>
        <div className="card-head"><h2><Icon name="key" /> Roles &amp; permissions</h2></div>
        <div className="perm-grid">
          {Object.keys(ROLE_LABEL).map((r) => (
            <div key={r} className={`perm${user.role === r ? ' mine' : ''}`}>
              <b>{ROLE_LABEL[r]}</b>
              <ul>{(permissions[r] || []).map((p) => <li key={p}><Icon name="check" /> {p}</li>)}</ul>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <h2><Icon name="activity" /> System security events</h2>
          <div className="filter glass-tabs has-glider" ref={filterRef}>
            <Glider />
            {FILTERS.map(([key, label]) => (
              <button key={key} className={`pill${filter === key ? ' on' : ''}`} type="button" onClick={() => setFilter(key)}>{label}</button>
            ))}
          </div>
        </div>
        {rows.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>When</th><th>User</th><th>Event</th><th>Details</th></tr></thead>
              <tbody>
                {rows.map((e) => {
                  const c = eventCategory(e.event_type);
                  return (
                    <tr key={e.id}>
                      <td className="muted" style={{ whiteSpace: 'nowrap' }}><Time value={e.timestamp} /></td>
                      <td><b>{e.username}</b></td>
                      <td>
                        <span
                          className={`badge ${c === 'alerts' ? 'badge-bad' : c === 'files' || c === 'scans' ? 'badge-ok' : ''}`}
                          style={c === 'account' ? { background: 'var(--info-soft)', color: 'var(--info)' } : undefined}
                        >{eventTitle(e.event_type)}</span>
                      </td>
                      <td style={{ overflowWrap: 'anywhere', minWidth: 220 }}><HashText text={e.description} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty"><div className="big"><Icon name="activity" /></div><b>No events</b>Nothing matches this filter yet.</div>
        )}
      </section>

      {confirm && (
        <ConfirmModal
          title={`Disable ${confirm.username}?`}
          icon="lock"
          confirmLabel="Disable account"
          busyLabel="Disabling…"
          busy={busyId === confirm.id}
          onConfirm={async () => { await act(confirm.id, () => api.adminSetDisabled(confirm.id, true)); setConfirm(null); }}
          onCancel={() => { if (busyId === null) setConfirm(null); }}
        >
          They will be signed out immediately and cannot log in until you enable the account again. Their encrypted files are kept.
        </ConfirmModal>
      )}
    </>
  );
}
