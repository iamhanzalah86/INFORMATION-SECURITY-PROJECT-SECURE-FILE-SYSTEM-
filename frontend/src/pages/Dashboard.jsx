import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import Icon from '../components/Icon';
import Time from '../components/Time';
import HashText from '../components/HashText';
import ConfirmModal from '../components/ConfirmModal';
import ActivityChart from '../components/ActivityChart';
import { Glider, useGlider } from '../components/Glider';
import { DashboardSkeleton } from '../components/Skeleton';
import { useAuth, useFlash } from '../context';
import { useVault } from '../vault';
import { eventTitle, eventVisual, fileTypeBadge, humanSize, timeAgo, useTitle } from '../hooks';
import { api } from '../api';

const fmt = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);

function FileType({ name }) {
  const t = fileTypeBadge(name);
  return <span className={`ftype ${t.cls}`}>{t.label}</span>;
}

// text the search box matches against (same as matching the visible row text)
const fileRowText = (f) => `${f.original_filename} ${f.sha256_hash.slice(0, 12)} ${humanSize(f.file_size)} ${f.status === 'TAMPERED' ? 'Tampered' : 'Secure'}`;

const SORTERS = {
  name: (f) => f.original_filename.toLowerCase(),
  size: (f) => f.file_size,
  status: (f) => (f.status === 'TAMPERED' ? 0 : 1),
  uploaded: (f) => new Date(f.uploaded_at.endsWith('Z') ? f.uploaded_at : `${f.uploaded_at}Z`).getTime(),
};

const STATUS_FILTERS = [['all', 'All'], ['secure', 'Secure'], ['tampered', 'Tampered']];

const scrollToFiles = () => {
  const el = document.getElementById('files');
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

export default function Dashboard() {
  useTitle('Dashboard');
  const { flash, clear } = useFlash();
  const { user } = useAuth();
  const { setStats, version, bump } = useVault();
  const [data, setData] = useState(null);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sort, setSort] = useState({ key: 'uploaded', dir: 'desc' });
  const [selected, setSelected] = useState(() => new Set());
  const [confirm, setConfirm] = useState(null); // { ids: number[], label: string }
  const [deleting, setDeleting] = useState(false);
  const [chosen, setChosen] = useState(null);
  const [over, setOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const inputRef = useRef(null);
  const filterRef = useRef(null);
  useGlider(filterRef, statusFilter);

  const load = useCallback(async () => {
    const d = await api.getDashboard();
    setData(d);
    setStats(d.stats); // keeps the sidebar status in sync
    // forget selected files that no longer exist
    setSelected((prev) => {
      const ids = new Set(d.files.map((f) => f.id));
      const next = new Set([...prev].filter((id) => ids.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [setStats]);
  useEffect(() => { load(); }, [load, version]);

  const files = data ? data.files : [];
  const q = query.toLowerCase();
  const visible = useMemo(() => {
    const rows = files.filter((f) => {
      if (statusFilter === 'tampered' && f.status !== 'TAMPERED') return false;
      if (statusFilter === 'secure' && f.status === 'TAMPERED') return false;
      return !q || fileRowText(f).toLowerCase().includes(q);
    });
    const get = SORTERS[sort.key];
    rows.sort((a, b) => {
      const x = get(a), y = get(b);
      const c = x < y ? -1 : x > y ? 1 : 0;
      return sort.dir === 'asc' ? c : -c;
    });
    return rows;
  }, [files, q, statusFilter, sort]);

  if (!data) return <DashboardSkeleton />;
  const { stats, recent_events: recent, activity, max_mb: MAX_MB, dev_tools: devTools } = data;

  /* ---------- upload ---------- */
  const pick = (f) => {
    if (!f) { setChosen(null); return; }
    if (f.size > MAX_MB * 1048576) {
      flash(`"${f.name}" is ${fmt(f.size)}. The limit is ${MAX_MB} MB.`, 'error');
      if (inputRef.current) inputRef.current.value = '';
      setChosen(null);
      return;
    }
    setChosen(f);
  };

  const onDrop = (ev) => {
    ev.preventDefault();
    setOver(false);
    if (ev.dataTransfer.files.length && inputRef.current) {
      inputRef.current.files = ev.dataTransfer.files;
      pick(ev.dataTransfer.files[0]);
    }
  };

  const upload = async (e) => {
    e.preventDefault();
    if (!chosen) return;
    setUploading(true);
    clear();
    try {
      const res = await api.uploadFile(chosen);
      flash(res.message, 'success');
      setChosen(null);
      if (inputRef.current) inputRef.current.value = '';
      await load();
    } catch (err) {
      flash(err.message, 'error');
    }
    setUploading(false);
  };

  /* ---------- actions ---------- */
  const scan = async (e) => {
    e.preventDefault();
    setScanning(true);
    clear();
    try {
      const r = await api.integrityScan();
      flash(r.message, r.issues ? 'error' : 'success');
      await load();
    } catch (err) {
      flash(err.message, 'error');
    }
    setScanning(false);
  };

  const download = async (e, f) => {
    e.preventDefault();
    clear();
    try {
      await api.downloadFile(f.id, f.original_filename);
      await load();
    } catch (err) {
      flash(err.message, 'error');
      await load(); // a failed check marks the file as tampered
    }
  };

  const simulateTamper = async (f) => {
    clear();
    try {
      const r = await api.devTamper(f.id);
      flash(r.message, 'info');
      await load();
    } catch (err) {
      flash(err.message, 'error');
    }
  };

  const runDelete = async () => {
    if (!confirm) return;
    setDeleting(true);
    clear();
    let ok = 0;
    let failed = 0;
    for (const id of confirm.ids) {
      try { await api.deleteFile(id); ok += 1; } catch (err) { failed += 1; }
    }
    if (ok) flash(ok === 1 && !failed ? `${confirm.label} was permanently deleted.` : `${ok} file${ok === 1 ? '' : 's'} permanently deleted.`, 'success');
    if (failed) flash(`${failed} file${failed === 1 ? '' : 's'} could not be deleted.`, 'error');
    setSelected(new Set());
    setConfirm(null);
    setDeleting(false);
    await load();
  };

  /* ---------- selection / sorting ---------- */
  const allVisibleSelected = visible.length > 0 && visible.every((f) => selected.has(f.id));
  const toggleAll = () => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allVisibleSelected) visible.forEach((f) => next.delete(f.id));
      else visible.forEach((f) => next.add(f.id));
      return next;
    });
  };
  const toggleOne = (id) => setSelected((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const sortBy = (key) => setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'name' ? 'asc' : 'desc' }));
  const sortTh = (k, children, className) => (
    <th className={className} aria-sort={sort.key === k ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className={`th-sort${sort.key === k ? ' on' : ''}${sort.key === k && sort.dir === 'asc' ? ' asc' : ''}`} onClick={() => sortBy(k)}>
        {children} <Icon name="chevron" />
      </button>
    </th>
  );

  const openStat = (filter) => { setStatusFilter(filter); setQuery(''); setTimeout(scrollToFiles, 30); };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Hello, {user.username} 👋</h1>
          <p>Your vault at a glance · last integrity scan: {stats.last_scan ? <Time value={stats.last_scan} /> : 'never'}</p>
        </div>
        <div className="actions">
          {devTools && <span className="tag dev-tag" title="DEV_TOOLS=1 is set in .env">Demo tools on</span>}
          <form onSubmit={scan}>
            <button className="btn" type="submit" disabled={scanning}><Icon name="scan" /> {scanning ? 'Scanning…' : 'Run integrity scan'}</button>
          </form>
          <a className="btn btn-primary" href="#upload"><Icon name="upload" /> Upload file</a>
        </div>
      </div>

      <section className="stats">
        <button type="button" className="card stat stat-link" onClick={() => openStat('all')}>
          <div className="ico ico-brand"><Icon name="folder" /></div>
          <div><div className="num">{stats.total}</div><div className="lbl">Encrypted files</div>
            <div className="sub">{stats.last_upload ? `Last upload ${timeAgo(stats.last_upload)}` : 'No uploads yet'}</div></div>
        </button>
        <button type="button" className="card stat stat-link" onClick={() => openStat('secure')}>
          <div className="ico ico-ok"><Icon name="shield" /></div>
          <div><div className="num">{stats.secure}</div><div className="lbl">Verified secure</div>
            <div className="sub">{stats.total ? `of ${stats.total} file${stats.total === 1 ? '' : 's'}` : 'Nothing to verify yet'}</div></div>
        </button>
        <button type="button" className="card stat stat-link" onClick={() => (stats.tampered ? openStat('tampered') : scrollToFiles())}>
          <div className={`ico ${stats.tampered ? 'ico-bad' : 'ico-info'}`}><Icon name="alert" /></div>
          <div><div className="num">{stats.tampered}</div><div className="lbl">Tamper alerts</div>
            <div className={`sub${stats.tampered ? ' bad' : ''}`}>{stats.tampered ? 'Needs attention' : 'All clear'}</div></div>
        </button>
        <div className="card stat">
          <div className="ico ico-info"><Icon name="database" /></div>
          <div><div className="num">{humanSize(stats.size)}</div><div className="lbl">Data protected</div>
            <div className="sub">AES-256-GCM sealed</div></div>
        </div>
      </section>

      <section className="grid-2" id="upload">
        <div className="card">
          <div className="card-head"><h2><Icon name="upload" /> Upload &amp; encrypt</h2><span className="tag">AES-256-GCM</span></div>
          <div className="card-pad">
            <form onSubmit={upload}>
              <label
                className={`drop${over ? ' over' : ''}`}
                onDragEnter={(e) => { e.preventDefault(); setOver(true); }}
                onDragOver={(e) => { e.preventDefault(); setOver(true); }}
                onDragLeave={(e) => { e.preventDefault(); setOver(false); }}
                onDrop={onDrop}
              >
                <div className="big"><Icon name="upload" /></div>
                <b>Drop a file here or click to browse</b>
                <span className="muted">Encrypted before it's stored · max {MAX_MB} MB</span>
                <input ref={inputRef} type="file" name="file" required onChange={(e) => pick(e.target.files[0])} />
              </label>
              <div className={`chosen${chosen ? ' show' : ''}`} id="chosen">
                <span><Icon name="file" /> <span id="chosen-name">{chosen ? `${chosen.name}  ·  ${fmt(chosen.size)}` : ''}</span></span>
                <button className="btn btn-primary btn-sm" id="upload-btn" type="submit" disabled={uploading}>
                  <Icon name="lock" /><span>{uploading ? ' Encrypting…' : ' Encrypt & upload'}</span>
                </button>
              </div>
              <div className={`progress${uploading ? ' show' : ''}`}><i /></div>
            </form>
          </div>
        </div>

        <div className="card posture">
          {stats.total === 0 ? (
            <>
              <div className="ring idle"><Icon name="shield" /></div><h3>Vault is empty</h3>
              <span className="muted">Upload your first file to start monitoring.</span>
            </>
          ) : stats.tampered ? (
            <>
              <div className="ring bad"><Icon name="shield-alert" /></div><h3 style={{ color: 'var(--bad)' }}>Attention needed</h3>
              <span className="muted">{stats.tampered} file{stats.tampered !== 1 ? 's' : ''} failed integrity verification.</span>
            </>
          ) : (
            <>
              <div className="ring ok"><Icon name="shield" /></div><h3 style={{ color: 'var(--ok)' }}>All files verified</h3>
              <span className="muted">No tampering detected in your vault.</span>
            </>
          )}
          <div className="chips"><span className="chip"><Icon name="lock" /> AES-256-GCM</span><span className="chip"><Icon name="hash" /> SHA-256</span></div>
        </div>
      </section>

      <section className="card" id="files" style={{ marginBottom: 20 }}>
        {files.length === 0 ? (
          <div className="empty-compact">
            <span className="ico ico-brand"><Icon name="folder" /></span>
            <div><b>No files yet</b><small>Upload a file above and it will appear here, encrypted.</small></div>
            <a className="btn btn-sm" href="#upload"><Icon name="upload" /> Upload</a>
          </div>
        ) : (
          <>
            <div className="card-head">
              <h2><Icon name="folder" /> Your files</h2>
              <div className="toolbar">
                <div className="filter glass-tabs has-glider" ref={filterRef}>
                  <Glider />
                  {STATUS_FILTERS.map(([key, label]) => (
                    <button key={key} type="button" className={`pill${statusFilter === key ? ' on' : ''}`} onClick={() => setStatusFilter(key)}>{label}</button>
                  ))}
                </div>
                <div className="search"><Icon name="search" /><input id="file-search" type="search" placeholder="Search files…" aria-label="Search files" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
              </div>
            </div>

            {selected.size > 0 && (
              <div className="bulkbar" role="status">
                <span><b>{selected.size}</b> selected</span>
                <div className="actions">
                  <button type="button" className="btn btn-sm" onClick={() => setSelected(new Set())}>Clear</button>
                  <button
                    type="button" className="btn btn-sm btn-danger"
                    onClick={() => setConfirm({ ids: [...selected], label: `${selected.size} files` })}
                  ><Icon name="trash" /> Delete selected</button>
                </div>
              </div>
            )}

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th className="chk-col"><input type="checkbox" className="chk" aria-label="Select all files" checked={allVisibleSelected} onChange={toggleAll} /></th>
                    {sortTh('name', 'File')}
                    {sortTh('size', 'Size', 'hide-sm')}
                    {sortTh('status', 'Status')}
                    {sortTh('uploaded', 'Uploaded', 'hide-sm')}
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody id="files-body">
                  {visible.map((f) => (
                    <tr key={f.id} className={selected.has(f.id) ? 'row-selected' : ''}>
                      <td className="chk-col"><input type="checkbox" className="chk" aria-label={`Select ${f.original_filename}`} checked={selected.has(f.id)} onChange={() => toggleOne(f.id)} /></td>
                      <td><div className="fname"><FileType name={f.original_filename} /><div><b>{f.original_filename}</b><small>SHA-256 {f.sha256_hash.slice(0, 12)}…</small></div></div></td>
                      <td className="hide-sm">{humanSize(f.file_size)}</td>
                      <td>{f.status === 'TAMPERED' ? <span className="badge badge-bad">Tampered</span> : <span className="badge badge-ok">Secure</span>}</td>
                      <td className="hide-sm muted"><Time value={f.uploaded_at} mode="date" /></td>
                      <td>
                        <div className="row-actions">
                          {f.status === 'TAMPERED' && f.has_backup && (
                            <Link className="btn btn-sm btn-primary" to={`/recover/${f.id}`}><Icon name="shield" /> <span className="hide-sm">Recover</span></Link>
                          )}
                          {devTools && f.status !== 'TAMPERED' && (
                            <button type="button" className="btn btn-sm btn-warn" title="Demo only: corrupt the stored copy of this file" onClick={() => simulateTamper(f)}>
                              <Icon name="alert" /> <span className="hide-sm">Tamper</span>
                            </button>
                          )}
                          <a className="btn btn-sm" href={`/api/files/${f.id}/download`} onClick={(e) => download(e, f)}><Icon name="download" /> <span className="hide-sm">Download</span></a>
                          <button
                            type="button" className="btn btn-sm btn-danger btn-icon" aria-label={`Delete ${f.original_filename}`}
                            onClick={() => setConfirm({ ids: [f.id], label: `'${f.original_filename}'` })}
                          ><Icon name="trash" /></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {visible.length === 0 && (
                <div className="empty" style={{ padding: '30px 20px' }}>
                  <b>No matching files</b>
                  <button type="button" className="btn btn-sm" onClick={() => { setQuery(''); setStatusFilter('all'); }}>Clear filters</button>
                </div>
              )}
            </div>
          </>
        )}
      </section>

      <section className="grid-2">
        <div className="card">
          <div className="card-head"><h2><Icon name="activity" /> Recent activity</h2><Link to="/security-events" className="btn btn-sm">View all <Icon name="arrow" /></Link></div>
          {recent.length ? (
            <ul className="feed">
              {recent.map((e) => {
                const v = eventVisual(e.event_type);
                return (
                  <li key={e.id}>
                    <div className={`dot ${v.tone}`}><Icon name={v.icon} /></div>
                    <div><b>{eventTitle(e.event_type)}</b><small><HashText text={e.description} /></small><time><Time value={e.timestamp} /></time></div>
                  </li>
                );
              })}
            </ul>
          ) : <div className="empty">No activity yet.</div>}
        </div>

        <div className="card">
          <div className="card-head"><h2><Icon name="grid" /> Last 7 days</h2></div>
          <ActivityChart activity={activity} />
        </div>
      </section>

      {confirm && (
        <ConfirmModal
          title={confirm.ids.length > 1 ? `Delete ${confirm.ids.length} files?` : 'Delete this file?'}
          confirmLabel={confirm.ids.length > 1 ? 'Delete all' : 'Delete'}
          busy={deleting}
          onConfirm={runDelete}
          onCancel={() => { if (!deleting) setConfirm(null); }}
        >
          {confirm.ids.length > 1
            ? 'The selected files and their backups will be permanently deleted. This cannot be undone.'
            : <>{confirm.label} and its backup will be permanently deleted. This cannot be undone.</>}
        </ConfirmModal>
      )}
    </>
  );
}
