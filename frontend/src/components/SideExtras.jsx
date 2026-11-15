import { useState } from 'react';
import { Link } from 'react-router-dom';
import Icon from './Icon';
import { useFlash } from '../context';
import { useVault } from '../vault';
import { humanSize, timeAgo } from '../hooks';
import { api } from '../api';

/** Quick actions + live vault status that fill the middle of the sidebar. */
export default function SideExtras() {
  const { stats, bump } = useVault();
  const { flash, clear } = useFlash();
  const [scanning, setScanning] = useState(false);

  const scan = async () => {
    setScanning(true);
    clear();
    try {
      const r = await api.integrityScan();
      flash(r.message, r.issues ? 'error' : 'success');
      bump();
    } catch (err) {
      flash(err.message, 'error');
    }
    setScanning(false);
  };

  let tone = 'ico-info', icon = 'shield', title = 'Checking vault…', note = '';
  if (stats) {
    if (stats.total === 0) { tone = 'ico-info'; icon = 'shield'; title = 'Vault is empty'; note = 'Upload a file to start'; }
    else if (stats.tampered) { tone = 'ico-bad'; icon = 'shield-alert'; title = 'Attention needed'; note = `${stats.tampered} file${stats.tampered === 1 ? '' : 's'} failed verification`; }
    else { tone = 'ico-ok'; icon = 'shield'; title = 'All files verified'; note = 'No tampering detected'; }
  }

  return (
    <>
      <div className="nav-label">Quick actions</div>
      <div className="side-quick">
        <Link to="/dashboard#upload" className="btn side-btn"><Icon name="upload" /> Upload file</Link>
        <button type="button" className="btn side-btn" onClick={scan} disabled={scanning}>
          <Icon name="scan" /> {scanning ? 'Scanning…' : 'Run integrity scan'}
        </button>
      </div>

      <div className="usercard side-status" aria-live="polite">
        <div className="side-status-head">
          <span className={`ico ${tone}`}><Icon name={icon} /></span>
          <div className="grow"><b>{title}</b><small>{note}</small></div>
        </div>
        {stats && (
          <dl className="side-facts">
            <div><dt>Files</dt><dd>{stats.total}</dd></div>
            <div><dt>Protected</dt><dd>{humanSize(stats.size)}</dd></div>
            <div><dt>Last scan</dt><dd>{stats.last_scan ? timeAgo(stats.last_scan) : 'never'}</dd></div>
          </dl>
        )}
        <div className="side-chips"><span><Icon name="lock" /> AES-256-GCM</span><span><Icon name="hash" /> SHA-256</span></div>
      </div>
    </>
  );
}
