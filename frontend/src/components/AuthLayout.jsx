import { Outlet, useLocation } from 'react-router-dom';
import Icon from './Icon';
import Brand from './Brand';
import Flashes from './Flashes';
import ThemeIcon from './ThemeIcon';
import { useTheme } from '../hooks';
import { APP_NAME } from '../config';

// Replaces auth_base.html. `solo` shows only the centred card (used by share links).
export default function AuthLayout({ solo = false }) {
  const toggleTheme = useTheme();
  const { pathname } = useLocation();
  return (
    <div className={`auth${solo ? ' auth-solo' : ''}`}>
      {!solo && (
        <aside className="auth-side">
          <Brand to="/" />
          <div>
            <h2>Your files, encrypted<br />and tamper-proof.</h2>
            <p className="lead">Every file is sealed with AES-256-GCM and fingerprinted with SHA-256, so any change is caught before you download it.</p>
            <ul className="feat">
              <li><span className="ico"><Icon name="lock" /></span><div><b>AES-256-GCM encryption</b>Files are encrypted before they are ever stored.</div></li>
              <li><span className="ico"><Icon name="hash" /></span><div><b>Integrity monitoring</b>SHA-256 checks detect missing or modified files.</div></li>
              <li><span className="ico"><Icon name="mail" /></span><div><b>Two-step sign-in</b>A one-time email code is required after your password.</div></li>
            </ul>
          </div>
          <small className="auth-copy">© {APP_NAME} · Information Security Project</small>
        </aside>
      )}
      <main className="auth-main">
        <button className="btn btn-ghost btn-icon theme-float" onClick={toggleTheme} aria-label="Toggle theme" type="button"><ThemeIcon /></button>
        <div className="auth-card">
          <Brand to="/" className="brand auth-brand" />
          <Flashes />
          {/* keyed so each auth screen fades in when you move between them */}
          <div className="auth-view" key={pathname}><Outlet /></div>
        </div>
      </main>
    </div>
  );
}
