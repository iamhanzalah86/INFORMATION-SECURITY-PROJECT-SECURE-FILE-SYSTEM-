import { Outlet } from 'react-router-dom';
import Icon from './Icon';
import Brand from './Brand';
import Flashes from './Flashes';
import { useTheme } from '../hooks';
import { APP_NAME } from '../config';

// Replaces auth_base.html
export default function AuthLayout() {
  const toggleTheme = useTheme();
  return (
    <div className="auth">
      <aside className="auth-side">
        <Brand to="/" />
        <div>
          <h2>Your files, encrypted<br />and tamper-proof.</h2>
          <p className="lead">Every file is sealed with AES-256-GCM and fingerprinted with SHA-256, so any change is caught before you download it.</p>
          <ul className="feat">
            <li><span className="ico"><Icon name="lock" /></span><div><b>AES-256-GCM encryption</b>Files are encrypted before they are ever stored.</div></li>
            <li><span className="ico"><Icon name="hash" /></span><div><b>Integrity monitoring</b>SHA-256 checks detect missing or modified files.</div></li>
            <li><span className="ico"><Icon name="mail" /></span><div><b>Email verification</b>One-time codes protect sign-up and password resets.</div></li>
          </ul>
        </div>
        <small style={{ color: '#8da0bd' }}>© {APP_NAME} · Information Security Project</small>
      </aside>
      <main className="auth-main">
        <button className="btn btn-ghost btn-icon theme-float" onClick={toggleTheme} aria-label="Toggle theme" type="button"><Icon name="moon" /></button>
        <div className="auth-card">
          <Brand to="/" className="brand auth-brand" />
          <Flashes />
          <Outlet />
        </div>
      </main>
    </div>
  );
}
