import { useRef, useState } from 'react';
import { NavLink, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom';
import Icon from './Icon';
import Brand from './Brand';
import Flashes from './Flashes';
import ThemeIcon from './ThemeIcon';
import ConfirmModal from './ConfirmModal';
import { Glider, useGlider } from './Glider';
import { VaultProvider, useVault } from '../vault';
import { useAuth, useFlash } from '../context';
import { useTheme } from '../hooks';
import { api } from '../api';

// Shell for logged-in pages: slim header on top, floating glass dock at the bottom.
function Shell() {
  const { user, signOut } = useAuth();
  const { flash, clear } = useFlash();
  const toggleTheme = useTheme();
  const { stats } = useVault();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  // the Recover page keeps "Dashboard" highlighted
  const active = pathname.startsWith('/admin') ? 'admin' : pathname.startsWith('/security-events') ? 'events' : 'dashboard';
  const isStaff = user.role === 'admin' || user.role === 'analyst';

  // sliding glass thumb behind the active dock tab
  const tabsRef = useRef(null);
  useGlider(tabsRef, active);

  const [askLogout, setAskLogout] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const logout = async () => {
    setLeaving(true);
    try { await api.logout(); } catch (err) { /* session already gone */ }
    signOut();
    clear();
    flash('You have been logged out.', 'success');
    navigate('/login');
  };

  return (
    <>
      <header className="app-top">
        <Brand to="/dashboard" />
        <div className="user-chip" title={user.email}>
          <span className="avatar">{user.username[0].toUpperCase()}</span>
          <span className="user-chip-name">{user.username}</span>
          {isStaff && <span className="role-tag">{user.role}</span>}
        </div>
      </header>

      <div className="toast-zone"><Flashes /></div>

      <main className="content">
        <Outlet />
      </main>

      <div className="dock-wrap">
        <nav className="dock glass-tabs has-glider" ref={tabsRef} aria-label="Main">
          <Glider />
          <NavLink to="/dashboard" className={active === 'dashboard' ? 'active' : ''}>
            <Icon name="grid" /><span className="dock-label">Dashboard</span>
          </NavLink>
          <NavLink to="/security-events" className={active === 'events' ? 'active' : ''}>
            <Icon name="activity" /><span className="dock-label">Security events</span>
            {stats && stats.tampered > 0 && <span className="nav-badge" title="Tamper alerts">{stats.tampered}</span>}
          </NavLink>
          {isStaff && (
            <NavLink to="/admin" className={active === 'admin' ? 'active' : ''}>
              <Icon name="users" /><span className="dock-label">Admin</span>
            </NavLink>
          )}
        </nav>
        <button className="dock-btn" type="button" onClick={toggleTheme} aria-label="Switch theme" title="Switch theme"><ThemeIcon /></button>
        <button className="dock-btn dock-btn-out" type="button" onClick={() => setAskLogout(true)} aria-label="Log out" title="Log out"><Icon name="logout" /></button>
      </div>

      {askLogout && (
        <ConfirmModal
          title="Log out of your vault?"
          icon="logout"
          confirmLabel="Log out"
          busyLabel="Logging out…"
          busy={leaving}
          onConfirm={logout}
          onCancel={() => { if (!leaving) setAskLogout(false); }}
        >
          You will need your password to get back in. Your files stay encrypted and safe.
        </ConfirmModal>
      )}
    </>
  );
}

export default function AppLayout() {
  const { user } = useAuth();
  const location = useLocation();
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  return (
    <VaultProvider>
      <Shell />
    </VaultProvider>
  );
}
