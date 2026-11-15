import { useRef, useState } from 'react';
import { NavLink, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom';
import Icon from './Icon';
import Brand from './Brand';
import Flashes from './Flashes';
import { Glider, useGlider } from './Glider';
import SideExtras from './SideExtras';
import { VaultProvider, useVault } from '../vault';
import { useAuth, useFlash } from '../context';
import { useBodyClass, useTheme } from '../hooks';
import { api } from '../api';

// Replaces app_base.html (topbar + sidebar shell for logged-in pages)
function Shell() {
  const { user, signOut } = useAuth();
  const { flash, clear } = useFlash();
  const [menuOpen, setMenuOpen] = useState(false);
  const toggleTheme = useTheme();
  const { stats } = useVault();
  const navigate = useNavigate();
  const location = useLocation();

  useBodyClass('menu-open', menuOpen);

  // sliding glass thumb behind the active sidebar tab
  const navRef = useRef(null);
  const path = location.pathname;
  useGlider(navRef, path.startsWith('/security-events') ? 'events' : path.startsWith('/dashboard') || path.startsWith('/recover') ? 'dashboard' : 'none');

  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;

  const isActive = (path) => location.pathname === path;
  // Recover page highlights "Dashboard", like `{% set active = 'dashboard' %}` did
  const dashActive = isActive('/dashboard') || location.pathname.startsWith('/recover');
  const eventsActive = isActive('/security-events');

  const logout = async (e) => {
    e.preventDefault();
    try { await api.logout(); } catch (err) { /* session already gone */ }
    signOut();
    clear();
    flash('You have been logged out.', 'success');
    navigate('/login');
  };

  return (
    <>
      <div className="topbar">
        <Brand to="/dashboard" />
        <button className="btn btn-icon" type="button" aria-label="Menu" onClick={() => setMenuOpen((v) => !v)}><Icon name="menu" /></button>
      </div>
      <div className="scrim" onClick={() => setMenuOpen(false)} />
      <div className="shell" onClick={(e) => { if (e.target.closest('.sidebar a')) setMenuOpen(false); }}>
        <aside className="sidebar">
          <Brand to="/dashboard" />
          <nav className="nav glass-tabs has-glider" ref={navRef}>
            <Glider />
            <div className="nav-label" style={{ marginTop: 0 }}>Workspace</div>
            <NavLink to="/dashboard" className={dashActive ? 'active' : ''}><Icon name="grid" /> Dashboard</NavLink>
            <NavLink to="/security-events" className={eventsActive ? 'active' : ''}><Icon name="activity" /> Security events{stats && stats.tampered > 0 && <span className="nav-badge" title="Tamper alerts">{stats.tampered}</span>}</NavLink>
          </nav>
          <SideExtras />
          <div className="side-bottom">
            <button className="btn side-btn" onClick={toggleTheme} type="button"><Icon name="moon" /> Switch theme</button>
            <div className="usercard">
              <div className="avatar">{user.username[0].toUpperCase()}</div>
              <div className="grow"><b>{user.username}</b><small>{user.email}</small></div>
            </div>
            <form onSubmit={logout}>
              <button className="btn side-btn" type="submit"><Icon name="logout" /> Log out</button>
            </form>
          </div>
        </aside>
        <main className="content">
          <Flashes />
          <Outlet />
        </main>
      </div>
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
