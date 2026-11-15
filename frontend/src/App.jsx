import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useEffect } from 'react';
import AuthLayout from './components/AuthLayout';
import AppLayout from './components/AppLayout';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Register from './pages/Register';
import VerifyOtp from './pages/VerifyOtp';
import ForgotPassword from './pages/ForgotPassword';
import Dashboard from './pages/Dashboard';
import Recover from './pages/Recover';
import SecurityEvents from './pages/SecurityEvents';
import Admin from './pages/Admin';
import OpenLink from './pages/OpenLink';
import { pendingLinkPath } from './pendingLink';
import { useAuth } from './context';

function ScrollTop() {
  const { pathname, hash } = useLocation();
  useEffect(() => {
    if (!hash) { window.scrollTo(0, 0); return undefined; }
    // the target may appear after data loads, so retry briefly
    let tries = 0;
    const t = setInterval(() => {
      const el = document.getElementById(hash.slice(1));
      if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); clearInterval(t); }
      else if (++tries > 15) clearInterval(t);
    }, 100);
    return () => clearInterval(t);
  }, [pathname, hash]);
  return null;
}

function GuestOnly({ children }) {
  const { user } = useAuth();
  // someone who arrived through a share link goes back to it once signed in
  return user ? <Navigate to={pendingLinkPath() || '/dashboard'} replace /> : children;
}

export default function App() {
  const { ready } = useAuth();
  if (!ready) return null;
  return (
    <>
      <ScrollTop />
      <Routes>
        <Route path="/" element={<Landing />} />

        <Route element={<GuestOnly><AuthLayout /></GuestOnly>}>
          <Route path="/login" element={<Login />} />
          <Route path="/login/verify" element={<VerifyOtp mode="login" />} />
          <Route path="/register" element={<Register />} />
          <Route path="/verify-email" element={<VerifyOtp mode="register" />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<VerifyOtp mode="reset" />} />
        </Route>

        {/* share links work for visitors and signed-in users alike */}
        <Route element={<AuthLayout solo />}>
          <Route path="/s/:token" element={<OpenLink />} />
        </Route>

        <Route element={<AppLayout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/recover/:fileId" element={<Recover />} />
          <Route path="/security-events" element={<SecurityEvents />} />
          <Route path="/admin" element={<Admin />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}
