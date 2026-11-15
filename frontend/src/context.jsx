import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { api } from './api';

/* ---------- Flash messages (replaces Flask flash()) ---------- */
const FlashContext = createContext(null);
let flashId = 0;

export function FlashProvider({ children }) {
  const [flashes, setFlashes] = useState([]);
  const location = useLocation();

  // Like Flask's flash(): a message is shown once. Messages queued right before a
  // redirect survive the navigation; anything older is dropped when the page changes.
  useEffect(() => {
    setFlashes((f) => f.filter((x) => Date.now() - x.at < 1500));
  }, [location.key]);

  const remove = useCallback((id) => setFlashes((f) => f.filter((x) => x.id !== id)), []);
  const flash = useCallback((message, category = 'info') => {
    const cat = ['success', 'error', 'info'].includes(category) ? category : 'info';
    setFlashes((f) => [...f, { id: ++flashId, message, category: cat, at: Date.now() }]);
  }, []);
  const clear = useCallback(() => setFlashes([]), []);
  const value = useMemo(() => ({ flashes, flash, remove, clear }), [flashes, flash, remove, clear]);
  return <FlashContext.Provider value={value}>{children}</FlashContext.Provider>;
}
export const useFlash = () => useContext(FlashContext);

/* ---------- Auth: the Flask session is the source of truth ---------- */
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    api.me().then((d) => setUser(d.user)).catch(() => setUser(null)).finally(() => setReady(true));
    const onExpired = () => setUser(null);
    window.addEventListener('sv:unauthorized', onExpired);
    return () => window.removeEventListener('sv:unauthorized', onExpired);
  }, []);

  const signIn = useCallback((u) => setUser(u), []);
  const signOut = useCallback(() => setUser(null), []);
  const value = useMemo(() => ({ user, ready, signIn, signOut }), [user, ready, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
export const useAuth = () => useContext(AuthContext);
