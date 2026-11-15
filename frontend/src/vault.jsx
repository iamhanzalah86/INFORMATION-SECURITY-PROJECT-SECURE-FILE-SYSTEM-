import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api } from './api';

/**
 * Shares the vault summary (counts, last scan...) between the sidebar and the pages.
 * `version` goes up whenever something changes the vault, so pages can reload.
 */
const VaultContext = createContext(null);

export function VaultProvider({ children }) {
  const [stats, setStats] = useState(null);
  const [version, setVersion] = useState(0);

  const refresh = useCallback(async () => {
    try {
      const d = await api.getDashboard();
      setStats(d.stats);
    } catch (e) { /* the page that triggered this shows its own errors */ }
  }, []);

  useEffect(() => { refresh(); }, [refresh, version]);

  const bump = useCallback(() => setVersion((v) => v + 1), []);
  const value = useMemo(() => ({ stats, setStats, version, bump }), [stats, version, bump]);
  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export const useVault = () => useContext(VaultContext);
