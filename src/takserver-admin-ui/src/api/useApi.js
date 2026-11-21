import { useCallback, useEffect, useRef, useState } from 'react';

// Load data on mount (and when deps change). Returns { data, error, loading, reload }.
// reload(true) refreshes in the background without showing the loading state.
export function useApi(loader, deps = []) {
  const [state, setState] = useState({ data: undefined, error: null, loading: true });
  const seq = useRef(0);
  const run = useCallback(async (silent = false) => {
    const id = ++seq.current;
    if (silent !== true) setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const data = await loader();
      if (id === seq.current) setState({ data, error: null, loading: false });
    } catch (error) {
      if (id === seq.current) setState((s) => ({ ...s, error, loading: false }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { run(); }, [run]);
  return { ...state, reload: run };
}

// Poll a loader every `ms` while the tab is visible.
export function usePolling(loader, ms, deps = []) {
  const result = useApi(loader, deps);
  const { reload } = result;
  useEffect(() => {
    if (!ms) return undefined;
    const t = setInterval(() => { if (document.visibilityState === 'visible') reload(true); }, ms);
    return () => clearInterval(t);
  }, [ms, reload]);
  return result;
}
