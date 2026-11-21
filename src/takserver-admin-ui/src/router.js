import { useEffect, useState } from 'react';

// Minimal hash router: the app is a static bundle under /Marti/ui/, so routes
// live in the fragment and the server never needs a fallback rule.
function current() {
  const h = window.location.hash.replace(/^#/, '');
  return h.startsWith('/') ? h : '/';
}

export function useRoute() {
  const [path, setPath] = useState(current);
  useEffect(() => {
    const on = () => setPath(current());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return path;
}

// Only internal, fixed paths are ever navigated to.
export function navigate(path) {
  window.location.hash = path;
}
