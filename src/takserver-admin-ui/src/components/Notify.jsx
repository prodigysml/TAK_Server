import React, { createContext, useCallback, useContext, useState } from 'react';
import { Alert, Snackbar } from '@mui/material';

const Ctx = createContext(() => {});

// notify('Saved user alice') or notify(err, 'error'). Errors stay until dismissed.
export function NotifyProvider({ children }) {
  const [msg, setMsg] = useState(null);
  const notify = useCallback((text, severity = 'success') => {
    const t = text instanceof Error ? text.message : String(text);
    setMsg({ text: t, severity: text instanceof Error ? 'error' : severity, key: Date.now() });
  }, []);
  const close = (_, reason) => { if (reason !== 'clickaway') setMsg(null); };
  return (
    <Ctx.Provider value={notify}>
      {children}
      <Snackbar
        key={msg?.key}
        open={!!msg}
        onClose={close}
        autoHideDuration={msg?.severity === 'error' ? null : 4000}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        {msg ? <Alert onClose={close} severity={msg.severity} variant="filled" sx={{ maxWidth: 520 }}>{msg.text}</Alert> : undefined}
      </Snackbar>
    </Ctx.Provider>
  );
}

export const useNotify = () => useContext(Ctx);
