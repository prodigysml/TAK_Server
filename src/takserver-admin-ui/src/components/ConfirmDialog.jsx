import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField } from '@mui/material';

/**
 * Confirm a risky action. confirmLabel names the action ("Revoke 3 certificates").
 * typeToConfirm: optional word the admin must type for irreversible actions.
 */
export default function ConfirmDialog({ open, title, body, confirmLabel, danger = true, typeToConfirm, busy, onConfirm, onClose }) {
  const [typed, setTyped] = useState('');
  const blocked = typeToConfirm && typed !== typeToConfirm;
  const close = () => { setTyped(''); onClose(); };
  return (
    <Dialog open={open} onClose={busy ? undefined : close} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        {body && <DialogContentText component="div">{body}</DialogContentText>}
        {typeToConfirm && (
          <TextField
            autoFocus fullWidth sx={{ mt: 2 }}
            label={`Type ${typeToConfirm} to confirm`}
            value={typed} onChange={(e) => setTyped(e.target.value)}
          />
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close} disabled={busy}>Cancel</Button>
        <Button
          variant="contained" color={danger ? 'error' : 'primary'} disabled={blocked || busy}
          onClick={async () => { await onConfirm(); setTyped(''); }}
        >
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
