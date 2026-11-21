import React, { useEffect, useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Stack } from '@mui/material';
import { useNotify } from '../../components/Notify';
import PasswordField from './PasswordField';
import { isValidPassword, usersApi } from './model';

export default function ChangePasswordDialog({ username, onClose }) {
  const notify = useNotify();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => { setPassword(''); setError(null); }, [username]);

  const submit = async (e) => {
    e.preventDefault();
    if (!isValidPassword(password) || busy) return;
    setBusy(true);
    setError(null);
    try {
      await usersApi.changePassword(username, password);
      setPassword('');
      notify(`Changed the password for ${username}`);
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={!!username} onClose={busy ? undefined : onClose} maxWidth="xs" fullWidth component="form" onSubmit={submit} noValidate>
      <DialogTitle>Change password for {username}</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <DialogContentText>The old password stops working as soon as you save. Tell the user their new password through a secure channel.</DialogContentText>
          {error && <Alert severity="error">Couldn’t change the password. {error.message}</Alert>}
          {/* Hidden username helps password managers file the new password under the right account. */}
          <input type="text" name="username" autoComplete="username" value={username || ''} readOnly hidden />
          <PasswordField label="New password" value={password} onChange={setPassword} autoFocus disabled={busy} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button type="submit" variant="contained" disabled={busy || !isValidPassword(password)}>
          {busy ? 'Changing password…' : 'Change password'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
