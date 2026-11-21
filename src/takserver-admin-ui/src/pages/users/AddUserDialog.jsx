import React, { useEffect, useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Stack, TextField } from '@mui/material';
import { useNotify } from '../../components/Notify';
import GroupAssignment from './GroupAssignment';
import PasswordField from './PasswordField';
import { USERNAME_RULE, isValidPassword, isValidUsername, usersApi } from './model';

export default function AddUserDialog({ open, onClose, onCreated, users, groups }) {
  const notify = useNotify();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [assignments, setAssignments] = useState([]);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (open) { setUsername(''); setPassword(''); setAssignments([]); setTouched(false); setError(null); }
  }, [open]);

  const name = username.trim();
  const exists = users.includes(name);
  const nameError = touched && name && (!isValidUsername(name) ? USERNAME_RULE : exists ? 'A user with this name already exists.' : '');
  const canSubmit = isValidUsername(name) && !exists && isValidPassword(password) && !busy;

  const submit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      await usersApi.createUser(name, password, assignments);
      setPassword('');
      notify(`Added user ${name}${assignments.length ? ` in ${assignments.length} group${assignments.length === 1 ? '' : 's'}` : ''}`);
      onCreated(name);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth component="form" onSubmit={submit} noValidate>
      <DialogTitle>Add user</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">Couldn’t add the user. {error.message}</Alert>}
          <TextField
            autoFocus required fullWidth label="Username" value={username}
            onChange={(e) => setUsername(e.target.value)} onBlur={() => setTouched(true)}
            error={!!nameError} helperText={nameError || USERNAME_RULE}
            inputProps={{ spellCheck: false, autoCapitalize: 'off', autoComplete: 'off', maxLength: 255 }}
            disabled={busy}
          />
          <PasswordField value={password} onChange={setPassword} disabled={busy} />
          <Divider />
          <GroupAssignment value={assignments} onChange={setAssignments} groups={groups} disabled={busy} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button type="submit" variant="contained" disabled={!canSubmit}>{busy ? 'Adding user…' : 'Add user'}</Button>
      </DialogActions>
    </Dialog>
  );
}
