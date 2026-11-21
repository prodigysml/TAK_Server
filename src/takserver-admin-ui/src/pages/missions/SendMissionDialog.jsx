import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert, Autocomplete, Button, Chip, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField,
} from '@mui/material';
import { api } from '../../api/client';
import { useApi } from '../../api/useApi';
import { useNotify } from '../../components/Notify';
import { asArray, missionPath, plural, text } from './missionUtils';

const MODES = {
  send: {
    title: 'Send mission package',
    body: 'Connected clients you pick receive the mission’s files and items as a data package.',
    suffix: '/send',
    verb: 'Send to',
    done: (name, n) => `Sent ${name} to ${plural(n, 'client')}`,
  },
  invite: {
    title: 'Invite to mission',
    body: 'Connected clients you pick get an invitation to subscribe to this mission.',
    suffix: '/invite',
    verb: 'Invite',
    done: (name, n) => `Invited ${plural(n, 'client')} to ${name}`,
  },
};

/** Send a mission package to, or invite, connected contacts. Same calls as the classic manager. */
export default function SendMissionDialog({ mode, missionName, onClose }) {
  const notify = useNotify();
  const open = !!mode;
  const cfg = MODES[mode] || MODES.send;
  const [picked, setPicked] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const contacts = useApi(
    () => (open ? api.get('/Marti/api/contacts/all') : Promise.resolve(undefined)),
    [open],
  );
  const options = useMemo(() => {
    const seen = new Set();
    return asArray(contacts.data)
      .map((c) => ({ uid: text(c && c.uid), callsign: text(c && c.callsign), username: text(c && c.username) }))
      .filter((c) => c.uid && !seen.has(c.uid) && seen.add(c.uid))
      .sort((a, b) => (a.callsign || a.uid).localeCompare(b.callsign || b.uid));
  }, [contacts.data]);

  useEffect(() => { if (open) { setPicked([]); setError(''); setBusy(false); } }, [open, mode]);

  async function submit() {
    setBusy(true);
    setError('');
    try {
      const body = new URLSearchParams();
      picked.forEach((c) => body.append('contacts', c.uid));
      await api.post(missionPath(missionName, cfg.suffix), body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
      });
      notify(cfg.done(missionName, picked.length));
      onClose();
    } catch (err) {
      setError(err.message || 'The server didn’t accept the request. Try again.');
      setBusy(false);
    }
  }

  const label = (c) => (c.callsign ? `${c.callsign} (${c.uid})` : c.uid);

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{cfg.title}</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          {cfg.body} Mission: <strong>{missionName}</strong>
        </DialogContentText>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {contacts.error && (
          <Alert severity="error" sx={{ mb: 2 }} action={<Button color="inherit" size="small" onClick={() => contacts.reload()}>Try again</Button>}>
            Couldn’t load connected clients: {contacts.error.message}
          </Alert>
        )}
        <Autocomplete
          multiple options={options} value={picked} loading={contacts.loading}
          getOptionLabel={label}
          isOptionEqualToValue={(a, b) => a.uid === b.uid}
          onChange={(_, v) => setPicked(v)}
          noOptionsText={contacts.loading ? 'Loading clients…' : 'No connected clients'}
          renderTags={(value, getTagProps) => value.map((c, i) => {
            const { key, ...rest } = getTagProps({ index: i });
            return <Chip key={key} size="small" label={c.callsign || c.uid} {...rest} />;
          })}
          renderInput={(params) => (
            <TextField {...params} label="Clients" autoFocus helperText="Search by callsign or UID." />
          )}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant="contained" onClick={submit} disabled={busy || picked.length === 0}>
          {picked.length ? `${cfg.verb} ${plural(picked.length, 'client')}` : cfg.verb}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
