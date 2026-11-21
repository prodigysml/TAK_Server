import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert, Autocomplete, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel,
  MenuItem, Stack, Switch, TextField,
} from '@mui/material';
import { api, ApiError } from '../../api/client';
import { useApi } from '../../api/useApi';
import { ROLES, asArray, missionPath, validateMissionName, validateSafeText } from './missionUtils';

const COP_TOOL = 'vbm';
const EMPTY = {
  name: '', description: '', chatRoom: '', tool: 'public', groups: [], defaultRole: '', password: '', expiration: '',
};

// datetime-local value (local time) to Unix seconds.
function toSeconds(local) {
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? null : Math.floor(d.getTime() / 1000);
}

function validate(f) {
  const e = {};
  const n = validateMissionName(f.name);
  if (n) e.name = n;
  const d = validateSafeText(f.description, 'Description');
  if (d) e.description = d;
  const c = validateSafeText(f.chatRoom, 'Chat room');
  if (c) e.chatRoom = c;
  if (!f.tool.trim()) e.tool = 'Enter a tool, for example public.';
  else {
    const t = validateSafeText(f.tool.trim(), 'Tool');
    if (t) e.tool = t;
  }
  // Sent as an HTTP header, which only carries printable ASCII.
  if (f.password && !/^[\x20-\x7E]+$/.test(f.password)) e.password = 'Use letters, numbers, spaces and standard symbols only.';
  if (f.expiration) {
    const s = toSeconds(f.expiration);
    if (s === null) e.expiration = 'Enter a valid date and time.';
    else if (s * 1000 <= Date.now()) e.expiration = 'Pick a time in the future.';
  }
  return e;
}

/**
 * Create a mission with the same fields as the classic Mission Manager's Add tab.
 * The server's PUT /missions/{name} also updates an existing mission of that name,
 * so the dialog checks the name is free first instead of silently editing another mission.
 */
export default function CreateMissionDialog({ open, onClose, onCreated }) {
  const [form, setForm] = useState(EMPTY);
  const [touched, setTouched] = useState({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState('');

  const groupsReq = useApi(
    () => (open ? api.get('/Marti/api/groups/all', { query: { useCache: false, sendLatestSA: false } }) : Promise.resolve(undefined)),
    [open],
  );
  const groupNames = useMemo(() => {
    const names = asArray(groupsReq.data).map((g) => g && g.name).filter((n) => typeof n === 'string' && n);
    return [...new Set(names)].sort((a, b) => a.localeCompare(b));
  }, [groupsReq.data]);

  useEffect(() => {
    if (open) { setForm(EMPTY); setTouched({}); setServerError(''); setBusy(false); }
  }, [open]);

  const errors = validate(form);
  const show = (k) => (touched[k] || touched.submit) && errors[k];
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const blur = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  async function submit(e) {
    e.preventDefault();
    setTouched((t) => ({ ...t, submit: true }));
    if (Object.keys(errors).length) return;
    const name = form.name.trim();
    setBusy(true);
    setServerError('');
    try {
      // Refuse to overwrite: a mission that already exists answers 200 (or 403 if hidden from us).
      let exists = false;
      try {
        await api.get(missionPath(name));
        exists = true;
      } catch (err) {
        // 404 (never existed) and 410 (deleted) both mean the name is free.
        if (!(err instanceof ApiError) || (err.status !== 404 && err.status !== 410)) {
          if (err instanceof ApiError && err.status === 403) exists = true;
          else throw err;
        }
      }
      if (exists) {
        setServerError(`A mission named ${name} already exists. Pick another name.`);
        setBusy(false);
        return;
      }
      const query = {
        description: form.description || undefined,
        chatRoom: form.chatRoom || undefined,
        tool: form.tool.trim(),
        group: form.groups.length ? form.groups : undefined,
        defaultRole: form.defaultRole || undefined,
        expiration: form.expiration ? toSeconds(form.expiration) : undefined,
      };
      // The password goes in the MissionPassword header so it stays out of URLs and access logs.
      const headers = form.password ? { MissionPassword: form.password } : {};
      await api.put(missionPath(name), undefined, { query, headers });
      onCreated(name);
    } catch (err) {
      setServerError(err.message || 'The server couldn’t create the mission. Try again.');
      setBusy(false);
    }
  }

  const cop = form.tool.trim() === COP_TOOL;

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth>
      <form onSubmit={submit} noValidate>
        <DialogTitle>Create mission</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {serverError && <Alert severity="error">{serverError}</Alert>}
            <TextField
              label="Name" required autoFocus fullWidth value={form.name}
              onChange={set('name')} onBlur={blur('name')}
              error={!!show('name')} helperText={show('name') || 'Shown to TAK clients. Can’t be changed later.'}
            />
            <TextField
              label="Description" fullWidth multiline minRows={2} value={form.description}
              onChange={set('description')} onBlur={blur('description')}
              error={!!show('description')} helperText={show('description') || ' '}
            />
            <Autocomplete
              multiple options={groupNames} value={form.groups} loading={groupsReq.loading}
              onChange={(_, v) => setForm((f) => ({ ...f, groups: v }))}
              renderTags={(value, getTagProps) => value.map((g, i) => {
                const { key, ...rest } = getTagProps({ index: i });
                return <Chip key={key} size="small" label={g} {...rest} />;
              })}
              renderInput={(params) => (
                <TextField
                  {...params} label="Groups"
                  error={!!groupsReq.error}
                  helperText={groupsReq.error
                    ? `Couldn’t load groups: ${groupsReq.error.message}`
                    : 'Only members of these groups can see the mission. Leave empty for the __ANON__ group.'}
                />
              )}
            />
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ sm: 'flex-start' }}>
              <TextField
                label="Tool" required fullWidth value={form.tool}
                onChange={set('tool')} onBlur={blur('tool')}
                error={!!show('tool')} helperText={show('tool') || 'Usually public. COP missions use vbm.'}
              />
              <FormControlLabel
                sx={{ flexShrink: 0, mt: { sm: 0.5 } }}
                control={(
                  <Switch
                    checked={cop}
                    onChange={(e) => setForm((f) => ({ ...f, tool: e.target.checked ? COP_TOOL : 'public' }))}
                  />
                )}
                label="Mark as COP"
              />
            </Stack>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                select label="Default role" fullWidth value={form.defaultRole} onChange={set('defaultRole')}
                helperText="Role new subscribers get."
              >
                <MenuItem value="">Server default (subscriber)</MenuItem>
                {ROLES.map((r) => <MenuItem key={r.value} value={r.value}>{r.label}</MenuItem>)}
              </TextField>
              <TextField
                label="Chat room" fullWidth value={form.chatRoom}
                onChange={set('chatRoom')} onBlur={blur('chatRoom')}
                error={!!show('chatRoom')} helperText={show('chatRoom') || 'Optional.'}
              />
            </Stack>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                label="Password" type="password" autoComplete="new-password" fullWidth value={form.password}
                onChange={set('password')} onBlur={blur('password')}
                error={!!show('password')} helperText={show('password') || 'Optional. Clients must enter it to subscribe.'}
              />
              <TextField
                label="Expires" type="datetime-local" fullWidth value={form.expiration}
                onChange={set('expiration')} onBlur={blur('expiration')}
                InputLabelProps={{ shrink: true }}
                error={!!show('expiration')} helperText={show('expiration') || 'Optional. Your local time. Empty means never.'}
              />
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={busy}>{busy ? 'Creating…' : 'Create mission'}</Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}
