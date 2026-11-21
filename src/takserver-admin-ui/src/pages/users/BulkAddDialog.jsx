import React, { useEffect, useState } from 'react';
import {
  Alert, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Divider,
  FormControlLabel, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import { useNotify } from '../../components/Notify';
import GroupAssignment from './GroupAssignment';
import { isValidUsername, usersApi } from './model';

const MAX_USERS = 1000;
const FILE_NAME = 'tak_users.txt';

// Save the generated credentials as a local file. The Blob is built here from the
// create response; nothing is fetched from a URL.
function downloadCredentials(rows) {
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = FILE_NAME;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function parseIntStrict(s) {
  const t = String(s).trim();
  return /^\d{1,9}$/.test(t) ? Number(t) : NaN;
}

export default function BulkAddDialog({ open, onClose, onCreated, users, groups }) {
  const notify = useNotify();
  const [expr, setExpr] = useState('');
  const [start, setStart] = useState('1');
  const [end, setEnd] = useState('10');
  const [assignments, setAssignments] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState(null); // { rows, requested }
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (open) {
      setExpr(''); setStart('1'); setEnd('10'); setAssignments([]); setError(null);
      setConfirming(false); setResult(null); setSaved(false);
    }
  }, [open]);

  const e = expr.trim();
  const s = parseIntStrict(start);
  const n = parseIntStrict(end);
  const count = Number.isNaN(s) || Number.isNaN(n) ? 0 : n - s + 1;
  const sample = (i) => e.replaceAll('[N]', String(i));
  const exprError = !e ? '' : !e.includes('[N]') ? 'Include [N] where the number goes, for example team-[N].'
    : !isValidUsername(sample(s || 0)) ? 'Generated names need at least 4 characters: letters, numbers, dots, underscores and hyphens.' : '';
  const rangeError = Number.isNaN(s) ? 'Enter a whole number, 0 or more.'
    : Number.isNaN(n) ? '' : n < s ? 'End must be the same as or after start.'
      : count > MAX_USERS ? `Create at most ${MAX_USERS.toLocaleString()} users at a time.` : '';
  const endError = Number.isNaN(n) ? 'Enter a whole number, 0 or more.' : '';
  const clashes = count > 0 && !exprError && count <= MAX_USERS
    ? Array.from({ length: count }, (_, k) => sample(s + k)).filter((u) => users.includes(u)).length : 0;
  const canSubmit = e && !exprError && !rangeError && !endError && count > 0 && clashes < count && !busy;

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const rows = await usersApi.createUsers(e, s, n, assignments);
      setResult({ rows, requested: count });
      setConfirming(false);
      downloadCredentials(rows);
      onCreated();
      notify(`Added ${rows.length} user${rows.length === 1 ? '' : 's'}. Credentials file downloaded.`);
    } catch (err) {
      setConfirming(false);
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const closeResult = () => { setResult(null); onClose(); };

  if (result) {
    const skipped = result.requested - result.rows.length;
    return (
      <Dialog open={open} maxWidth="sm" fullWidth onClose={saved ? closeResult : undefined}>
        <DialogTitle>Save these credentials now</DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            <Alert severity="warning">
              The server doesn’t keep these passwords. {FILE_NAME} has been downloaded; once you close this window you can’t get them back and would need to set new passwords.
            </Alert>
            <Typography>
              Added {result.rows.length} user{result.rows.length === 1 ? '' : 's'}.
              {skipped > 0 && ` ${skipped} skipped because the name already exists or isn’t allowed.`}
            </Typography>
            <Paper variant="outlined" sx={{ maxHeight: 240, overflow: 'auto' }}>
              <Table size="small" stickyHeader aria-label="Created users">
                <TableHead><TableRow><TableCell>Username</TableCell></TableRow></TableHead>
                <TableBody>
                  {result.rows.map((r) => <TableRow key={r.username}><TableCell>{r.username}</TableCell></TableRow>)}
                </TableBody>
              </Table>
            </Paper>
            <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => downloadCredentials(result.rows)} sx={{ alignSelf: 'flex-start' }}>
              Download credentials again
            </Button>
            <FormControlLabel
              control={<Checkbox checked={saved} onChange={(ev) => setSaved(ev.target.checked)} />}
              label="I’ve saved the credentials file somewhere safe"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button variant="contained" onClick={closeResult} disabled={!saved}>Close</Button>
        </DialogActions>
      </Dialog>
    );
  }

  return (
    <>
      <Dialog open={open && !confirming} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth component="form" noValidate
        onSubmit={(ev) => { ev.preventDefault(); if (canSubmit) setConfirming(true); }}
      >
        <DialogTitle>Add users in bulk</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText>
              Creates numbered users with server-generated passwords. You get one chance to download the passwords.
            </DialogContentText>
            {error && <Alert severity="error">Couldn’t add the users. {error.message}</Alert>}
            <TextField
              autoFocus required fullWidth label="Username pattern" value={expr} onChange={(ev) => setExpr(ev.target.value)}
              placeholder="team-[N]" error={!!exprError}
              helperText={exprError || '[N] is replaced by each number in the range.'}
              inputProps={{ spellCheck: false, autoCapitalize: 'off', autoComplete: 'off', maxLength: 240 }}
              disabled={busy}
            />
            <Stack direction="row" spacing={2}>
              <TextField required label="First number" value={start} onChange={(ev) => setStart(ev.target.value)}
                inputProps={{ inputMode: 'numeric' }} error={!!rangeError} helperText={rangeError || ' '} disabled={busy} sx={{ flex: 1 }} />
              <TextField required label="Last number" value={end} onChange={(ev) => setEnd(ev.target.value)}
                inputProps={{ inputMode: 'numeric' }} error={!!endError} helperText={endError || ' '} disabled={busy} sx={{ flex: 1 }} />
            </Stack>
            {canSubmit && (
              <Typography variant="body2" color="text.secondary">
                Creates {count === 1 ? sample(s) : `${sample(s)} to ${sample(n)} (${count} users)`}.
                {clashes > 0 && ` ${clashes} already exist and will be skipped.`}
              </Typography>
            )}
            {e && !exprError && count > 0 && clashes === count && (
              <Alert severity="info">Every name in this range already exists. Change the pattern or the numbers.</Alert>
            )}
            <Divider />
            <GroupAssignment value={assignments} onChange={setAssignments} groups={groups} disabled={busy} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={!canSubmit}>
            {count > 0 && canSubmit ? `Add ${count - clashes} user${count - clashes === 1 ? '' : 's'}` : 'Add users'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={open && confirming} onClose={busy ? undefined : () => setConfirming(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Add {count - clashes} user{count - clashes === 1 ? '' : 's'}?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Your browser will download {FILE_NAME} with each username and password. It’s your only chance to save them. Keep the file somewhere safe and delete it once the passwords are handed out.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirming(false)} disabled={busy}>Back</Button>
          <Button variant="contained" onClick={create} disabled={busy}>
            {busy ? 'Adding users…' : `Add ${count - clashes} user${count - clashes === 1 ? '' : 's'}`}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
