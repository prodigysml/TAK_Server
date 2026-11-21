import React, { useEffect, useState } from 'react';
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { api, ApiError, seg } from '../../api/client';
import { useNotify } from '../../components/Notify';
import { ErrorState, Loading } from '../../components/States';
import { Facts, SwitchField } from './common';
import { PROTOCOL_SHORT, authLabel, linesToList, listToLines, validateFilterGroups } from './model';

const NOMOD_HINT = 'Name, protocol, authentication, port, multicast group and interface can’t be changed after an input is created. Delete the input and add it again to change those.';

/**
 * Edit an input's archive flags and filter groups.
 * Loads GET /Marti/api/inputs/{name} and sends the same object back with PUT /Marti/api/inputs/{name},
 * as the classic page does.
 */
export default function EditInputDialog({ name, onClose, onSaved }) {
  const notify = useNotify();
  const open = !!name;
  const [state, setState] = useState({ loading: false, error: null, input: null });
  const [f, setF] = useState({ archive: true, archiveOnly: false, filtergroup: '' });
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState(null);

  const load = async () => {
    setState({ loading: true, error: null, input: null });
    setSaveError(null);
    try {
      const metric = await api.get(`/Marti/api/inputs/${seg(name)}`);
      const input = metric?.input;
      if (!input) throw new ApiError(404, `Input “${name}” no longer exists. It may have been deleted.`);
      setState({ loading: false, error: null, input });
      setF({ archive: !!input.archive, archiveOnly: !!input.archiveOnly, filtergroup: listToLines(input.filtergroup) });
    } catch (error) {
      setState({ loading: false, error, input: null });
    }
  };

  useEffect(() => { if (open) load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [name]);

  const fgError = validateFilterGroups(f.filtergroup);
  const archiveOnlyError = f.archiveOnly && !f.archive ? 'Turn on archive first. Archive only needs archiving.' : null;

  const save = async (e) => {
    e.preventDefault();
    if (fgError || archiveOnlyError || !state.input) return;
    setBusy(true);
    setSaveError(null);
    try {
      const body = { ...state.input, archive: f.archive, archiveOnly: f.archiveOnly, filtergroup: linesToList(f.filtergroup) };
      await api.put(`/Marti/api/inputs/${seg(state.input.name)}`, body);
      notify(`Saved changes to input “${state.input.name}”`);
      onSaved();
    } catch (err) {
      // The server puts its reason in data.displayMessage, which the shared client doesn't surface.
      setSaveError(err.status === 400 ? `The server refused the change. ${NOMOD_HINT}` : err.message);
    } finally {
      setBusy(false);
    }
  };

  const input = state.input;
  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth>
      <form onSubmit={save} noValidate>
        <DialogTitle>Edit input {name ? `“${name}”` : ''}</DialogTitle>
        <DialogContent dividers>
          {state.loading && <Loading />}
          {state.error && <ErrorState error={state.error} onRetry={load} />}
          {input && (
            <>
              <Facts items={[
                ['Protocol', PROTOCOL_SHORT[String(input.protocol).toLowerCase()] || input.protocol],
                ['Port', input.port],
                ['Authentication', authLabel(input.auth)],
                ['Core version', input.coreVersion],
                input.group && ['Multicast group', input.group],
                input.iface && ['Interface', input.iface],
              ]} />
              {saveError && <Alert severity="error" sx={{ mb: 2 }}>{saveError}</Alert>}
              <Stack spacing={2}>
                <Box>
                  <SwitchField
                    label="Archive" checked={f.archive}
                    onChange={(v) => setF((s) => ({ ...s, archive: v, archiveOnly: v ? s.archiveOnly : false }))}
                    help="Store messages received on this input in the database."
                  />
                  <SwitchField
                    label="Archive only" checked={f.archiveOnly} disabled={!f.archive}
                    onChange={(v) => setF((s) => ({ ...s, archiveOnly: v }))}
                    help="Store messages without sending them on to other clients." error={archiveOnlyError}
                  />
                </Box>
                <TextField
                  label="Filter groups" multiline minRows={4} value={f.filtergroup}
                  onChange={(e) => setF((s) => ({ ...s, filtergroup: e.target.value }))}
                  error={!!fgError}
                  helperText={fgError || 'One group per line. Clients connecting on this port are placed in these groups.'}
                />
              </Stack>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={busy || !input}>{busy ? 'Saving…' : 'Save changes'}</Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}
