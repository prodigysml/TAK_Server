import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Typography } from '@mui/material';
import { useApi } from '../../api/useApi';
import { useNotify } from '../../components/Notify';
import { ErrorState, Loading } from '../../components/States';
import GroupAssignment from './GroupAssignment';
import { usersApi } from './model';

const key = (list) => JSON.stringify([...list].sort((a, b) => a.name.localeCompare(b.name)));

export default function EditGroupsDialog({ username, onClose, onSaved, groups }) {
  const notify = useNotify();
  const open = !!username;
  const { data, error, loading, reload } = useApi(
    () => (username ? usersApi.groupsForUser(username) : Promise.resolve([])),
    [username],
  );
  const [assignments, setAssignments] = useState([]);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState(null);

  useEffect(() => { if (data) setAssignments(data); setSaveError(null); }, [data]);
  const dirty = useMemo(() => !!data && key(data) !== key(assignments), [data, assignments]);

  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      await usersApi.updateGroups(username, assignments);
      notify(`Updated groups for ${username}`);
      onSaved();
    } catch (err) {
      setSaveError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Edit groups for {username}</DialogTitle>
      <DialogContent>
        {loading && <Loading />}
        {error && <ErrorState error={error} onRetry={reload} />}
        {!loading && !error && data && (
          <Stack spacing={2} sx={{ pt: 1 }}>
            {saveError && <Alert severity="error">Couldn’t save the groups. {saveError.message}</Alert>}
            <GroupAssignment
              value={assignments} onChange={setAssignments} groups={groups} disabled={busy}
              emptyNote="No groups assigned. If you save with no groups, the user is placed in the __ANON__ group."
            />
            {dirty && <Typography variant="body2" color="text.secondary">You have unsaved changes.</Typography>}
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => data && setAssignments(data)} disabled={busy || !dirty} sx={{ mr: 'auto' }}>Undo changes</Button>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={busy || !dirty || loading || !!error}>
          {busy ? 'Saving…' : 'Save groups'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
