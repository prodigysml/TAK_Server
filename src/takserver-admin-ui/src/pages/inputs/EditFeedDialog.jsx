import React, { useEffect, useState } from 'react';
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { api, ApiError, seg } from '../../api/client';
import { useNotify } from '../../components/Notify';
import { ErrorState, Loading } from '../../components/States';
import { Facts, SwitchField } from './common';
import {
  PROTOCOL_SHORT, authLabel, feedPutBody, linesToList, listToLines, validateFilterGroups, validateRetention,
} from './model';

// Which fields the classic page lets you edit for each feed type.
const EDITABLE = {
  Streaming: ['archive', 'archiveOnly', 'filterGroups', 'tags', 'syncCacheRetentionSeconds', 'sync', 'federated'],
  Plugin: ['archive', 'tags', 'sync', 'federated'],
  Federation: ['archive', 'archiveOnly', 'sync'],
};

/**
 * Edit a data feed. Loads GET /Marti/api/datafeeds/{name}, saves with PUT /Marti/api/datafeeds/{name}.
 */
export default function EditFeedDialog({ name, onClose, onSaved }) {
  const notify = useNotify();
  const open = !!name;
  const [state, setState] = useState({ loading: false, error: null, feed: null });
  const [f, setF] = useState({});
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState(null);

  const load = async () => {
    setState({ loading: true, error: null, feed: null });
    setSaveError(null);
    try {
      const feed = await api.get(`/Marti/api/datafeeds/${seg(name)}`);
      if (!feed || typeof feed !== 'object') throw new ApiError(404, `Data feed “${name}” wasn’t found. It may have been deleted.`);
      setState({ loading: false, error: null, feed });
      setF({
        archive: !!feed.archive,
        archiveOnly: !!feed.archiveOnly,
        sync: !!feed.sync,
        federated: !!feed.federated,
        filterGroups: listToLines(feed.filterGroups),
        tags: listToLines(feed.tags),
        syncCacheRetentionSeconds: String(feed.syncCacheRetentionSeconds ?? 3600),
      });
    } catch (error) {
      // The server answers 400 when the feed doesn't exist or isn't in your groups.
      setState({ loading: false, error: error.status === 400 ? new Error(`Data feed “${name}” wasn’t found, or it isn’t shared with your groups.`) : error, feed: null });
    }
  };

  useEffect(() => { if (open) load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [name]);

  const feed = state.feed;
  const type = feed?.type || 'Streaming';
  const can = (k) => (EDITABLE[type] || EDITABLE.Streaming).includes(k);
  const set = (k) => (v) => setF((s) => ({ ...s, [k]: v }));

  const errors = {
    filterGroups: can('filterGroups') ? validateFilterGroups(f.filterGroups) : null,
    archiveOnly: can('archiveOnly') && f.archiveOnly && !f.archive ? 'Turn on archive first. Archive only needs archiving.' : null,
    syncCacheRetentionSeconds: can('syncCacheRetentionSeconds') ? validateRetention(f.syncCacheRetentionSeconds) : null,
  };
  const hasErrors = Object.values(errors).some(Boolean);

  const save = async (e) => {
    e.preventDefault();
    if (hasErrors || !feed) return;
    setBusy(true);
    setSaveError(null);
    try {
      const filterGroups = can('filterGroups') ? linesToList(f.filterGroups) : (feed.filterGroups || []);
      const tags = can('tags') ? linesToList(f.tags) : (feed.tags || []);
      const changes = {
        archive: f.archive,
        archiveOnly: can('archiveOnly') ? f.archiveOnly : feed.archiveOnly,
        sync: f.sync,
        federated: can('federated') ? f.federated : feed.federated,
        syncCacheRetentionSeconds: can('syncCacheRetentionSeconds') ? Number(f.syncCacheRetentionSeconds) : feed.syncCacheRetentionSeconds,
        filtergroup: filterGroups,
        tag: tags,
      };
      await api.put(`/Marti/api/datafeeds/${seg(feed.name)}`, feedPutBody(feed, changes));
      notify(`Saved changes to data feed “${feed.name}”`);
      onSaved();
    } catch (err) {
      setSaveError(err.status === 400
        ? 'The server refused the change. The feed may have been deleted or isn’t shared with your groups. Reload and try again.'
        : err.message);
    } finally {
      setBusy(false);
    }
  };

  const hadTags = (feed?.tags || []).length > 0;
  const hadGroups = (feed?.filterGroups || []).length > 0;

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth>
      <form onSubmit={save} noValidate>
        <DialogTitle>Edit data feed {name ? `“${name}”` : ''}</DialogTitle>
        <DialogContent dividers>
          {state.loading && <Loading />}
          {state.error && <ErrorState error={state.error} onRetry={load} />}
          {feed && (
            <>
              <Facts items={[
                ['Type', type],
                type !== 'Plugin' && ['Protocol', PROTOCOL_SHORT[String(feed.protocol || '').toLowerCase()] || feed.protocol],
                type !== 'Plugin' && ['Port', feed.port],
                type !== 'Plugin' && ['Authentication', authLabel(feed.auth)],
              ]} />
              {saveError && <Alert severity="error" sx={{ mb: 2 }}>{saveError}</Alert>}
              <Stack spacing={2}>
                {can('tags') && (
                  <TextField
                    label="Tags" multiline minRows={2} value={f.tags} onChange={(e) => set('tags')(e.target.value)}
                    helperText={hadTags ? 'One tag per line. The server keeps the old tags if you clear them all.' : 'One tag per line.'}
                  />
                )}
                {can('filterGroups') && (
                  <TextField
                    label="Filter groups" multiline minRows={3} value={f.filterGroups} onChange={(e) => set('filterGroups')(e.target.value)}
                    error={!!errors.filterGroups}
                    helperText={errors.filterGroups || (hadGroups
                      ? 'One group per line. Only these groups can see the feed. The server keeps the old groups if you clear them all.'
                      : 'One group per line. Only these groups can see the feed.')}
                  />
                )}
                {can('syncCacheRetentionSeconds') && (
                  <TextField
                    label="Sync cache retention (seconds)" value={f.syncCacheRetentionSeconds}
                    onChange={(e) => set('syncCacheRetentionSeconds')(e.target.value.replace(/[^0-9]/g, ''))}
                    inputProps={{ inputMode: 'numeric', maxLength: 15 }} error={!!errors.syncCacheRetentionSeconds}
                    helperText={errors.syncCacheRetentionSeconds || 'How long synced feed data is kept for clients that connect later.'}
                  />
                )}
                <Box>
                  <SwitchField
                    label="Archive" checked={f.archive}
                    onChange={(v) => setF((s) => ({ ...s, archive: v, archiveOnly: v ? s.archiveOnly : false }))}
                    help="Store this feed’s messages in the database."
                  />
                  {can('archiveOnly') && (
                    <SwitchField
                      label="Archive only" checked={f.archiveOnly} disabled={!f.archive} onChange={set('archiveOnly')}
                      help="Store messages without sending them on to other clients." error={errors.archiveOnly}
                    />
                  )}
                  <SwitchField label="Sync" checked={f.sync} onChange={set('sync')} help="Keep recent feed data so newly connected clients get it." />
                  {can('federated') && (
                    <SwitchField label="Federated" checked={f.federated} onChange={set('federated')} help="Share this feed’s data with federated servers." />
                  )}
                </Box>
              </Stack>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={busy || !feed}>{busy ? 'Saving…' : 'Save changes'}</Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}
