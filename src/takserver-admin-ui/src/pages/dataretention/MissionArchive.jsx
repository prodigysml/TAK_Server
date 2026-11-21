import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert, Box, Button, FormControlLabel, InputAdornment, Paper, Stack, Switch, TextField, Typography,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import SearchIcon from '@mui/icons-material/Search';
import { api } from '../../api/client';
import { useApi } from '../../api/useApi';
import { useNotify } from '../../components/Notify';
import ConfirmDialog from '../../components/ConfirmDialog';
import { EmptyState, ErrorState, Loading } from '../../components/States';
import ScheduleEditor, { ScheduleSummary } from './ScheduleEditor';
import { DISABLED, validateCron } from './cron';

const CONFIG = '/Marti/api/retention/missionarchiveconfig';
const ARCHIVE = '/Marti/api/retention/missionarchive';
const RESTORE = '/Marti/api/retention/restoremission';

// Same 10-year bound as ExpirationWindow (takserver-common).
const MAX_DAYS = 3650;

function configFrom(d) {
  return {
    cronExpression: typeof d?.cronExpression === 'string' && d.cronExpression.trim() ? d.cronExpression.trim() : DISABLED,
    archiveMissionByNoContentActivity: !!d?.archiveMissionByNoContentActivity,
    archiveMissionByNoSubscriptionActivity: !!d?.archiveMissionByNoSubscriptionActivity,
    timeToArchiveAfterNoActivityDays: d?.timeToArchiveAfterNoActivityDays ?? 365,
    removeFromArchiveAfterDays: d?.removeFromArchiveAfterDays ?? 1065,
  };
}

function daysError(v) {
  if (v === '' || v === null || v === undefined) return 'Enter a number of days.';
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 'Enter a number greater than 0.';
  if (n > MAX_DAYS) return `The longest period is ${MAX_DAYS} days (10 years).`;
  return '';
}

const sameConfig = (a, b) => a.cronExpression === b.cronExpression
  && a.archiveMissionByNoContentActivity === b.archiveMissionByNoContentActivity
  && a.archiveMissionByNoSubscriptionActivity === b.archiveMissionByNoSubscriptionActivity
  && Number(a.timeToArchiveAfterNoActivityDays) === Number(b.timeToArchiveAfterNoActivityDays)
  && Number(a.removeFromArchiveAfterDays) === Number(b.removeFromArchiveAfterDays);

function ArchiveSettings() {
  const notify = useNotify();
  const { data, error, loading, reload } = useApi(() => api.get(CONFIG));
  const saved = useMemo(() => configFrom(data), [data]);
  const [form, setForm] = useState(saved);
  const [busy, setBusy] = useState(false);
  const [confirmShorter, setConfirmShorter] = useState(null);

  useEffect(() => { setForm(saved); }, [saved]);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));
  const archiveErr = daysError(form.timeToArchiveAfterNoActivityDays);
  const removeErr = daysError(form.removeFromArchiveAfterDays);
  const cronErr = validateCron(form.cronExpression);
  const dirty = !sameConfig(form, saved);
  const invalid = !!(archiveErr || removeErr || cronErr);

  const save = async () => {
    const body = {
      ...form,
      timeToArchiveAfterNoActivityDays: Number(form.timeToArchiveAfterNoActivityDays),
      removeFromArchiveAfterDays: Number(form.removeFromArchiveAfterDays),
    };
    setBusy(true);
    try {
      const result = await api.put(CONFIG, body);
      if (result && typeof result === 'object' && result.cronExpression !== undefined && String(result.cronExpression).trim() !== body.cronExpression) {
        notify(new Error('Saved the archive settings, but the server kept its previous schedule. Check the cron expression.'));
      } else {
        notify('Saved mission archive settings');
      }
      reload(true);
    } catch (e) {
      notify(e);
    } finally {
      setBusy(false);
    }
  };

  // Lowering either window archives or permanently deletes missions on the next run.
  const requestSave = () => {
    const lowered = [];
    if (Number(form.timeToArchiveAfterNoActivityDays) < Number(saved.timeToArchiveAfterNoActivityDays)) {
      lowered.push(`Missions with no activity for ${Number(form.timeToArchiveAfterNoActivityDays)} days will be archived (was ${Number(saved.timeToArchiveAfterNoActivityDays)}).`);
    }
    if (Number(form.removeFromArchiveAfterDays) < Number(saved.removeFromArchiveAfterDays)) {
      lowered.push(`Archived missions older than ${Number(form.removeFromArchiveAfterDays)} days will be deleted for good (was ${Number(saved.removeFromArchiveAfterDays)}).`);
    }
    if (lowered.length) setConfirmShorter(lowered);
    else save();
  };

  if (loading && data === undefined) return <Loading />;
  if (error && data === undefined) return <ErrorState error={error} onRetry={reload} />;

  const neither = !form.archiveMissionByNoContentActivity && !form.archiveMissionByNoSubscriptionActivity;

  return (
    <Box>
      <Stack spacing={1}>
        <Typography variant="subtitle2" component="h3">Archive a mission when it has no</Typography>
        <FormControlLabel
          control={<Switch checked={form.archiveMissionByNoContentActivity} onChange={(e) => set({ archiveMissionByNoContentActivity: e.target.checked })} />}
          label="Content activity (nothing added or changed)"
        />
        <FormControlLabel
          control={<Switch checked={form.archiveMissionByNoSubscriptionActivity} onChange={(e) => set({ archiveMissionByNoSubscriptionActivity: e.target.checked })} />}
          label="Subscription activity (no one subscribing)"
        />
        {neither && form.cronExpression !== DISABLED && (
          <Alert severity="info" sx={{ maxWidth: 640 }}>Turn on at least one condition, or no missions will be archived when the schedule runs.</Alert>
        )}
      </Stack>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ mt: 2.5 }}>
        <TextField
          type="number" label="Archive after no activity for" value={form.timeToArchiveAfterNoActivityDays}
          onChange={(e) => set({ timeToArchiveAfterNoActivityDays: e.target.value })}
          inputProps={{ min: 0, step: 'any' }}
          InputProps={{ endAdornment: <InputAdornment position="end">days</InputAdornment> }}
          error={!!archiveErr} helperText={archiveErr || ' '} sx={{ maxWidth: 280 }}
        />
        <TextField
          type="number" label="Delete from archive after" value={form.removeFromArchiveAfterDays}
          onChange={(e) => set({ removeFromArchiveAfterDays: e.target.value })}
          inputProps={{ min: 0, step: 'any' }}
          InputProps={{ endAdornment: <InputAdornment position="end">days</InputAdornment> }}
          error={!!removeErr} helperText={removeErr || 'Archived missions older than this are deleted for good'} sx={{ maxWidth: 320 }}
        />
      </Stack>

      <Typography variant="subtitle2" component="h3" sx={{ mt: 2, mb: 1 }}>Check for missions to archive</Typography>
      <Stack direction="row" spacing={1} alignItems="baseline" sx={{ mb: 2 }} flexWrap="wrap" useFlexGap>
        <Typography variant="body2" color="text.secondary">Currently:</Typography>
        <ScheduleSummary value={saved.cronExpression} />
      </Stack>
      <ScheduleEditor
        idPrefix="archive-schedule" value={form.cronExpression} disabled={busy}
        onChange={(c) => set({ cronExpression: c })}
      />

      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button variant="contained" disabled={!dirty || invalid || busy} onClick={requestSave}>Save archive settings</Button>
        <Button disabled={!dirty || busy} onClick={() => setForm(saved)}>Discard changes</Button>
      </Stack>

      <ConfirmDialog
        open={!!confirmShorter}
        busy={busy}
        title="Archive or delete missions sooner?"
        body={(
          <>
            {(confirmShorter || []).map((t) => <Box component="span" key={t} sx={{ display: 'block', mb: 1 }}>{t}</Box>)}
            This takes effect the next time the archive schedule runs.
          </>
        )}
        confirmLabel="Save archive settings"
        onConfirm={async () => { await save(); setConfirmShorter(null); }}
        onClose={() => setConfirmShorter(null)}
      />
    </Box>
  );
}

function fmtTime(ms, raw) {
  const n = Number(ms);
  if (ms !== null && ms !== undefined && ms !== '' && Number.isFinite(n)) {
    return new Date(n).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  return raw ? String(raw) : '';
}

function parseArchive(data) {
  // The server returns the archive index as a JSON string inside the envelope.
  let obj = data;
  if (typeof data === 'string') {
    try { obj = data.trim() ? JSON.parse(data) : {}; } catch { throw new Error('The server returned an archive list this page can’t read.'); }
  }
  const entries = Array.isArray(obj?.missionArchiveStoreEntries) ? obj.missionArchiveStoreEntries : [];
  return entries.map((e) => ({
    id: e.id,
    missionName: String(e.missionName ?? ''),
    createMs: Number(e.createTimeMs) || null,
    archiveMs: Number(e.archiveTimeMs) || null,
    createTime: fmtTime(e.createTimeMs, e.createTime),
    archiveTime: fmtTime(e.archiveTimeMs, e.archiveTime),
  }));
}

function ArchivedMissions() {
  const notify = useNotify();
  const { data, error, loading, reload } = useApi(async () => parseArchive(await api.get(ARCHIVE)));
  const [query, setQuery] = useState('');
  const [target, setTarget] = useState(null);
  const [busy, setBusy] = useState(false);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const all = data || [];
    if (!q) return all;
    return all.filter((r) => r.missionName.toLowerCase().includes(q) || r.createTime.toLowerCase().includes(q) || r.archiveTime.toLowerCase().includes(q));
  }, [data, query]);

  const restore = async () => {
    setBusy(true);
    try {
      // Body is the entry id as a bare JSON number (@RequestBody Integer id).
      const msg = await api.post(RESTORE, target.id);
      const text = typeof msg === 'string' ? msg : '';
      if (text.endsWith(' Restored')) {
        notify(`Restored mission ${target.missionName}`);
      } else {
        notify(new Error(`Couldn’t restore ${target.missionName}: ${text || 'the server gave no reason'}.`));
      }
      setTarget(null);
      reload(true);
    } catch (e) {
      notify(e);
    } finally {
      setBusy(false);
    }
  };

  const columns = [
    { field: 'missionName', headerName: 'Mission', flex: 1, minWidth: 200 },
    { field: 'createTime', headerName: 'Created', width: 190, sortComparator: (a, b, p1, p2) => (p1.api.getRow(p1.id).createMs || 0) - (p2.api.getRow(p2.id).createMs || 0) },
    { field: 'archiveTime', headerName: 'Archived', width: 190, sortComparator: (a, b, p1, p2) => (p1.api.getRow(p1.id).archiveMs || 0) - (p2.api.getRow(p2.id).archiveMs || 0) },
    {
      field: 'actions', headerName: '', width: 110, sortable: false, filterable: false, disableColumnMenu: true,
      renderCell: (p) => (
        <Button size="small" onClick={() => setTarget(p.row)} aria-label={`Restore mission ${p.row.missionName}`}>Restore</Button>
      ),
    },
  ];

  if (loading && data === undefined) return <Loading />;
  if (error && data === undefined) return <ErrorState error={error} onRetry={reload} />;

  return (
    <Box>
      {data.length === 0 ? (
        <EmptyState
          title="No archived missions"
          body="Missions appear here after the archive schedule moves inactive missions out of the database. Turn on an archive condition above to start."
        />
      ) : (
        <>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ sm: 'center' }} sx={{ mb: 1.5 }}>
            <TextField
              placeholder="Search by mission or date" value={query} onChange={(e) => setQuery(e.target.value)}
              inputProps={{ 'aria-label': 'Search archived missions' }}
              InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
              sx={{ maxWidth: 360, width: '100%' }}
            />
            <Typography variant="body2" color="text.secondary">
              {rows.length === data.length ? `${data.length} archived ${data.length === 1 ? 'mission' : 'missions'}` : `${rows.length} of ${data.length} shown`}
            </Typography>
          </Stack>
          <Box sx={{ width: '100%', overflowX: 'auto' }}>
            <DataGrid
              autoHeight rows={rows} columns={columns} getRowId={(r) => r.id}
              initialState={{ sorting: { sortModel: [{ field: 'archiveTime', sort: 'desc' }] }, pagination: { paginationModel: { pageSize: 25 } } }}
              pageSizeOptions={[25, 50, 100]}
              localeText={{ noRowsLabel: 'No archived missions match your search' }}
              sx={{ minWidth: 640 }}
            />
          </Box>
        </>
      )}

      <ConfirmDialog
        open={!!target}
        danger={false}
        busy={busy}
        title={target ? `Restore ${target.missionName}?` : ''}
        confirmLabel="Restore mission"
        onClose={() => setTarget(null)}
        onConfirm={restore}
        body={target && 'The mission, its content and its CoT are put back in the database and it is removed from the archive. Restore fails if a mission with the same name already exists.'}
      />
    </Box>
  );
}

export default function MissionArchive() {
  return (
    <Stack spacing={3}>
      <Paper variant="outlined" sx={{ p: { xs: 2, md: 2.5 } }}>
        <ArchiveSettings />
      </Paper>
      <Box>
        <Typography variant="h3" component="h3" sx={{ mb: 1.5 }}>Archived missions</Typography>
        <ArchivedMissions />
      </Box>
    </Stack>
  );
}
