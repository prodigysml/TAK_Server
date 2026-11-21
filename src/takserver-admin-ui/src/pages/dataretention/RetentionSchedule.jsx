import React, { useEffect, useState } from 'react';
import { Box, Button, Stack, Typography } from '@mui/material';
import { api } from '../../api/client';
import { useApi } from '../../api/useApi';
import { useNotify } from '../../components/Notify';
import { ErrorState, Loading } from '../../components/States';
import ScheduleEditor, { ScheduleSummary } from './ScheduleEditor';
import { DISABLED, validateCron } from './cron';

const SCHEDULE = '/Marti/api/retention/service/schedule';

export default function RetentionSchedule() {
  const notify = useNotify();
  const { data, error, loading, reload } = useApi(() => api.get(SCHEDULE));
  const saved = typeof data === 'string' && data.trim() ? data.trim() : DISABLED;
  const [cron, setCron] = useState(saved);
  const [busy, setBusy] = useState(false);

  useEffect(() => { setCron(saved); }, [saved]);

  const err = validateCron(cron);
  const dirty = cron !== saved;

  const save = async () => {
    setBusy(true);
    try {
      // The server takes the raw expression as the request body (@RequestBody String).
      const result = await api.put(SCHEDULE, cron);
      if (typeof result !== 'string' || result.trim() !== cron) {
        // An invalid expression is ignored by the server without an error status.
        notify(new Error('The server didn’t accept that schedule, so the previous one is still in effect. Check the cron expression.'));
      } else {
        notify(cron === DISABLED ? 'Turned off the retention schedule' : 'Saved the retention schedule');
      }
      reload(true);
    } catch (e) {
      notify(e);
    } finally {
      setBusy(false);
    }
  };

  if (loading && data === undefined) return <Loading />;
  if (error && data === undefined) return <ErrorState error={error} onRetry={reload} />;

  return (
    <Box>
      <Stack direction="row" spacing={1} alignItems="baseline" sx={{ mb: 2 }} flexWrap="wrap" useFlexGap>
        <Typography variant="body2" color="text.secondary">Currently:</Typography>
        <ScheduleSummary value={saved} />
      </Stack>
      <ScheduleEditor idPrefix="retention-schedule" value={cron} onChange={(c) => setCron(c)} disabled={busy} />
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button variant="contained" disabled={!dirty || !!err || busy} onClick={save}>Save retention schedule</Button>
        <Button disabled={!dirty || busy} onClick={() => setCron(saved)}>Discard changes</Button>
      </Stack>
    </Box>
  );
}
