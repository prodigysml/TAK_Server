import React, { useEffect, useState } from 'react';
import {
  Box, Chip, Divider, Paper, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography,
} from '@mui/material';
import { api } from '../../api/client';
import { useApi, usePolling } from '../../api/useApi';
import { useNotify } from '../../components/Notify';
import { ErrorState, Loading } from '../../components/States';
import ConfirmDialog from '../../components/ConfirmDialog';
import RateRulesEditor from './RateRulesEditor';
import { POLL_MS } from './model';

// /qos/ratelimit/*/active returns a Map.Entry, serialized as { "<threshold>": <limit> }.
function firstEntry(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const keys = Object.keys(obj);
  if (!keys.length) return null;
  const k = keys[keys.length - 1];
  return { threshold: Number(k), limit: Number(obj[k]) };
}

function OnOffChip({ on }) {
  return on ? <Chip size="small" color="success" label="On" /> : <Chip size="small" variant="outlined" label="Off" />;
}

// One setting row: title, one-line explanation, switch on the right.
function SettingRow({ title, help, checked, busy, onChange, children }) {
  const id = `setting-${title.replace(/\W+/g, '-').toLowerCase()}`;
  return (
    <Box sx={{ py: 2 }}>
      <Stack direction="row" spacing={2} alignItems="flex-start" justifyContent="space-between">
        <Box sx={{ minWidth: 0 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="h3" component="h3" id={id}>{title}</Typography>
            {checked !== undefined && <OnOffChip on={checked} />}
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 680 }}>{help}</Typography>
        </Box>
        {checked !== undefined && (
          <Switch checked={!!checked} disabled={busy} onChange={(e) => onChange(e.target.checked)} inputProps={{ 'aria-labelledby': id }} />
        )}
      </Stack>
      {children && <Box sx={{ mt: 1.5 }}>{children}</Box>}
    </Box>
  );
}

function ActiveLine({ entry, limitWord = 'Current limit', unit = 's', noLimit = 'no limit' }) {
  if (!entry) return <Typography variant="body2" color="text.secondary">No rule is active right now.</Typography>;
  return (
    <Typography variant="body2">
      Active rule: threshold <strong>{entry.threshold < 1 ? 'none' : entry.threshold}</strong> clients.{' '}
      {limitWord}: <strong>{entry.limit < 1 ? noLimit : `${entry.limit}${unit}`}</strong>.
    </Typography>
  );
}

/** Store-and-forward chat and QoS (delivery, read and DoS rate limiting). */
export default function MessagingTab({ connectedClients }) {
  const notify = useNotify();
  const sf = useApi(() => api.get('/Marti/api/inputs/storeForwardChat/enabled'), []);
  const qos = useApi(() => api.get('/Marti/api/qos/conf'), []);
  const active = usePolling(async () => {
    const [delivery, read, dos] = await Promise.all([
      api.get('/Marti/api/qos/ratelimit/delivery/active').catch(() => null),
      api.get('/Marti/api/qos/ratelimit/read/active').catch(() => null),
      api.get('/Marti/api/qos/ratelimit/dos/active').catch(() => null),
    ]);
    return { delivery: firstEntry(delivery), read: firstEntry(read), dos: firstEntry(dos) };
  }, POLL_MS);

  // Local switch state so toggles feel immediate; reverted if the server refuses.
  const [sfOn, setSfOn] = useState(undefined);
  const [flags, setFlags] = useState({});
  const [busy, setBusy] = useState(null);
  useEffect(() => { if (typeof sf.data === 'boolean') setSfOn(sf.data); }, [sf.data]);
  useEffect(() => {
    const d = qos.data;
    if (d) {
      setFlags({
        delivery: !!d.deliveryRateLimiter?.enabled,
        read: !!d.readRateLimiter?.enabled,
        dos: !!d.dosRateLimiter?.enabled,
      });
    }
  }, [qos.data]);

  const toggleSf = async (on) => {
    setBusy('sf');
    setSfOn(on);
    try {
      await api.put(`/Marti/api/inputs/storeForwardChat/${on ? 'enable' : 'disable'}`);
      notify(on ? 'Turned on store and forward for chat' : 'Turned off store and forward for chat');
    } catch (err) {
      setSfOn(!on);
      notify(err);
    } finally {
      setBusy(null);
    }
  };

  const NAMES = { delivery: 'delivery rate limiting', read: 'read rate limiting', dos: 'DoS protection' };
  // Turning a limiter off applies to every client at once, so confirm it first.
  const [confirmOff, setConfirmOff] = useState(null);
  const requestQos = (key, on) => { if (on) toggleQos(key, true); else setConfirmOff(key); };
  const toggleQos = async (key, on) => {
    setBusy(key);
    setFlags((f) => ({ ...f, [key]: on }));
    try {
      await api.put(`/Marti/api/qos/${key}/enable`, on);
      notify(`Turned ${on ? 'on' : 'off'} ${NAMES[key]}`);
      active.reload(true);
    } catch (err) {
      setFlags((f) => ({ ...f, [key]: !on }));
      notify(err);
    } finally {
      setBusy(null);
    }
  };

  const conf = qos.data;
  const dosRules = conf?.dosRateLimiter?.dosLimitRule || [];
  const dosInterval = conf?.dosRateLimiter?.intervalSeconds;

  return (
    <Stack spacing={3}>
      <Paper variant="outlined" sx={{ px: { xs: 2, sm: 3 } }}>
        <Typography variant="h2" sx={{ pt: 2 }}>Chat delivery</Typography>
        {sf.loading && sfOn === undefined ? <Loading /> : sf.error ? <Box sx={{ pb: 2 }}><ErrorState error={sf.error} onRetry={sf.reload} /></Box> : (
          <SettingRow
            title="Store and forward for chat"
            help="Hold chat messages for offline users and deliver them when they reconnect. Applies immediately."
            checked={sfOn} busy={busy === 'sf'} onChange={toggleSf}
          />
        )}
      </Paper>

      <Paper variant="outlined" sx={{ px: { xs: 2, sm: 3 } }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={1} sx={{ pt: 2 }}>
          <Typography variant="h2">Quality of service</Typography>
          <Typography variant="body2" color="text.secondary">
            Clients connected across inputs: <strong>{connectedClients}</strong>
          </Typography>
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 680 }}>
          When a limiter is on, the server picks the rule with the highest client threshold that the current client count has reached.
        </Typography>

        {qos.loading && !conf ? <Loading /> : qos.error ? <Box sx={{ py: 2 }}><ErrorState error={qos.error} onRetry={qos.reload} /></Box> : (
          <>
            <SettingRow
              title="Delivery rate limiting"
              help="Slow how often position reports are sent out to each client as more clients connect (writes)."
              checked={flags.delivery} busy={busy === 'delivery'} onChange={(v) => requestQos('delivery', v)}
            >
              <Box sx={{ mb: 1.5 }}><ActiveLine entry={active.data?.delivery} limitWord="Reporting limit" /></Box>
              <RateRulesEditor kind="delivery" label="delivery" rules={conf?.deliveryRateLimiter?.rateLimitRule} onSaved={() => { qos.reload(true); active.reload(true); }} />
            </SettingRow>
            <Divider />
            <SettingRow
              title="Read rate limiting"
              help="Slow how often the server accepts reports from each client as more clients connect (reads)."
              checked={flags.read} busy={busy === 'read'} onChange={(v) => requestQos('read', v)}
            >
              <Box sx={{ mb: 1.5 }}><ActiveLine entry={active.data?.read} limitWord="Reporting limit" /></Box>
              <RateRulesEditor kind="read" label="read" rules={conf?.readRateLimiter?.rateLimitRule} onSaved={() => { qos.reload(true); active.reload(true); }} />
            </SettingRow>
            <Divider />
            <SettingRow
              title="DoS protection"
              help={`Cap how many messages each IP address can send per ${dosInterval ? `${dosInterval}-second` : ''} interval as more clients connect. Rules are set in CoreConfig.`}
              checked={flags.dos} busy={busy === 'dos'} onChange={(v) => requestQos('dos', v)}
            >
              <Box sx={{ mb: 1.5 }}><ActiveLine entry={active.data?.dos} limitWord="Messages per interval" unit="" /></Box>
              {dosRules.length === 0 ? (
                <Typography variant="body2" color="text.secondary">No DoS rules are configured in CoreConfig.</Typography>
              ) : (
                <TableContainer sx={{ maxWidth: 560, border: 1, borderColor: 'divider', borderRadius: 1, mb: 2 }}>
                  <Table size="small" aria-label="DoS protection rules (read only)">
                    <TableHead>
                      <TableRow>
                        <TableCell>When connected clients reach</TableCell>
                        <TableCell>Messages per IP per {dosInterval ?? '?'} s</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dosRules.map((r, i) => (
                        // eslint-disable-next-line react/no-array-index-key
                        <TableRow key={i}>
                          <TableCell>{String(r?.clientThresholdCount ?? '')}</TableCell>
                          <TableCell>{r?.messageLimitPerInterval === -1 ? 'No limit' : String(r?.messageLimitPerInterval ?? '')}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </SettingRow>
          </>
        )}
      </Paper>
      <ConfirmDialog
        open={!!confirmOff}
        title={confirmOff ? `Turn off ${NAMES[confirmOff]}?` : ''}
        body={confirmOff === 'dos'
          ? 'Every IP address can then send messages without a per-interval cap. This applies to the whole server immediately.'
          : 'Clients are then no longer slowed as more connect. This applies to the whole server immediately.'}
        confirmLabel={confirmOff ? `Turn off ${NAMES[confirmOff]}` : 'Turn off'}
        onConfirm={async () => { const k = confirmOff; setConfirmOff(null); await toggleQos(k, false); }}
        onClose={() => setConfirmOff(null)}
      />
    </Stack>
  );
}
