import React, { useEffect, useMemo, useState } from 'react';
import { Box, Button, Divider, Typography } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import PageHeader from '../components/PageHeader';
import { api } from '../api/client';
import { usePolling } from '../api/useApi';
import Block from './overview/Block';
import StatusSummary from './overview/StatusSummary';
import ClientsBlock, { SUBS_LIMIT, freshness } from './overview/ClientsBlock';
import InputsBlock from './overview/InputsBlock';
import CertsBlock from './overview/CertsBlock';
import SecurityBlock from './overview/SecurityBlock';
import { expiringCerts, formatTime, parseSecure, splitInputs } from './overview/helpers';

const POLL_MS = 30 * 1000;
// The active-certificate list carries every certificate's PEM, so it's much
// heavier than the other calls; refresh it less often. "Refresh now" still reloads it.
const CERT_POLL_MS = 5 * 60 * 1000;

// Each loader hits one fixed endpoint; every block polls on its own so one
// failing endpoint only affects its own block.
const loadVersion = () => api.get('/Marti/api/version', { headers: { Accept: 'text/plain, */*' } });
const loadSubs = () => api.get('/Marti/api/subscriptions/all', { query: { limit: SUBS_LIMIT } });
const loadInputs = () => api.get('/Marti/api/inputs');
const loadCerts = () => api.get('/Marti/api/certadmin/cert/active/');
const loadSecure = () => api.get('/Marti/api/security/isSecure');

export default function Overview() {
  const version = usePolling(loadVersion, POLL_MS);
  const subs = usePolling(loadSubs, POLL_MS);
  const inputs = usePolling(loadInputs, POLL_MS);
  const certs = usePolling(loadCerts, CERT_POLL_MS);
  const secure = usePolling(loadSecure, POLL_MS);

  const states = [version, subs, inputs, certs, secure];
  const anyLoading = states.some((s) => s.loading);

  // "Updated" time: when the last round of requests finished (success or not).
  const [updatedAt, setUpdatedAt] = useState(null);
  useEffect(() => {
    if (!anyLoading) setUpdatedAt(new Date());
  }, [anyLoading, version.data, version.error, subs.data, subs.error, inputs.data, inputs.error,
    certs.data, certs.error, secure.data, secure.error]);

  // Silent when a block already has data; a normal reload (showing its loading state) when it failed.
  const refreshAll = () => states.forEach((s) => s.reload(s.data !== undefined));

  const subList = Array.isArray(subs.data) ? subs.data : null;
  const quietCount = useMemo(() => (subList ? freshness(subList).quiet : 0), [subList]);
  const expiring = useMemo(() => (Array.isArray(certs.data) ? expiringCerts(certs.data) : null), [certs.data]);
  const sec = secure.data !== undefined ? parseSecure(secure.data) : null;
  const inputsByPort = useMemo(() => {
    const map = new Map();
    splitInputs(inputs.data).inputs.forEach((m) => map.set(Number(m.input.port), String(m.input.name ?? '')));
    return map;
  }, [inputs.data]);

  const failedChecks = [];
  if (secure.data === undefined && secure.error) failedChecks.push('port encryption');
  if (certs.data === undefined && certs.error) failedChecks.push('certificate expiry');

  return (
    <Box sx={{ maxWidth: 1200 }}>
      <PageHeader
        title="Overview"
        description="How the server is doing right now. Refreshes every 30 seconds."
        actions={(
          <>
            {updatedAt && (
              <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }} aria-live="polite">
                Updated {formatTime(updatedAt)}
              </Typography>
            )}
            <Button size="small" variant="outlined" startIcon={<RefreshIcon />} onClick={refreshAll} disabled={anyLoading}>
              Refresh now
            </Button>
          </>
        )}
      />

      <StatusSummary
        version={version}
        subs={subs}
        clientCount={subList ? subList.length : null}
        quietCount={quietCount}
        sec={sec}
        expiringCount={expiring ? expiring.length : 0}
        urgentCertCount={expiring ? expiring.filter((x) => x.days <= 7).length : 0}
        failedChecks={failedChecks}
        onRetry={refreshAll}
      />

      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: 'minmax(0, 7fr) minmax(0, 5fr)' },
          columnGap: 5,
          rowGap: 4,
        }}
      >
        <Block title="Connected clients" to="/clients" linkLabel="View all clients" state={subs}>
          <ClientsBlock subs={subs.data} />
        </Block>

        <Box sx={{ display: 'grid', rowGap: 4, alignContent: 'start', minWidth: 0 }}>
          <Block title="Certificates expiring soon" to="/certs" linkLabel="Manage certificates" state={certs}>
            {expiring && <CertsBlock expiring={expiring} total={certs.data.length} />}
          </Block>
          <Divider />
          <Block title="Port encryption" to="/inputs" linkLabel="Review inputs" state={secure}>
            {sec && <SecurityBlock sec={sec} inputsByPort={inputsByPort} />}
          </Block>
        </Box>

        <Block
          title="Inputs" to="/inputs" linkLabel="Manage inputs" state={inputs}
          sx={{ gridColumn: { md: '1 / -1' } }}
        >
          <InputsBlock metrics={inputs.data} insecurePorts={sec ? sec.ports : null} />
        </Block>
      </Box>
    </Box>
  );
}
