import React, { useMemo, useState } from 'react';
import { Box, Tab, Tabs } from '@mui/material';
import PageHeader from '../components/PageHeader';
import { ErrorState, Loading } from '../components/States';
import { api } from '../api/client';
import { useApi, usePolling } from '../api/useApi';
import InputsTab from './inputs/InputsTab';
import DataFeedsTab from './inputs/DataFeedsTab';
import MessagingTab from './inputs/MessagingTab';
import { POLL_MS, num, splitInputs } from './inputs/model';

const TABS = [
  { key: 'inputs', label: 'Inputs' },
  { key: 'feeds', label: 'Data feeds' },
  { key: 'messaging', label: 'Messaging settings' },
];

function readTab() {
  try {
    const t = window.sessionStorage.getItem('takadmin.inputs.tab');
    return TABS.some((x) => x.key === t) ? t : 'inputs';
  } catch {
    return 'inputs';
  }
}

export default function Inputs() {
  const [tab, setTab] = useState(readTab);
  const changeTab = (_, v) => {
    setTab(v);
    try { window.sessionStorage.setItem('takadmin.inputs.tab', v); } catch { /* storage unavailable */ }
  };

  // GET /Marti/api/inputs returns InputMetric[] ({ input, readsReceived, messagesReceived, numClients, bytesRecieved }).
  // Data feeds come back in the same list with input.type set.
  const list = usePolling(() => api.get('/Marti/api/inputs', { query: { excludeDataFeeds: false } }), POLL_MS);
  // Used only to show the TLS version of core-version-1 TLS inputs; failures are non-fatal.
  const sec = useApi(() => api.get('/Marti/api/security/config').catch(() => null), []);

  const all = useMemo(() => (Array.isArray(list.data) ? list.data.filter((m) => m && m.input) : []), [list.data]);
  const { inputs, feeds } = useMemo(() => splitInputs(all), [all]);
  const connected = useMemo(() => all.reduce((n, m) => n + num(m.numClients), 0), [all]);

  const firstLoad = list.loading && list.data === undefined;

  return (
    <Box sx={{ minWidth: 0 }}>
      <PageHeader
        title="Inputs and data feeds"
        description="The ports TAK clients connect on, the feeds that bring data in, and server-wide messaging limits."
      />

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tab} onChange={changeTab} variant="scrollable" allowScrollButtonsMobile aria-label="Inputs page sections">
          {TABS.map((t) => (
            <Tab
              key={t.key} value={t.key} id={`inputs-tab-${t.key}`} aria-controls={`inputs-panel-${t.key}`}
              label={t.key === 'inputs' && list.data ? `Inputs (${inputs.length})` : t.key === 'feeds' && list.data ? `Data feeds (${feeds.length})` : t.label}
            />
          ))}
        </Tabs>
      </Box>

      <Box role="tabpanel" id={`inputs-panel-${tab}`} aria-labelledby={`inputs-tab-${tab}`} sx={{ minWidth: 0 }}>
        {tab !== 'messaging' && firstLoad && <Loading />}
        {tab !== 'messaging' && list.error && (
          <ErrorState
            error={{ message: `Couldn’t load inputs: ${list.error.message} The TAK Server API or messaging process may be down. This page retries every few seconds.` }}
            onRetry={() => list.reload()}
          />
        )}
        {tab === 'inputs' && list.data !== undefined && (
          <InputsTab inputs={inputs} all={all} secConfig={sec.data} reload={list.reload} />
        )}
        {tab === 'feeds' && list.data !== undefined && (
          <DataFeedsTab feeds={feeds} all={all} secConfig={sec.data} reload={list.reload} />
        )}
        {tab === 'messaging' && <MessagingTab connectedClients={connected} />}
      </Box>
    </Box>
  );
}
