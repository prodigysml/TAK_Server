import React from 'react';
import { Alert, Box, Divider, Paper, Typography } from '@mui/material';
import PageHeader from '../components/PageHeader';
import { Loading } from '../components/States';
import { api } from '../api/client';
import { useApi } from '../api/useApi';
import RetentionPolicies from './dataretention/RetentionPolicies';
import RetentionSchedule from './dataretention/RetentionSchedule';
import MissionArchive from './dataretention/MissionArchive';

function Section({ id, title, description, children }) {
  return (
    <Box component="section" aria-labelledby={id} sx={{ mb: 5 }}>
      <Typography variant="h2" id={id} sx={{ mb: 0.5 }}>{title}</Typography>
      {description && <Typography color="text.secondary" sx={{ mb: 2, maxWidth: 760 }}>{description}</Typography>}
      {children}
    </Box>
  );
}

// The retention endpoints answer 500 when TAK's separate retention service
// (takserver-retention) isn't running. Probe once and say so plainly.
async function probeService() {
  try {
    await api.get('/Marti/api/retention/policy');
    return 'running';
  } catch (e) {
    return e && e.status === 500 ? 'off' : 'unknown';
  }
}

export default function DataRetention() {
  const probe = useApi(probeService, []);
  const header = (
    <PageHeader
      title="Data retention"
      description="Choose how long the server keeps each kind of data, when old data is deleted, and when inactive missions are archived."
    />
  );
  if (probe.loading) return <Box>{header}<Loading /></Box>;
  if (probe.data === 'off') {
    return (
      <Box>
        {header}
        <Alert severity="info" sx={{ maxWidth: 760 }}>
          Data retention isn&apos;t running on this server, so nothing is being deleted or archived: all data is kept.
          The server&apos;s retention service has to be started before policies can be set here.
        </Alert>
      </Box>
    );
  }
  return (
    <Box>
      {header}

      <Section
        id="retention-policies"
        title="Retention policies"
        description="Each time the retention schedule runs, data older than its limit is deleted."
      >
        <RetentionPolicies />
      </Section>

      <Section
        id="retention-schedule"
        title="Retention schedule"
        description="When the server checks for and deletes data past its retention limit."
      >
        <Paper variant="outlined" sx={{ p: { xs: 2, md: 2.5 } }}>
          <RetentionSchedule />
        </Paper>
      </Section>

      <Divider sx={{ mb: 4 }} />

      <Section
        id="mission-archive"
        title="Mission archiving"
        description="Move inactive missions out of the database into archive files, and bring them back when needed."
      >
        <MissionArchive />
      </Section>
    </Box>
  );
}
