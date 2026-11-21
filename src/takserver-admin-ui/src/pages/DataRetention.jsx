import React from 'react';
import { Box, Divider, Paper, Typography } from '@mui/material';
import PageHeader from '../components/PageHeader';
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

export default function DataRetention() {
  return (
    <Box>
      <PageHeader
        title="Data retention"
        description="Choose how long the server keeps each kind of data, when old data is deleted, and when inactive missions are archived."
      />

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
