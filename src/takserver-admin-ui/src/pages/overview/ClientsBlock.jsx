import React from 'react';
import { Box, Button, Stack, Typography } from '@mui/material';
import { BarList, SegmentBar } from './Bars';
import { countBy, protocolLabel, plural, FRESH_MS, STALE_MS } from './helpers';
import { navigate } from '../../router';

export const SUBS_LIMIT = 1000;

export function reportAge(s, now = Date.now()) {
  if (typeof s?.lastReportDiffMilliseconds === 'number') return s.lastReportDiffMilliseconds;
  if (typeof s?.lastReportMilliseconds === 'number' && s.lastReportMilliseconds > 0) return now - s.lastReportMilliseconds;
  return Infinity;
}

export function freshness(subs) {
  let fresh = 0; let stale = 0; let quiet = 0;
  subs.forEach((s) => {
    const age = reportAge(s);
    if (age < FRESH_MS) fresh += 1;
    else if (age < STALE_MS) stale += 1;
    else quiet += 1;
  });
  return { fresh, stale, quiet };
}

export default function ClientsBlock({ subs }) {
  const list = Array.isArray(subs) ? subs : [];
  const n = list.length;
  const capped = n >= SUBS_LIMIT;

  if (n === 0) {
    return (
      <Box>
        <Typography variant="h2" component="p">No clients connected</Typography>
        <Typography color="text.secondary" sx={{ mt: 0.5, maxWidth: 520 }}>
          Nothing is subscribed right now. If devices should be online, check that their inputs are listening and their certificates are valid.
        </Typography>
        <Button size="small" variant="outlined" sx={{ mt: 1.5 }} onClick={() => navigate('/inputs')}>Check inputs</Button>
      </Box>
    );
  }

  const byProtocol = countBy(list, (s) => protocolLabel(s.protocol));
  const byApp = countBy(list, (s) => (s.takClient ? String(s.takClient) : 'Not reported'));
  const f = freshness(list);

  return (
    <Box>
      <Typography variant="h2" component="p" sx={{ fontSize: '1.75rem' }}>
        {capped ? `${SUBS_LIMIT.toLocaleString()}+` : n.toLocaleString()}{' '}
        <Box component="span" sx={{ fontSize: '1.125rem', fontWeight: 500 }}>{n === 1 ? 'client connected' : 'clients connected'}</Box>
      </Typography>
      {capped && (
        <Typography variant="body2" color="text.secondary">
          The server returns at most {SUBS_LIMIT.toLocaleString()} clients per request, so the breakdown below covers the first {SUBS_LIMIT.toLocaleString()}.
        </Typography>
      )}

      <Box sx={{ mt: 2 }}>
        <Typography variant="subtitle2" component="h3" sx={{ mb: 0.75 }}>Last report</Typography>
        <SegmentBar
          ariaLabel={`${f.fresh} reported in the last 10 seconds, ${f.stale} between 10 seconds and 3 minutes ago, ${f.quiet} more than 3 minutes ago`}
          segments={[
            { label: 'Under 10 s', count: f.fresh, color: 'success.main' },
            { label: '10 s to 3 min', count: f.stale, color: 'warning.main' },
            { label: 'Over 3 min', count: f.quiet, color: 'error.main' },
          ]}
        />
      </Box>

      <Box sx={{ mt: 2.5, display: 'grid', gap: 2.5, gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' } }}>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle2" component="h3" sx={{ mb: 0.75 }}>By protocol</Typography>
          <BarList rows={byProtocol} total={n} ariaLabel="Clients by protocol" />
        </Box>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle2" component="h3" sx={{ mb: 0.75 }}>By app</Typography>
          <BarList rows={byApp} total={n} ariaLabel="Clients by app" />
        </Box>
      </Box>
      {f.quiet > 0 && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          {plural(f.quiet, 'client')} {f.quiet === 1 ? 'hasn’t' : 'haven’t'} sent anything in over 3 minutes. They may be idle or on a dropped link.
        </Typography>
      )}
    </Box>
  );
}
