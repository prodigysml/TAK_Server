import React from 'react';
import { Box, Button, Chip, Link, Paper, Skeleton, Stack, Typography } from '@mui/material';
import { navigate } from '../../router';
import { plural, CERT_WINDOW_DAYS } from './helpers';
import { SUBS_LIMIT } from './ClientsBlock';

// The first thing an admin sees: is the server answering, are clients on it,
// and the short list of things that need a decision.
export default function StatusSummary({ version, subs, clientCount, quietCount, sec, expiringCount, urgentCertCount, failedChecks = [], onRetry }) {
  const versionDown = version.data === undefined && version.error;
  const subsDown = subs.data === undefined && subs.error;
  const firstLoad = version.data === undefined && subs.data === undefined && (version.loading || subs.loading);
  const unreachable = !firstLoad && versionDown && subsDown;

  const issues = [];
  if (sec && !sec.secure) {
    issues.push({
      key: 'sec', to: '/inputs', link: 'Review inputs', color: 'warning',
      text: sec.ports.length
        ? `${plural(sec.ports.length, 'port')} ${sec.ports.length === 1 ? 'accepts' : 'accept'} unencrypted connections (${sec.ports.join(', ')}).`
        : 'Some ports accept unencrypted connections.',
    });
  }
  if (expiringCount > 0) {
    issues.push({
      key: 'certs', to: '/certs', link: 'Review certificates', color: urgentCertCount > 0 ? 'error' : 'warning',
      text: `${plural(expiringCount, 'client certificate')} ${expiringCount === 1 ? 'expires' : 'expire'} within ${CERT_WINDOW_DAYS} days${urgentCertCount > 0 ? `, ${urgentCertCount.toLocaleString()} within a week` : ''}.`,
    });
  }
  if (quietCount > 0) {
    issues.push({
      key: 'quiet', to: '/clients', link: 'See clients', color: 'warning',
      text: `${plural(quietCount, 'connected client')} ${quietCount === 1 ? 'hasn’t' : 'haven’t'} reported in over 3 minutes.`,
    });
  }

  let tone = 'success'; let chip = 'Healthy'; let headline;
  const countText = clientCount === null ? null
    : clientCount >= SUBS_LIMIT ? `${SUBS_LIMIT.toLocaleString()}+ clients` : plural(clientCount, 'client');
  if (unreachable) {
    tone = 'error'; chip = 'Not responding';
    headline = 'The server isn’t answering API requests.';
  } else if (countText === null) {
    headline = 'Server is up. The connected client count isn’t available right now.';
  } else if (clientCount === 0) {
    headline = 'Server is up, but no clients are connected.';
  } else {
    headline = `Server is up with ${countText} connected.`;
  }
  if (!unreachable && issues.length > 0) { tone = 'warning'; chip = 'Needs attention'; }

  const versionText = typeof version.data === 'string' ? version.data.trim().slice(0, 120) : '';

  return (
    <Paper
      variant="outlined" component="section" aria-label="Server status"
      sx={{ p: { xs: 2, sm: 2.5 }, borderLeft: 4, borderLeftColor: `${tone}.main`, mb: 4 }}
    >
      {firstLoad ? (
        <Box aria-busy="true" aria-label="Loading server status">
          <Skeleton width="55%" height={36} />
          <Skeleton width="30%" />
        </Box>
      ) : (
        <>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={{ xs: 1, sm: 2 }} alignItems={{ sm: 'center' }} justifyContent="space-between">
            <Typography variant="h2" component="p" sx={{ fontSize: { xs: '1.125rem', sm: '1.375rem' } }}>{headline}</Typography>
            <Chip color={tone} label={chip} size="small" sx={{ alignSelf: { xs: 'flex-start', sm: 'center' }, flexShrink: 0 }} />
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {versionText || (version.error ? 'Version unavailable.' : '')}
            {unreachable && ' Check that the TAK Server API process is running and that your session hasn’t expired.'}
          </Typography>
          {unreachable && (
            <Button size="small" variant="outlined" sx={{ mt: 1.5 }} onClick={onRetry}>Try again</Button>
          )}

          {!unreachable && (
            issues.length > 0 ? (
              <Box component="ul" sx={{ listStyle: 'none', m: 0, mt: 2, p: 0, display: 'grid', gap: 1 }}>
                {issues.map((i) => (
                  <Stack component="li" key={i.key} direction="row" spacing={1.25} alignItems="baseline" flexWrap="wrap" useFlexGap>
                    <Box aria-hidden="true" sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: `${i.color}.main`, flexShrink: 0, transform: 'translateY(-1px)' }} />
                    <Typography component="span">{i.text}</Typography>
                    <Link component="button" type="button" underline="hover" onClick={() => navigate(i.to)} sx={{ fontWeight: 500 }}>{i.link}</Link>
                  </Stack>
                ))}
              </Box>
            ) : (
              <Typography sx={{ mt: 1.5 }} color="text.secondary">
                {failedChecks.length === 0
                  ? 'Nothing needs your attention.'
                  : `Nothing flagged so far, but ${failedChecks.join(' and ')} couldn’t be checked. See below.`}
              </Typography>
            )
          )}
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2, opacity: 0.85 }}>
            Uptime, memory and CPU aren’t shown: this server build no longer exposes the metrics endpoints the classic dashboard read them from.
          </Typography>
        </>
      )}
    </Paper>
  );
}
