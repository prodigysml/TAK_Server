import React from 'react';
import { Box, Chip, Link, Stack, Typography } from '@mui/material';
import { CERT_WINDOW_DAYS, expiresPhrase, formatDate, plural } from './helpers';
import { navigate } from '../../router';

const SHOW = 6;

// expiring: output of expiringCerts(), soonest first. total: active certificate count.
export default function CertsBlock({ expiring, total }) {
  if (expiring.length === 0) {
    return (
      <Typography color="text.secondary">
        None of the {plural(total, 'active certificate')} expire in the next {CERT_WINDOW_DAYS} days.
      </Typography>
    );
  }
  const shown = expiring.slice(0, SHOW);
  const more = expiring.length - shown.length;
  return (
    <Box>
      <Typography color="text.secondary" sx={{ mb: 1 }}>
        {plural(expiring.length, 'certificate')} of {total.toLocaleString()} active {expiring.length === 1 ? 'expires' : 'expire'} within {CERT_WINDOW_DAYS} days.
        Users on {expiring.length === 1 ? 'it' : 'them'} lose access when {expiring.length === 1 ? 'it lapses' : 'they lapse'}.
      </Typography>
      <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0 }}>
        {shown.map(({ cert, expires, days, name }) => {
          const urgent = days <= 7;
          return (
            <Stack
              component="li" key={cert.id ?? cert.hash ?? `${name}-${expires.getTime()}`}
              direction="row" alignItems="center" justifyContent="space-between" spacing={1.5}
              sx={{ py: 0.75, borderTop: 1, borderColor: 'divider', '&:first-of-type': { borderTop: 0 } }}
            >
              <Box sx={{ minWidth: 0 }}>
                <Typography variant="body2" noWrap title={String(cert.subjectDn ?? '')} sx={{ fontWeight: 500 }}>{name}</Typography>
                <Typography variant="body2" color="text.secondary">{formatDate(expires)}</Typography>
              </Box>
              <Chip
                size="small" variant="outlined" color={urgent ? 'error' : 'warning'}
                label={days < 0 ? 'Expired' : expiresPhrase(days)} sx={{ flexShrink: 0 }}
              />
            </Stack>
          );
        })}
      </Box>
      {more > 0 && (
        <Link component="button" type="button" variant="body2" underline="hover" sx={{ mt: 1 }} onClick={() => navigate('/certs')}>
          and {more.toLocaleString()} more
        </Link>
      )}
    </Box>
  );
}
