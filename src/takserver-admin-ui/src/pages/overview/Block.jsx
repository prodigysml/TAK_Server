import React from 'react';
import { Alert, Box, Button, Link, Skeleton, Stack, Typography } from '@mui/material';
import { navigate } from '../../router';

// One section of the overview. Owns its own loading and error state so a failing
// endpoint never blanks the rest of the page.
//  - first load: skeleton lines
//  - failed with nothing to show: small error with "Try again"
//  - failed on a background refresh: keep the last data, note that it's stale
export default function Block({ title, to, linkLabel, state, children, sx, failMessage }) {
  const { data, error, loading, reload } = state;
  const headingId = `ov-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  const hasData = data !== undefined;
  return (
    <Box component="section" aria-labelledby={headingId} sx={{ minWidth: 0, ...sx }}>
      <Stack direction="row" alignItems="baseline" justifyContent="space-between" spacing={2} sx={{ mb: 1.25 }}>
        <Typography id={headingId} variant="h3" component="h2">{title}</Typography>
        {to && (
          <Link
            component="button" type="button" underline="hover" variant="body2"
            onClick={() => navigate(to)} sx={{ flexShrink: 0, fontWeight: 500 }}
          >
            {linkLabel}
          </Link>
        )}
      </Stack>
      {!hasData && loading && (
        <Box aria-busy="true" aria-label={`Loading ${title.toLowerCase()}`}>
          <Skeleton width="60%" height={28} />
          <Skeleton width="90%" />
          <Skeleton width="75%" />
        </Box>
      )}
      {!hasData && !loading && error && (
        <Alert
          severity="error" variant="outlined" sx={{ py: 0.25 }}
          action={<Button color="inherit" size="small" onClick={() => reload()}>Try again</Button>}
        >
          {failMessage || `Couldn’t load ${title.toLowerCase()}.`} {error.message}
        </Alert>
      )}
      {hasData && children}
      {hasData && error && (
        <Typography variant="body2" color="warning.main" sx={{ mt: 1 }}>
          Couldn’t refresh: {error.message}{' '}
          <Link component="button" type="button" variant="body2" onClick={() => reload(true)}>Try again</Link>
        </Typography>
      )}
    </Box>
  );
}
