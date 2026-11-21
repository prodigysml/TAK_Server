import React from 'react';
import { Alert, Box, Button, LinearProgress, Paper, Typography } from '@mui/material';

export function Loading() {
  return <LinearProgress sx={{ my: 2 }} aria-label="Loading" />;
}

export function ErrorState({ error, onRetry }) {
  return (
    <Alert severity="error" sx={{ my: 2 }} action={onRetry && <Button color="inherit" size="small" onClick={() => onRetry()}>Try again</Button>}>
      {error?.message || 'Something went wrong loading this page.'}
    </Alert>
  );
}

export function EmptyState({ title, body, action }) {
  return (
    <Paper variant="outlined" sx={{ p: 4, textAlign: 'center' }}>
      <Typography variant="h3" component="p">{title}</Typography>
      {body && <Typography color="text.secondary" sx={{ mt: 1 }}>{body}</Typography>}
      {action && <Box sx={{ mt: 2 }}>{action}</Box>}
    </Paper>
  );
}
