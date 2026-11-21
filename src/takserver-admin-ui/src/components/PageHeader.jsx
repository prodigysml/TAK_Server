import React from 'react';
import { Box, Stack, Typography } from '@mui/material';

// Page title, one line of plain description, and the page's primary actions.
export default function PageHeader({ title, description, actions }) {
  return (
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ sm: 'flex-end' }} justifyContent="space-between" sx={{ mb: 3 }}>
      <Box sx={{ maxWidth: 720 }}>
        <Typography variant="h1" component="h1">{title}</Typography>
        {description && <Typography color="text.secondary" sx={{ mt: 0.5 }}>{description}</Typography>}
      </Box>
      {actions && <Stack direction="row" spacing={1} flexShrink={0} flexWrap="wrap" useFlexGap>{actions}</Stack>}
    </Stack>
  );
}
