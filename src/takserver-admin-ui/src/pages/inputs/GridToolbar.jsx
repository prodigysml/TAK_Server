import React from 'react';
import { GridToolbarColumnsButton, GridToolbarContainer, GridToolbarQuickFilter } from '@mui/x-data-grid';
import { Box } from '@mui/material';

// Search box plus the column chooser, so admins can show hidden metric columns.
export default function GridToolbar({ children }) {
  return (
    <GridToolbarContainer sx={{ px: 1, py: 1, gap: 1, flexWrap: 'wrap' }}>
      <GridToolbarQuickFilter debounceMs={200} placeholder="Search" sx={{ minWidth: 200 }} />
      {children}
      <Box sx={{ flex: 1 }} />
      <GridToolbarColumnsButton />
    </GridToolbarContainer>
  );
}
