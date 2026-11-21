import React from 'react';
import { Box, Chip, FormControlLabel, FormHelperText, Stack, Switch, Typography } from '@mui/material';

// Small yes/no chip for boolean flags in tables. Text carries the meaning, not color.
export function FlagChip({ value, on = 'Yes', off = 'No' }) {
  if (value === null || value === undefined) return <Typography variant="body2" color="text.secondary">Not set</Typography>;
  return value
    ? <Chip size="small" label={on} color="success" variant="outlined" />
    : <Chip size="small" label={off} variant="outlined" />;
}

// Connection status for an input row.
export function ClientsChip({ count }) {
  const n = Number(count) || 0;
  return n > 0
    ? <Chip size="small" color="success" label={`${n} connected`} />
    : <Chip size="small" variant="outlined" label="No clients" />;
}

// Labelled switch with a one-line explanation underneath.
export function SwitchField({ label, help, checked, onChange, disabled, error }) {
  return (
    <Box>
      <FormControlLabel
        control={<Switch checked={!!checked} onChange={(e) => onChange(e.target.checked)} disabled={disabled} />}
        label={label}
      />
      {help && <FormHelperText sx={{ mt: -0.5, ml: 0 }}>{help}</FormHelperText>}
      {error && <FormHelperText error sx={{ ml: 0 }}>{error}</FormHelperText>}
    </Box>
  );
}

// Read-only label/value pair used at the top of edit dialogs.
export function Facts({ items }) {
  return (
    <Stack direction="row" flexWrap="wrap" useFlexGap spacing={3} sx={{ mb: 2 }}>
      {items.filter(Boolean).map(([k, v]) => (
        <Box key={k}>
          <Typography variant="caption" color="text.secondary" component="div">{k}</Typography>
          <Typography variant="body2">{v === '' || v === null || v === undefined ? 'None' : String(v)}</Typography>
        </Box>
      ))}
    </Stack>
  );
}
