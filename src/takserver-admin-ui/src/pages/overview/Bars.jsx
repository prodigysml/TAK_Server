import React from 'react';
import { Box, Stack, Typography } from '@mui/material';

// Small inline bars drawn with plain boxes; no chart library. Every bar is
// paired with its number as text, so nothing relies on color or length alone.

// Labelled rows: label, count, and a proportional bar.
export function BarList({ rows, total, max = 5, otherLabel = 'Other', ariaLabel }) {
  const shown = rows.slice(0, max);
  const rest = rows.slice(max).reduce((s, r) => s + r.count, 0);
  const all = rest > 0 ? [...shown, { label: otherLabel, count: rest }] : shown;
  const denom = total || all.reduce((s, r) => s + r.count, 0) || 1;
  return (
    <Box component="ul" aria-label={ariaLabel} sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 0.75 }}>
      {all.map((r) => (
        <Box
          component="li" key={r.label}
          sx={{ display: 'grid', gridTemplateColumns: 'minmax(72px, 9rem) 3.5rem 1fr', alignItems: 'center', columnGap: 1.5 }}
        >
          <Typography variant="body2" noWrap title={r.label}>{r.label}</Typography>
          <Typography variant="body2" sx={{ textAlign: 'right', fontWeight: 500 }}>{r.count.toLocaleString()}</Typography>
          <Box sx={{ height: 6, borderRadius: 3, bgcolor: 'divider', overflow: 'hidden' }} aria-hidden="true">
            <Box sx={{ height: '100%', width: `${Math.max(2, (r.count / denom) * 100)}%`, bgcolor: 'primary.main', borderRadius: 3 }} />
          </Box>
        </Box>
      ))}
    </Box>
  );
}

// One bar split into colored segments, with a text legend underneath.
// segments: [{ label, count, color }] where color is a theme palette path.
export function SegmentBar({ segments, ariaLabel }) {
  const total = segments.reduce((s, x) => s + x.count, 0);
  return (
    <Box>
      <Box
        role="img" aria-label={ariaLabel}
        sx={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', bgcolor: 'divider', gap: '2px' }}
      >
        {total > 0 && segments.filter((s) => s.count > 0).map((s) => (
          <Box key={s.label} sx={{ flexGrow: s.count, flexBasis: 0, minWidth: 4, bgcolor: s.color }} />
        ))}
      </Box>
      <Stack direction="row" flexWrap="wrap" useFlexGap columnGap={2} rowGap={0.5} sx={{ mt: 0.75 }}>
        {segments.map((s) => (
          <Stack key={s.label} direction="row" spacing={0.75} alignItems="center">
            <Box aria-hidden="true" sx={{ width: 8, height: 8, borderRadius: '2px', bgcolor: s.color }} />
            <Typography variant="body2" color="text.secondary">
              {s.label} <Box component="span" sx={{ color: 'text.primary', fontWeight: 500 }}>{s.count.toLocaleString()}</Box>
            </Typography>
          </Stack>
        ))}
      </Stack>
    </Box>
  );
}
