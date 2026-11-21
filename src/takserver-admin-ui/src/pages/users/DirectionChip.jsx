import React from 'react';
import { Chip, Tooltip } from '@mui/material';
import { DIRECTIONS, directionLabel } from './model';

export default function DirectionChip({ direction }) {
  const help = DIRECTIONS.find((d) => d.value === direction)?.help;
  return (
    <Tooltip title={help || ''}>
      <Chip
        size="small"
        variant={direction === 'both' ? 'filled' : 'outlined'}
        color={direction === 'both' ? 'primary' : 'default'}
        label={directionLabel(direction)}
      />
    </Tooltip>
  );
}
