import React from 'react';
import { Chip } from '@mui/material';
import { STATUS } from './certUtils';

export default function StatusChip({ status }) {
  const s = STATUS[status] || STATUS.active;
  return <Chip size="small" label={s.label} color={s.color} variant={s.color === 'default' ? 'outlined' : 'filled'} />;
}
