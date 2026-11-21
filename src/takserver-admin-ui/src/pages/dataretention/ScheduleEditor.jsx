import React, { useEffect, useRef, useState } from 'react';
import { Box, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { DAYS, MAX_CRON_LENGTH, buildPreset, describeCron, parsePreset, validateCron } from './cron';

const KINDS = [
  { value: 'hourly', label: 'Every hour' },
  { value: 'daily', label: 'Every day' },
  { value: 'weekly', label: 'Every week' },
  { value: 'monthly', label: 'Every month' },
  { value: 'never', label: 'Never (turned off)' },
  { value: 'custom', label: 'Advanced: cron expression' },
];

const pad = (n) => String(n).padStart(2, '0');

function fromValue(value) {
  const p = parsePreset(value);
  return { ...p, custom: p.kind === 'custom' ? String(value ?? '') : '' };
}

function emit(s) {
  return s.kind === 'custom' ? s.custom.trim() : buildPreset(s);
}

/** Plain-English summary of a cron expression, falling back to the raw text. */
export function ScheduleSummary({ value }) {
  const text = describeCron(value);
  if (text) return <Typography variant="body2">{text}</Typography>;
  return (
    <Typography variant="body2">
      Custom schedule: <Box component="code" sx={{ fontFamily: 'monospace', bgcolor: 'action.hover', px: 0.5, borderRadius: 0.5 }}>{String(value ?? '')}</Box>
    </Typography>
  );
}

/**
 * Edit a Spring cron schedule with presets plus an advanced field.
 * value: cron string ("-" = never). onChange(cron, error).
 */
export default function ScheduleEditor({ value, onChange, idPrefix, disabled }) {
  const [s, setS] = useState(() => fromValue(value));
  const last = useRef(value);

  // Re-sync when the parent replaces the value (load, discard), not on our own edits.
  useEffect(() => {
    if (value !== last.current) {
      last.current = value;
      setS(fromValue(value));
    }
  }, [value]);

  const update = (patch) => {
    const next = { ...s, ...patch };
    if (patch.kind === 'custom' && !s.custom) next.custom = String(value ?? '') === '-' ? '0 0 2 * * *' : String(value ?? '');
    setS(next);
    const cron = emit(next);
    last.current = cron;
    onChange(cron, validateCron(cron));
  };

  const error = s.kind === 'custom' ? validateCron(s.custom) : '';
  const time = `${pad(s.hour)}:${pad(s.minute)}`;
  const current = emit(s);

  return (
    <Stack spacing={1.5}>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ sm: 'flex-start' }} useFlexGap flexWrap="wrap">
        <TextField
          select label="Run" value={s.kind} disabled={disabled} sx={{ minWidth: 220 }}
          id={`${idPrefix}-kind`}
          onChange={(e) => update({ kind: e.target.value })}
        >
          {KINDS.map((k) => <MenuItem key={k.value} value={k.value}>{k.label}</MenuItem>)}
        </TextField>

        {s.kind === 'weekly' && (
          <TextField select label="On" value={s.dow} disabled={disabled} sx={{ minWidth: 160 }} onChange={(e) => update({ dow: Number(e.target.value) })}>
            {DAYS.map((d, i) => <MenuItem key={d} value={i}>{d}</MenuItem>)}
          </TextField>
        )}

        {s.kind === 'monthly' && (
          <TextField
            select label="On day" value={s.dom} disabled={disabled} sx={{ minWidth: 110 }}
            onChange={(e) => update({ dom: Number(e.target.value) })}
            helperText={s.dom > 28 ? 'Skipped in shorter months' : ' '}
          >
            {Array.from({ length: 31 }, (_, i) => <MenuItem key={i + 1} value={i + 1}>{i + 1}</MenuItem>)}
          </TextField>
        )}

        {['daily', 'weekly', 'monthly'].includes(s.kind) && (
          <TextField
            type="time" label="At" value={time} disabled={disabled} sx={{ width: 140 }}
            inputProps={{ step: 60 }}
            InputLabelProps={{ shrink: true }}
            onChange={(e) => {
              const m = /^(\d{2}):(\d{2})/.exec(e.target.value);
              if (m) update({ hour: Number(m[1]), minute: Number(m[2]) });
            }}
            helperText="Server time"
          />
        )}

        {s.kind === 'hourly' && (
          <TextField
            select label="Minutes past the hour" value={s.minute} disabled={disabled} sx={{ minWidth: 190 }}
            onChange={(e) => update({ minute: Number(e.target.value) })}
          >
            {Array.from({ length: 60 }, (_, i) => <MenuItem key={i} value={i}>{pad(i)}</MenuItem>)}
          </TextField>
        )}

        {s.kind === 'custom' && (
          <TextField
            label="Cron expression" value={s.custom} disabled={disabled}
            sx={{ minWidth: { sm: 280 }, flex: 1 }}
            inputProps={{ maxLength: MAX_CRON_LENGTH, spellCheck: false, style: { fontFamily: 'monospace' } }}
            error={!!error}
            helperText={error || 'Six fields: second minute hour day-of-month month day-of-week. Use - to turn it off.'}
            onChange={(e) => update({ custom: e.target.value })}
          />
        )}
      </Stack>
      {!error && <ScheduleSummary value={current} />}
    </Stack>
  );
}
