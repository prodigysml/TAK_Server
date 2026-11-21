import React, { useEffect, useMemo, useState } from 'react';
import {
  Box, Button, Chip, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TextField, Typography,
} from '@mui/material';
import { api } from '../../api/client';
import { useApi } from '../../api/useApi';
import { useNotify } from '../../components/Notify';
import ConfirmDialog from '../../components/ConfirmDialog';
import { ErrorState, Loading } from '../../components/States';
import { DATA_TYPES, UNITS, describeTtl, isShorter, labelFor, toRow, toSeconds, validateRow } from './ttl';

const POLICY = '/Marti/api/retention/policy';

function rowsFrom(map) {
  const keys = [...DATA_TYPES.map((t) => t.key), ...Object.keys(map || {}).filter((k) => !DATA_TYPES.some((t) => t.key === k))];
  const out = {};
  keys.forEach((k) => { out[k] = toRow(map ? map[k] : null); });
  return out;
}

const cap = (t) => t.charAt(0).toUpperCase() + t.slice(1);
const same = (a, b) => toSeconds(a) === toSeconds(b);

export default function RetentionPolicies() {
  const notify = useNotify();
  const { data, error, loading, reload } = useApi(() => api.get(POLICY));
  const server = useMemo(() => (data && typeof data === 'object' ? data : {}), [data]);
  const original = useMemo(() => rowsFrom(server), [server]);
  const [rows, setRows] = useState(original);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(null);

  useEffect(() => { setRows(original); }, [original]);

  const keys = Object.keys(rows);
  const errors = Object.fromEntries(keys.map((k) => [k, validateRow(rows[k])]));
  const changed = keys.filter((k) => original[k] && !same(rows[k], original[k]) && !errors[k]);
  const dirty = keys.some((k) => original[k] && !same(rows[k], original[k]));
  const hasErrors = keys.some((k) => errors[k]);

  const set = (k, patch) => setRows((r) => ({ ...r, [k]: { ...r[k], ...patch } }));

  const save = async () => {
    const body = Object.fromEntries(changed.map((k) => [k, toSeconds(rows[k])]));
    setBusy(true);
    try {
      await api.put(POLICY, body);
      notify(`Saved retention for ${changed.map(labelFor).join(', ')}`);
      setConfirm(null);
      reload(true);
    } catch (err) {
      notify(err);
    } finally {
      setBusy(false);
    }
  };

  const requestSave = () => {
    const shorter = changed.filter((k) => isShorter(toSeconds(original[k]), toSeconds(rows[k])));
    if (shorter.length) setConfirm(shorter);
    else save();
  };

  if (loading && data === undefined) return <Loading />;
  if (error && data === undefined) return <ErrorState error={error} onRetry={reload} />;

  return (
    <Box>
      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: 'auto' }}>
        <Table size="small" aria-label="Retention by data type">
          <TableHead>
            <TableRow>
              <TableCell>Data</TableCell>
              <TableCell sx={{ minWidth: 170 }}>Keep</TableCell>
              <TableCell sx={{ minWidth: 300 }}>For</TableCell>
              <TableCell>Currently</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {keys.map((k) => {
              const row = rows[k];
              const type = DATA_TYPES.find((t) => t.key === k);
              const isChanged = original[k] && !same(row, original[k]);
              return (
                <TableRow key={k} hover>
                  <TableCell>
                    <Typography variant="body2" fontWeight={500}>{type?.label || k}</Typography>
                    {type && <Typography variant="caption" color="text.secondary">{type.description}</Typography>}
                  </TableCell>
                  <TableCell>
                    <TextField
                      select size="small" fullWidth value={row.forever ? 'forever' : 'limited'}
                      inputProps={{ 'aria-label': `How long to keep ${type?.label || k}` }}
                      onChange={(e) => {
                        const forever = e.target.value === 'forever';
                        set(k, forever ? { forever } : { forever, amount: row.amount || '30', unit: row.amount ? row.unit : 'days' });
                      }}
                    >
                      <MenuItem value="forever">Keep forever</MenuItem>
                      <MenuItem value="limited">Delete after</MenuItem>
                    </TextField>
                  </TableCell>
                  <TableCell>
                    {row.forever ? (
                      <Typography variant="body2" color="text.secondary">Never deleted by retention</Typography>
                    ) : (
                      <Stack direction="row" spacing={1} alignItems="flex-start">
                        <TextField
                          type="number" size="small" value={row.amount} sx={{ width: 110 }}
                          inputProps={{ min: 0, step: 'any', 'aria-label': `Amount for ${type?.label || k}` }}
                          error={!!errors[k]} helperText={errors[k] || ' '}
                          onChange={(e) => set(k, { amount: e.target.value })}
                        />
                        <TextField
                          select size="small" value={row.unit} sx={{ width: 120 }}
                          inputProps={{ 'aria-label': `Unit for ${type?.label || k}` }}
                          onChange={(e) => set(k, { unit: e.target.value })}
                        >
                          {UNITS.map((u) => <MenuItem key={u.value} value={u.value}>{u.label}</MenuItem>)}
                        </TextField>
                      </Stack>
                    )}
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography variant="body2" sx={{ whiteSpace: 'nowrap' }}>
                        {cap(describeTtl(server[k]))}
                      </Typography>
                      {isChanged && <Chip size="small" color="warning" variant="outlined" label="Unsaved" />}
                    </Stack>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1 }}>
        A month counts as 30.42 days and a year as 365. Data older than the limit is deleted the next time the retention schedule runs.
      </Typography>
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button variant="contained" disabled={!changed.length || hasErrors || busy} onClick={requestSave}>
          {changed.length > 1 ? `Save ${changed.length} retention policies` : 'Save retention policy'}
        </Button>
        <Button disabled={!dirty || busy} onClick={() => setRows(original)}>Discard changes</Button>
      </Stack>

      <ConfirmDialog
        open={!!confirm}
        title="Shorten retention?"
        busy={busy}
        confirmLabel={changed.length > 1 ? `Save ${changed.length} policies` : 'Save policy'}
        onClose={() => setConfirm(null)}
        onConfirm={save}
        body={confirm && (
          <>
            The next retention run will permanently delete:
            <Box component="ul" sx={{ my: 1, pl: 3 }}>
              {confirm.map((k) => (
                <li key={k}>{labelFor(k)} older than {describeTtl(toSeconds(rows[k]))}</li>
              ))}
            </Box>
            This can’t be undone.
          </>
        )}
      />
    </Box>
  );
}
