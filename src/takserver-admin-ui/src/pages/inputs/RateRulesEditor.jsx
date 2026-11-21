import React, { useRef, useEffect, useState } from 'react';
import {
  Alert, Box, Button, Chip, IconButton, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TextField, Tooltip,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/DeleteOutline';
import AddIcon from '@mui/icons-material/Add';
import { api } from '../../api/client';
import { useNotify } from '../../components/Notify';
import { MAX_RATE_RULES, validateRateRules, validateRuleValue } from './model';

const toEdit = (rules) => (rules || []).map((r) => ({
  clientThresholdCount: String(r?.clientThresholdCount ?? 0),
  reportingRateLimitSeconds: String(r?.reportingRateLimitSeconds ?? 0),
}));

/**
 * Editable client-count -> reporting-rate table for the delivery or read limiter.
 * Saves with PUT /Marti/api/qos/{delivery|read}/set (a JSON array of rules).
 */
export default function RateRulesEditor({ kind, label, rules, onSaved }) {
  const notify = useNotify();
  const [rows, setRows] = useState(toEdit(rules));
  const [busy, setBusy] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  // Take server values when they arrive, unless the admin has edited the rows
  // since the last server copy (compared against that copy, not the new one).
  const serverKey = JSON.stringify(toEdit(rules));
  const lastServerKey = useRef(serverKey);
  const dirty = JSON.stringify(rows) !== serverKey;
  useEffect(() => {
    if (JSON.stringify(rows) === lastServerKey.current) setRows(toEdit(rules));
    lastServerKey.current = serverKey;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverKey]);

  const listError = validateRateRules(rows);
  const cellErrors = rows.map((r) => ({
    clientThresholdCount: validateRuleValue(r.clientThresholdCount),
    reportingRateLimitSeconds: validateRuleValue(r.reportingRateLimitSeconds),
  }));
  const hasErrors = !!listError || cellErrors.some((c) => c.clientThresholdCount || c.reportingRateLimitSeconds);

  const setCell = (i, k, v) => setRows((rs) => rs.map((r, j) => (j === i ? { ...r, [k]: v.replace(/[^0-9]/g, '') } : r)));

  const save = async () => {
    setSubmitted(true);
    if (hasErrors) return;
    setBusy(true);
    try {
      const body = rows.map((r) => ({
        clientThresholdCount: Number(r.clientThresholdCount),
        reportingRateLimitSeconds: Number(r.reportingRateLimitSeconds),
      }));
      await api.put(`/Marti/api/qos/${kind}/set`, body);
      notify(`Saved ${body.length} ${label} rate limit ${body.length === 1 ? 'rule' : 'rules'}`);
      setSubmitted(false);
      onSaved();
    } catch (err) {
      notify(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box>
      <TableContainer sx={{ maxWidth: 560, border: 1, borderColor: 'divider', borderRadius: 1 }}>
        <Table size="small" aria-label={`${label} rate limit rules`}>
          <TableHead>
            <TableRow>
              <TableCell>When connected clients reach</TableCell>
              <TableCell>Limit each client to one report every (seconds)</TableCell>
              <TableCell width={48} aria-label="Remove" />
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((r, i) => (
              // eslint-disable-next-line react/no-array-index-key
              <TableRow key={i}>
                {['clientThresholdCount', 'reportingRateLimitSeconds'].map((k) => {
                  const err = (submitted || r[k] === '') && cellErrors[i][k];
                  return (
                    <TableCell key={k}>
                      <TextField
                        value={r[k]} onChange={(e) => setCell(i, k, e.target.value)}
                        inputProps={{ inputMode: 'numeric', maxLength: 10, 'aria-label': `${k === 'clientThresholdCount' ? 'Client threshold' : 'Seconds'}, rule ${i + 1}` }}
                        error={!!err} helperText={err || ' '} sx={{ width: 140 }}
                      />
                    </TableCell>
                  );
                })}
                <TableCell>
                  <Tooltip title="Remove rule">
                    <span>
                      <IconButton
                        size="small" aria-label={`Remove rule ${i + 1}`} disabled={busy || rows.length <= 1}
                        onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      {(submitted || rows.length === 0) && listError && <Alert severity="error" sx={{ mt: 1, maxWidth: 560 }}>{listError}</Alert>}
      <Stack direction="row" spacing={1} sx={{ mt: 1.5 }} alignItems="center" flexWrap="wrap" useFlexGap>
        <Button
          size="small" startIcon={<AddIcon />} disabled={busy || rows.length >= MAX_RATE_RULES}
          onClick={() => setRows((rs) => [...rs, { clientThresholdCount: '0', reportingRateLimitSeconds: '0' }])}
        >
          Add rule
        </Button>
        <Button size="small" variant="contained" disabled={busy || !dirty} onClick={save}>
          {busy ? 'Saving…' : `Save ${label} rules`}
        </Button>
        {dirty && (
          <>
            <Button size="small" disabled={busy} onClick={() => { setRows(toEdit(rules)); setSubmitted(false); }}>Discard changes</Button>
            <Chip size="small" color="warning" variant="outlined" label="Unsaved changes" />
          </>
        )}
      </Stack>
    </Box>
  );
}
