import React, { useState } from 'react';
import {
  Autocomplete, Box, Button, IconButton, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow,
  TextField, ToggleButton, ToggleButtonGroup, Tooltip, Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { DIRECTIONS, DIRECTION_HELP, GROUP_RULE, isValidGroupName } from './model';

/**
 * Edit a user's group memberships: [{ name, direction: 'both'|'in'|'out' }].
 * Admins can pick an existing group or type a new name (a group exists once
 * someone is assigned to it, as in the classic page).
 */
export default function GroupAssignment({ value, onChange, groups = [], disabled, emptyNote }) {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const assigned = new Set(value.map((a) => a.name));
  const options = groups.filter((g) => !assigned.has(g));

  const add = (raw) => {
    const name = (raw || '').trim();
    if (!name) return;
    if (assigned.has(name)) { setError(`${name} is already assigned.`); return; }
    if (!groups.includes(name) && !isValidGroupName(name)) { setError(`New group names need ${GROUP_RULE.charAt(0).toLowerCase()}${GROUP_RULE.slice(1)}`); return; }
    onChange([...value, { name, direction: 'both' }]);
    setInput('');
    setError('');
  };
  const setDir = (name, direction) => direction && onChange(value.map((a) => (a.name === name ? { ...a, direction } : a)));
  const remove = (name) => onChange(value.filter((a) => a.name !== name));

  return (
    <Box>
      <Typography variant="subtitle2" component="h3">Groups</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{DIRECTION_HELP}</Typography>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'flex-start' }}>
        <Autocomplete
          freeSolo fullWidth disabled={disabled}
          options={options}
          inputValue={input}
          onInputChange={(_, v, reason) => { if (reason !== 'reset') { setInput(v); setError(''); } }}
          onChange={(_, v, reason) => { if (reason === 'selectOption' || reason === 'createOption') add(v); }}
          renderInput={(params) => (
            <TextField
              {...params}
              label="Add a group"
              placeholder="Pick a group or type a new name"
              error={!!error}
              helperText={error || 'New members join with direction Both. Change it in the list below.'}
            />
          )}
        />
        <Button variant="outlined" onClick={() => add(input)} disabled={disabled || !input.trim()} sx={{ flexShrink: 0, mt: { sm: '1px' } }}>
          Add group
        </Button>
      </Stack>

      {value.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5 }}>
          {emptyNote || 'No groups assigned. Users with no groups are placed in the __ANON__ group.'}
        </Typography>
      ) : (
        <Paper variant="outlined" sx={{ mt: 1.5, overflowX: 'auto' }}>
          <Table size="small" aria-label="Assigned groups">
            <TableHead>
              <TableRow>
                <TableCell>Group</TableCell>
                <TableCell>Direction</TableCell>
                <TableCell align="right"><Box component="span" sx={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>Remove</Box></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {value.map((a) => (
                <TableRow key={a.name}>
                  <TableCell sx={{ wordBreak: 'break-all' }}>
                    {a.name}
                    {!groups.includes(a.name) && <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>new</Typography>}
                  </TableCell>
                  <TableCell>
                    <ToggleButtonGroup
                      exclusive size="small" disabled={disabled}
                      value={a.direction}
                      onChange={(_, d) => setDir(a.name, d)}
                      aria-label={`Direction for ${a.name}`}
                    >
                      {DIRECTIONS.map((d) => (
                        <Tooltip key={d.value} title={d.help}>
                          <ToggleButton value={d.value} sx={{ py: 0.25, px: 1.25, whiteSpace: 'nowrap' }}>{d.label}</ToggleButton>
                        </Tooltip>
                      ))}
                    </ToggleButtonGroup>
                  </TableCell>
                  <TableCell align="right">
                    <IconButton size="small" onClick={() => remove(a.name)} disabled={disabled} aria-label={`Remove ${a.name}`}>
                      <CloseIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}
    </Box>
  );
}
