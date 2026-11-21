import React from 'react';
import { Box, Button, Chip, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { compactNumber, formatBytes, isPlaintextProtocol, plural, splitInputs } from './helpers';
import { navigate } from '../../router';

function status(m, insecurePorts) {
  const port = Number(m.input.port);
  const plaintext = (insecurePorts && insecurePorts.includes(port)) || isPlaintextProtocol(m.input.protocol);
  if (plaintext) return { label: 'Unencrypted', color: 'warning' };
  if (Number(m.numClients) > 0) return { label: 'In use', color: 'success' };
  return { label: 'No clients', color: 'default' };
}

export default function InputsBlock({ metrics, insecurePorts }) {
  const { inputs, feeds } = splitInputs(metrics);

  if (inputs.length === 0) {
    return (
      <Box>
        <Typography color="text.secondary">
          No inputs are configured, so clients have no port to connect to.
        </Typography>
        <Button size="small" variant="outlined" sx={{ mt: 1.5 }} onClick={() => navigate('/inputs')}>Add an input</Button>
      </Box>
    );
  }

  const totalClients = inputs.reduce((s, m) => s + (Number(m.numClients) || 0), 0);

  return (
    <Box>
      <Typography color="text.secondary" sx={{ mb: 1 }}>
        {plural(inputs.length, 'input')} listening, {plural(totalClients, 'client')} connected through them
        {feeds.length > 0 ? `, plus ${plural(feeds.length, 'data feed')}` : ''}.
      </Typography>
      <TableContainer sx={{ border: 1, borderColor: 'divider', borderRadius: 1, overflowX: 'auto' }}>
        <Table size="small" aria-label="Inputs">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Protocol</TableCell>
              <TableCell align="right">Port</TableCell>
              <TableCell>Auth</TableCell>
              <TableCell align="right">Connected</TableCell>
              <TableCell align="right">Messages</TableCell>
              <TableCell align="right">Data received</TableCell>
              <TableCell>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {inputs.map((m) => {
              const st = status(m, insecurePorts);
              return (
                <TableRow key={`${m.input.name}-${m.input.port}`} hover>
                  <TableCell sx={{ fontWeight: 500, whiteSpace: 'nowrap' }}>{String(m.input.name ?? '')}</TableCell>
                  <TableCell sx={{ textTransform: 'uppercase' }}>{String(m.input.protocol ?? '')}</TableCell>
                  <TableCell align="right">{String(m.input.port ?? '')}</TableCell>
                  <TableCell>{String(m.input.auth ?? '')}</TableCell>
                  <TableCell align="right">{(Number(m.numClients) || 0).toLocaleString()}</TableCell>
                  <TableCell align="right">{compactNumber(m.messagesReceived)}</TableCell>
                  <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>{formatBytes(m.bytesRecieved)}</TableCell>
                  <TableCell><Chip size="small" variant="outlined" color={st.color} label={st.label} /></TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
