import React from 'react';
import { Box, Chip, Stack, Typography } from '@mui/material';
import ShieldIcon from '@mui/icons-material/ShieldOutlined';
import WarningIcon from '@mui/icons-material/WarningAmberOutlined';

// sec: output of parseSecure(). inputsByPort: Map port -> input name, when inputs loaded.
export default function SecurityBlock({ sec, inputsByPort }) {
  if (sec.secure) {
    return (
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        <Chip size="small" color="success" variant="outlined" icon={<ShieldIcon />} label="Encrypted" />
        <Typography color="text.secondary">Every listening port requires TLS.</Typography>
      </Stack>
    );
  }
  return (
    <Box>
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        <Chip size="small" color="warning" variant="outlined" icon={<WarningIcon />} label="Unencrypted ports" sx={{ flexShrink: 0 }} />
        <Typography>
          {sec.ports.length === 1 ? 'One port accepts' : `${sec.ports.length || 'Some'} ports accept`} unencrypted connections.
          Anyone on the network path can read positions and messages sent to {sec.ports.length === 1 ? 'it' : 'them'}.
        </Typography>
      </Stack>
      {sec.ports.length > 0 && (
        <Box component="ul" sx={{ m: 0, mt: 1, pl: 0, listStyle: 'none', display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {sec.ports.map((p) => (
            <Box component="li" key={p} sx={{ px: 1, py: 0.25, border: 1, borderColor: 'divider', borderRadius: 1, fontSize: '0.8125rem' }}>
              Port {p}{inputsByPort?.get(p) ? ` (${inputsByPort.get(p)})` : ''}
            </Box>
          ))}
        </Box>
      )}
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        Switch these ports to TLS, or remove them if no clients need them.
      </Typography>
    </Box>
  );
}
