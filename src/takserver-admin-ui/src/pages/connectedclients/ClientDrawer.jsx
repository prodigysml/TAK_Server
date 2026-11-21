import React from 'react';
import { Box, Button, Chip, Divider, Drawer, IconButton, Link, Stack, Tooltip, Typography } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { seg } from '../../api/client';
import { DETAIL_SECTIONS, formatAgo, formatField, groupDirectionLabel } from './model';

function Field({ label, value }) {
  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '160px 1fr' }, columnGap: 2, py: 0.5 }}>
      <Typography variant="body2" color="text.secondary">{label}</Typography>
      <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>
        {value === '' ? <Box component="span" sx={{ color: 'text.disabled' }}>Not reported</Box> : value}
      </Typography>
    </Box>
  );
}

export default function ClientDrawer({ row, onClose, onDisconnect, onToggleIncognito, busy }) {
  const open = !!row;
  return (
    <Drawer anchor="right" open={open} onClose={onClose} PaperProps={{ sx: { width: { xs: '100%', sm: 480 } } }}>
      {row && (
        <Box sx={{ p: 2.5 }} role="region" aria-label={`Details for ${row.callsign || row.clientUid || 'client'}`}>
          <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={1}>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="h2" component="h2" sx={{ wordBreak: 'break-word' }}>{row.callsign || row.clientUid || 'Unnamed client'}</Typography>
              <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap" useFlexGap>
                <Chip size="small" color={row._health.color} label={row._health.label} variant="outlined" />
                <Chip size="small" label={row._protocol} variant="outlined" />
                {row.incognito && <Chip size="small" color="warning" label="Incognito" />}
              </Stack>
              {row.lastReportMilliseconds > 0 && (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Last report {formatAgo(row.lastReportDiffMilliseconds)}
                </Typography>
              )}
            </Box>
            <IconButton aria-label="Close details" onClick={onClose}><CloseIcon /></IconButton>
          </Stack>

          {row.subscriptionUid && (
            <Stack direction="row" spacing={1} sx={{ mt: 2 }} flexWrap="wrap" useFlexGap>
              <Button size="small" variant="outlined" color="error" disabled={busy} onClick={() => onDisconnect([row])}>
                Disconnect client
              </Button>
              <Button size="small" variant="outlined" disabled={busy} onClick={() => onToggleIncognito(row)}>
                {row.incognito ? 'Turn off incognito' : 'Turn on incognito'}
              </Button>
              <Button
                size="small"
                component={Link}
                href={`/Marti/metrics/index.html#!/connection/${seg(row.subscriptionUid)}`}
              >
                Open connection metrics
              </Button>
            </Stack>
          )}

          <Divider sx={{ my: 2 }} />
          <Typography variant="h3" component="h3" sx={{ mb: 1 }}>Groups</Typography>
          {row._groups.length === 0 ? (
            <Typography variant="body2" color="text.secondary">No groups reported for this connection.</Typography>
          ) : (
            <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
              {row._groups.map((g) => (
                <Tooltip key={g.name} title={`Client can ${groupDirectionLabel(g)} in this group`}>
                  <Chip
                    size="small"
                    variant="outlined"
                    label={g.in && g.out ? g.name : `${g.name} (${g.in ? 'send only' : 'receive only'})`}
                  />
                </Tooltip>
              ))}
            </Stack>
          )}

          {DETAIL_SECTIONS.map((section) => (
            <Box key={section.title}>
              <Divider sx={{ my: 2 }} />
              <Typography variant="h3" component="h3" sx={{ mb: 1 }}>{section.title}</Typography>
              {section.fields.map(([key, label, kind]) => (
                <Field key={key} label={label} value={formatField(row, key, kind)} />
              ))}
            </Box>
          ))}
        </Box>
      )}
    </Drawer>
  );
}
