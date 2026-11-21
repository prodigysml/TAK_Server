import React, { useState } from 'react';
import {
  AppBar, Box, Button, Chip, Drawer, IconButton, List, ListItemButton, ListItemIcon, ListItemText,
  ListSubheader, Toolbar, Tooltip, Typography, useMediaQuery,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import MenuIcon from '@mui/icons-material/Menu';
import ShieldIcon from '@mui/icons-material/ShieldOutlined';
import WarningIcon from '@mui/icons-material/WarningAmberOutlined';
import { sections } from '../routes';
import { navigate } from '../router';
import { tokens } from '../theme';
import { api } from '../api/client';
import { usePolling } from '../api/useApi';

const DRAWER = 248;

// Ends the server session (and its MFA flag), same as the classic menu's Log Out.
function signOut() {
  fetch('/Marti/api/onboarding/logout', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' } })
    .catch(() => {})
    .finally(() => {
      try { sessionStorage.clear(); } catch { /* storage blocked */ }
      window.location.href = '/';
    });
}

function Nav({ path, onPick }) {
  return (
    <Box sx={{ height: '100%', bgcolor: tokens.sidebar, color: tokens.sidebarText, display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ px: 2.5, py: 2.25 }}>
        <Typography sx={{ color: '#fff', fontWeight: 600, fontSize: '1.0625rem' }}>TAK Server</Typography>
        <Typography sx={{ fontSize: '0.8125rem', opacity: 0.7 }}>Administration</Typography>
      </Box>
      <Box component="nav" aria-label="Admin sections" sx={{ flex: 1, overflowY: 'auto', pb: 2 }}>
        {sections.map((s) => (
          <List
            key={s.title || 'top'} dense disablePadding sx={{ mb: 1 }}
            subheader={s.title && (
              <ListSubheader disableSticky sx={{ bgcolor: 'transparent', color: tokens.sidebarText, opacity: 0.65, lineHeight: '32px', fontSize: '0.8125rem' }}>
                {s.title}
              </ListSubheader>
            )}
          >
            {s.items.map((r) => {
              const Icon = r.icon;
              const active = r.path === path;
              return (
                <ListItemButton
                  key={r.path}
                  selected={active}
                  aria-current={active ? 'page' : undefined}
                  onClick={() => { navigate(r.path); onPick?.(); }}
                  sx={{
                    mx: 1, borderRadius: 1, color: 'inherit',
                    '&.Mui-selected, &.Mui-selected:hover': { bgcolor: 'rgba(255,255,255,0.10)', color: '#fff' },
                    '&.Mui-selected::before': { content: '""', position: 'absolute', left: -8, top: 6, bottom: 6, width: 3, borderRadius: 2, bgcolor: '#7FB8B5' },
                    '&:hover': { bgcolor: 'rgba(255,255,255,0.06)' },
                  }}
                >
                  <ListItemIcon sx={{ color: 'inherit', minWidth: 34 }}><Icon fontSize="small" /></ListItemIcon>
                  <ListItemText primary={r.label} primaryTypographyProps={{ fontSize: '0.875rem' }} />
                </ListItemButton>
              );
            })}
          </List>
        ))}
      </Box>
      <Box sx={{ px: 2.5, py: 2, borderTop: '1px solid rgba(255,255,255,0.08)', fontSize: '0.8125rem' }}>
        <Box component="a" href="/index.html" sx={{ color: tokens.sidebarText, display: 'block', mb: 1 }}>Switch to classic UI</Box>
        <Box component="button" type="button" onClick={signOut} sx={{ all: 'unset', cursor: 'pointer', color: tokens.sidebarText, '&:focus-visible': { outline: '2px solid #7FB8B5' } }}>
          Sign out
        </Box>
      </Box>
    </Box>
  );
}

// Live server status: whether every port requires TLS, and how many clients are connected.
function StatusStrip() {
  const secure = usePolling(() => api.get('/Marti/api/security/isSecure'), 60000);
  const subs = usePolling(() => api.get('/Marti/api/subscriptions/all', { query: { limit: 1000 } }), 30000);
  const isSecure = secure.data === true || secure.data === 'true';
  const count = Array.isArray(subs.data) ? subs.data.length : null;
  return (
    <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
      {secure.data !== undefined && (
        <Tooltip title={isSecure ? 'Every input requires TLS.' : `These ports accept unencrypted connections: ${secure.data}`}>
          <Chip
            size="small" variant="outlined"
            icon={isSecure ? <ShieldIcon /> : <WarningIcon />}
            color={isSecure ? 'success' : 'warning'}
            label={isSecure ? 'All ports encrypted' : 'Unencrypted ports open'}
          />
        </Tooltip>
      )}
      {count !== null && (
        <Chip
          size="small" variant="outlined" clickable onClick={() => navigate('/clients')}
          label={`${count}${count >= 1000 ? '+' : ''} connected ${count === 1 ? 'client' : 'clients'}`}
        />
      )}
    </Box>
  );
}

export default function Layout({ route, children }) {
  const theme = useTheme();
  const wide = useMediaQuery(theme.breakpoints.up('md'));
  const [open, setOpen] = useState(false);
  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      {wide ? (
        <Drawer variant="permanent" sx={{ width: DRAWER, flexShrink: 0, '& .MuiDrawer-paper': { width: DRAWER, border: 0 } }}>
          <Nav path={route.path} />
        </Drawer>
      ) : (
        <Drawer open={open} onClose={() => setOpen(false)} sx={{ '& .MuiDrawer-paper': { width: DRAWER, border: 0 } }}>
          <Nav path={route.path} onPick={() => setOpen(false)} />
        </Drawer>
      )}
      <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        <AppBar position="sticky" color="inherit" sx={{ borderBottom: `1px solid ${tokens.line}`, bgcolor: tokens.panel }}>
          <Toolbar variant="dense" sx={{ gap: 1.5, minHeight: 52 }}>
            {!wide && (
              <IconButton edge="start" aria-label="Open navigation" onClick={() => setOpen(true)}><MenuIcon /></IconButton>
            )}
            <StatusStrip />
            <Box sx={{ flex: 1 }} />
            {route.classic && (
              <Button size="small" variant="text" href={route.classic}>Open classic version</Button>
            )}
          </Toolbar>
        </AppBar>
        <Box component="main" sx={{ flex: 1, p: { xs: 2, md: 4 }, maxWidth: 1440, width: '100%' }}>
          {children}
        </Box>
      </Box>
    </Box>
  );
}
