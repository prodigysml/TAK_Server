import { createTheme } from '@mui/material/styles';

// Palette: slate sidebar, cool light surface, topo-teal primary, amber for warnings.
export const tokens = {
  ink: '#1D2B35',
  inkMuted: '#5A6872',
  sidebar: '#1D2B35',
  sidebarText: '#C9D3D9',
  surface: '#F5F6F4',
  panel: '#FFFFFF',
  line: '#DDE2E0',
  teal: '#2F6F73',
  amber: '#B7791F',
  red: '#B23A3A',
  green: '#3C7D4A',
};

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: { main: tokens.teal, contrastText: '#FFFFFF' },
    secondary: { main: tokens.ink },
    warning: { main: tokens.amber },
    error: { main: tokens.red },
    success: { main: tokens.green },
    background: { default: tokens.surface, paper: tokens.panel },
    text: { primary: tokens.ink, secondary: tokens.inkMuted },
    divider: tokens.line,
  },
  typography: {
    fontFamily: '"IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif',
    fontSize: 14,
    h1: { fontSize: '1.625rem', fontWeight: 600, letterSpacing: '-0.01em' },
    h2: { fontSize: '1.25rem', fontWeight: 600 },
    h3: { fontSize: '1.0625rem', fontWeight: 600 },
    subtitle2: { fontWeight: 600 },
    button: { textTransform: 'none', fontWeight: 500 },
  },
  shape: { borderRadius: 6 },
  components: {
    MuiPaper: {
      defaultProps: { elevation: 0 },
      styleOverrides: { outlined: { borderColor: tokens.line } },
    },
    MuiButton: { defaultProps: { disableElevation: true } },
    MuiTextField: { defaultProps: { size: 'small' } },
    MuiSelect: { defaultProps: { size: 'small' } },
    MuiChip: { styleOverrides: { root: { fontWeight: 500 } } },
    MuiTableCell: { styleOverrides: { head: { fontWeight: 600, color: tokens.inkMuted } } },
    MuiDataGrid: {
      defaultProps: { density: 'compact', disableRowSelectionOnClick: true },
      styleOverrides: {
        root: { border: `1px solid ${tokens.line}`, backgroundColor: tokens.panel, fontVariantNumeric: 'tabular-nums' },
        columnHeaderTitle: { fontWeight: 600, color: tokens.inkMuted },
      },
    },
    MuiCssBaseline: {
      styleOverrides: {
        body: { fontVariantNumeric: 'tabular-nums' },
        ':focus-visible': { outline: `2px solid ${tokens.teal}`, outlineOffset: 2 },
        '@media (prefers-reduced-motion: reduce)': {
          '*': { transition: 'none !important', animation: 'none !important' },
        },
      },
    },
  },
});

export default theme;
