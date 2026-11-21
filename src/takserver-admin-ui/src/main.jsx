import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import { CssBaseline, ThemeProvider } from '@mui/material';
import theme from './theme';
import App from './App';
import { NotifyProvider } from './components/Notify';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <NotifyProvider>
        <App />
      </NotifyProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
