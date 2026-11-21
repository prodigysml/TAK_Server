import React, { useState } from 'react';
import { Box, IconButton, InputAdornment, List, ListItem, ListItemIcon, ListItemText, TextField } from '@mui/material';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import { PASSWORD_RULES } from './model';

// Password input with show/hide and the server's complexity rules as a live checklist.
export default function PasswordField({ value, onChange, label = 'Password', autoFocus, disabled }) {
  const [show, setShow] = useState(false);
  return (
    <Box>
      <TextField
        fullWidth required autoFocus={autoFocus} disabled={disabled}
        label={label}
        type={show ? 'text' : 'password'}
        autoComplete="new-password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        inputProps={{ spellCheck: false, autoCapitalize: 'off', 'aria-describedby': 'password-rules' }}
        InputProps={{
          endAdornment: (
            <InputAdornment position="end">
              <IconButton size="small" edge="end" onClick={() => setShow((s) => !s)} aria-label={show ? 'Hide password' : 'Show password'}>
                {show ? <VisibilityOffIcon fontSize="small" /> : <VisibilityIcon fontSize="small" />}
              </IconButton>
            </InputAdornment>
          ),
        }}
      />
      <List dense disablePadding id="password-rules" aria-label="Password requirements" sx={{ mt: 0.5 }}>
        {PASSWORD_RULES.map((r) => {
          const ok = r.test(value || '');
          return (
            <ListItem key={r.id} disableGutters sx={{ py: 0 }}>
              <ListItemIcon sx={{ minWidth: 24 }}>
                {ok
                  ? <CheckCircleIcon fontSize="inherit" color="success" />
                  : <RadioButtonUncheckedIcon fontSize="inherit" sx={{ color: 'text.disabled' }} />}
              </ListItemIcon>
              <ListItemText
                primary={r.label}
                secondary={null}
                primaryTypographyProps={{ variant: 'body2', color: ok ? 'text.primary' : 'text.secondary' }}
              />
              <Box component="span" sx={visuallyHidden}>{ok ? 'met' : 'not met'}</Box>
            </ListItem>
          );
        })}
      </List>
    </Box>
  );
}

const visuallyHidden = {
  position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap',
};
