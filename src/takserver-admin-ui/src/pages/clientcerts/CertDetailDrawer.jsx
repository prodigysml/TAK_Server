import React, { useEffect, useState } from 'react';
import {
  Alert, Box, Button, Divider, Drawer, IconButton, Stack, Tooltip, Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { api, seg } from '../../api/client';
import { Loading } from '../../components/States';
import { useNotify } from '../../components/Notify';
import StatusChip from './StatusChip';
import {
  BASE, commonName, formatAbsolute, formatFull, formatRelative, parseDate, sanitize,
} from './certUtils';

function Field({ label, children, mono }) {
  return (
    <Box sx={{ py: 1 }}>
      <Typography variant="body2" color="text.secondary">{label}</Typography>
      <Typography
        variant="body2"
        component="div"
        sx={{ wordBreak: 'break-all', fontFamily: mono ? 'ui-monospace, SFMono-Regular, Menlo, monospace' : undefined }}
      >
        {children === null || children === undefined || children === '' ? <Box component="span" color="text.secondary">Not set</Box> : children}
      </Typography>
    </Box>
  );
}

function DateField({ label, value }) {
  const d = parseDate(value);
  return (
    <Field label={label}>
      {d ? `${formatAbsolute(d)} (${formatRelative(d)})` : null}
      {d && <Typography variant="caption" color="text.secondary" display="block">{formatFull(d)}</Typography>}
    </Field>
  );
}

// Detail view for one certificate. Starts from the row already loaded, then
// refreshes from GET /cert/{hash} like the classic view page did.
export default function CertDetailDrawer({ row, status, onClose, onRevoke, onDelete }) {
  const notify = useNotify();
  const [fresh, setFresh] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    setFresh(null);
    setError(null);
    if (!row?.hash) return undefined;
    let live = true;
    setLoading(true);
    api.get(`${BASE}/${seg(row.hash)}`)
      .then((c) => { if (live && c && typeof c === 'object') setFresh(sanitize(c)); })
      .catch((e) => { if (live) setError(e); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [row?.hash, row?.revocationDate]);

  const c = fresh || row;
  const revoked = status === 'revoked';

  const copyPem = async () => {
    try {
      await navigator.clipboard.writeText(c.certificate || '');
      notify('Copied the certificate PEM');
    } catch {
      notify(new Error('Couldn’t copy to the clipboard. Select the text and copy it manually.'));
    }
  };

  return (
    <Drawer anchor="right" open={!!row} onClose={onClose} PaperProps={{ sx: { width: { xs: '100%', sm: 520 } } }}>
      {c && (
        <Box sx={{ p: 3 }} role="region" aria-label="Certificate details">
          <Stack direction="row" alignItems="flex-start" spacing={1}>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography variant="h2" component="h2" sx={{ wordBreak: 'break-word' }}>{commonName(c.subjectDn) || 'Certificate'}</Typography>
              <Box sx={{ mt: 1 }}><StatusChip status={status} /></Box>
            </Box>
            <IconButton aria-label="Close details" onClick={onClose}><CloseIcon /></IconButton>
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mt: 2 }} flexWrap="wrap" useFlexGap>
            <Button
              variant="outlined" size="small" component="a"
              href={`${BASE}/${seg(c.hash)}/download`}
            >
              Download PEM
            </Button>
            <Tooltip title={revoked ? 'Already revoked' : ''}>
              <span>
                <Button variant="outlined" color="error" size="small" disabled={revoked} onClick={() => onRevoke(c)}>
                  Revoke certificate
                </Button>
              </span>
            </Tooltip>
            <Button color="error" size="small" onClick={() => onDelete(c)}>Delete record</Button>
          </Stack>

          {loading && <Loading />}
          {error && <Alert severity="warning" sx={{ mt: 2 }}>Couldn’t refresh from the server ({error.message}). Showing the values from the list.</Alert>}

          <Divider sx={{ my: 2 }} />
          <Field label="Subject DN">{c.subjectDn}</Field>
          <Field label="User DN">{c.userDn}</Field>
          <Field label="Created by (DN)">{c.creatorDn}</Field>
          <Field label="Device UID" mono>{c.clientUid}</Field>
          <Field label="Serial number (hex)" mono>{c.serialNumber}</Field>
          <Field label="Hash" mono>{c.hash}</Field>
          <Field label="Database id" mono>{c.id}</Field>
          <DateField label="Issued" value={c.issuanceDate} />
          <DateField label="Effective" value={c.effectiveDate} />
          <DateField label="Expires" value={c.expirationDate} />
          <DateField label="Revoked" value={c.revocationDate} />
          <Field label="Enrollment token">{c.hasToken ? 'Present (hidden; it is a live credential)' : 'None'}</Field>

          <Divider sx={{ my: 2 }} />
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="subtitle2" component="h3">Certificate (PEM)</Typography>
            <Button size="small" onClick={copyPem} disabled={!c.certificate}>Copy PEM</Button>
          </Stack>
          <Box
            component="pre"
            tabIndex={0}
            aria-label="Certificate PEM"
            sx={{
              mt: 1, p: 1.5, bgcolor: 'background.default', border: 1, borderColor: 'divider', borderRadius: 1,
              fontSize: 12, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', overflowX: 'auto', whiteSpace: 'pre',
            }}
          >
            {c.certificate || ''}
          </Box>
        </Box>
      )}
    </Drawer>
  );
}
