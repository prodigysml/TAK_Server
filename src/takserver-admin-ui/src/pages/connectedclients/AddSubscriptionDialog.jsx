import React, { useState } from 'react';
import {
  Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, MenuItem, Stack, TextField,
} from '@mui/material';
import { api } from '../../api/client';
import { STATIC_PROTOCOLS } from './model';

// Mirrors the server's MartiSafeString validator (takserver-core validation.properties).
const SAFE = /^[\p{L}\p{N}\w\s.()!=@#$&^*\-+[\]{}:,/|\\]*$/u;

const EMPTY = { uid: '', protocol: 'tcp', subaddr: '', subport: '', xpath: '', filterGroups: '', iface: '' };

function validate(f) {
  const e = {};
  const uid = f.uid.trim();
  if (!uid) e.uid = 'Enter a UID for this subscription.';
  else if (uid.length > 255 || !SAFE.test(uid)) e.uid = 'Use letters, numbers, spaces and . _ - : / only (up to 255 characters).';
  if (!f.protocol) e.protocol = 'Choose a protocol.';
  const addr = f.subaddr.trim();
  if (!addr) e.subaddr = 'Enter the host name or IP address to send to.';
  else if (addr.includes(':') || /\s/.test(addr)) e.subaddr = 'Enter a host name or IPv4 address without a port or spaces.';
  const port = Number(f.subport);
  if (!f.subport.trim()) e.subport = 'Enter a port.';
  else if (!Number.isInteger(port) || port < 1 || port > 65535) e.subport = 'Port must be a whole number from 1 to 65535.';
  if (f.xpath.includes(';')) e.xpath = 'XPath can’t contain a semicolon.';
  else if (f.xpath.length > 2048) e.xpath = 'XPath must be 2048 characters or fewer.';
  const groups = f.filterGroups.split(',').map((g) => g.trim()).filter(Boolean);
  if (groups.some((g) => g.length > 255 || !SAFE.test(g))) e.filterGroups = 'Group names can use letters, numbers, spaces and . _ - only.';
  if (f.iface && !SAFE.test(f.iface)) e.iface = 'Enter an interface name such as eth0.';
  return e;
}

export default function AddSubscriptionDialog({ open, onClose, onAdded, notify }) {
  const [form, setForm] = useState(EMPTY);
  const [touched, setTouched] = useState({});
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const errors = validate(form);
  const show = (k) => (submitted || touched[k]) && errors[k];
  const set = (k) => (ev) => setForm((f) => ({ ...f, [k]: ev.target.value }));
  const blur = (k) => () => setTouched((t) => ({ ...t, [k]: true }));
  const isUdp = ['udp', 'mcast', 'cotmcast'].includes(form.protocol);

  const reset = () => { setForm(EMPTY); setTouched({}); setSubmitted(false); };
  const close = () => { if (!busy) { reset(); onClose(); } };

  const submit = async (ev) => {
    ev.preventDefault();
    setSubmitted(true);
    if (Object.keys(errors).length) return;
    setBusy(true);
    const uid = form.uid.trim();
    try {
      // Same body shape the classic page posts (SubscriptionApi.tmpStaticSub).
      // xpath and filterGroups must be strings, not null: the server calls replaceAll on them.
      await api.post('/Marti/api/subscriptions/add', {
        uid,
        protocol: form.protocol,
        subaddr: form.subaddr.trim(),
        subport: String(Number(form.subport)),
        xpath: form.xpath.trim(),
        filterGroups: form.filterGroups,
        iface: isUdp ? form.iface.trim() : '',
      });
      notify(`Added static subscription ${uid}`);
      reset();
      onAdded();
    } catch (err) {
      notify(new Error(err.status === 400
        ? `The server rejected subscription ${uid}. Check the XPath, group names and address, then try again.`
        : err.message));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} maxWidth="sm" fullWidth>
      <form onSubmit={submit} noValidate>
        <DialogTitle>Add static subscription</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            The server will push matching traffic to this address and port. It is saved to the server configuration and survives restarts.
          </DialogContentText>
          <Stack spacing={2}>
            <TextField
              label="UID" required autoFocus fullWidth value={form.uid} onChange={set('uid')} onBlur={blur('uid')}
              error={!!show('uid')} helperText={show('uid') || 'A name for this subscription, for example Rascal-feed.'}
            />
            <TextField
              select label="Protocol" required fullWidth value={form.protocol} onChange={set('protocol')}
              error={!!show('protocol')} helperText={show('protocol') || ' '}
            >
              {STATIC_PROTOCOLS.map((p) => <MenuItem key={p.value} value={p.value}>{p.label}</MenuItem>)}
            </TextField>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                label="Subscriber address" required fullWidth value={form.subaddr} onChange={set('subaddr')} onBlur={blur('subaddr')}
                error={!!show('subaddr')} helperText={show('subaddr') || 'Host name or IPv4 address.'}
              />
              <TextField
                label="Port" required value={form.subport} onChange={set('subport')} onBlur={blur('subport')}
                inputProps={{ inputMode: 'numeric' }} sx={{ width: { sm: 160 } }}
                error={!!show('subport')} helperText={show('subport') || '1 to 65535'}
              />
            </Stack>
            <TextField
              label="XPath filter" fullWidth value={form.xpath} onChange={set('xpath')} onBlur={blur('xpath')}
              error={!!show('xpath')}
              helperText={show('xpath') || 'Optional. Leave blank to send everything. Example: /event[starts-with(@uid, \'Rascal.PPLI\')]'}
            />
            <TextField
              label="Groups" fullWidth value={form.filterGroups} onChange={set('filterGroups')} onBlur={blur('filterGroups')}
              error={!!show('filterGroups')} helperText={show('filterGroups') || 'Optional. Comma-separated group names.'}
            />
            {isUdp && (
              <TextField
                label="Outbound interface" fullWidth value={form.iface} onChange={set('iface')} onBlur={blur('iface')}
                error={!!show('iface')} helperText={show('iface') || 'Optional. Network interface to send UDP from, for example eth0.'}
              />
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={close} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={busy}>Add subscription</Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}
