import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControl,
  FormControlLabel, FormGroup, FormHelperText, FormLabel, MenuItem, Stack, TextField,
} from '@mui/material';
import { api } from '../../api/client';
import { useNotify } from '../../components/Notify';
import { SwitchField } from './common';
import {
  AUTHS, DEFAULT_TLS, FEED_PROTOCOLS, PROTOCOLS, TLS_VERSIONS, allowedAuths, isMcast, isTlsProtocol,
  linesToList, transportOf, validateFilterGroups, validateGroup, validateIface, validateName, validatePort, validateRetention,
} from './model';

const TITLES = {
  input: 'Add input',
  streaming: 'Add streaming data feed',
  plugin: 'Add plugin data feed',
};
const SAVE_LABEL = {
  input: 'Add input',
  streaming: 'Add data feed',
  plugin: 'Add data feed',
};

function initial(kind) {
  return {
    name: '',
    protocol: 'tls',
    auth: 'X_509',
    port: '',
    coreVersion: 2,
    tls: [...DEFAULT_TLS],
    group: '',
    iface: '',
    archive: true,
    anongroup: false,
    archiveOnly: false,
    filtergroup: '',
    tag: '',
    sync: false,
    federated: true,
    syncCacheRetentionSeconds: '3600',
    kind,
  };
}

/**
 * Create an input (POST /Marti/api/inputs) or a data feed (POST /Marti/api/datafeeds).
 * kind: 'input' | 'streaming' | 'plugin'
 * existing: list of InputMetric rows, used for duplicate name and port checks.
 */
export default function CreateDialog({ open, kind, existing, onClose, onCreated }) {
  const notify = useNotify();
  const [f, setF] = useState(initial(kind));
  const [touched, setTouched] = useState({});
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState(null);

  useEffect(() => {
    if (open) {
      setF(initial(kind)); setTouched({}); setSubmitted(false); setServerError(null);
    }
  }, [open, kind]);

  const isPlugin = kind === 'plugin';
  const isFeed = kind !== 'input';
  const protocols = kind === 'input' ? PROTOCOLS : FEED_PROTOCOLS;

  const names = useMemo(() => new Set((existing || []).map((m) => String(m.input?.name || '').toLowerCase())), [existing]);
  const portOwner = useMemo(() => {
    const p = Number(f.port);
    const mine = transportOf(f.protocol);
    const hit = (existing || []).find((m) => {
      const other = m.input || {};
      if (!other.protocol || Number(other.port) !== p) return false;
      // TCP and UDP can share a number; multicast inputs can share one across groups.
      if (transportOf(other.protocol) !== mine) return false;
      return !(isMcast(other.protocol) && isMcast(f.protocol));
    });
    return hit ? hit.input.name : null;
  }, [existing, f.port, f.protocol]);

  const auths = allowedAuths(f.protocol);
  const showTls = !isPlugin && Number(f.coreVersion) === 2 && isTlsProtocol(f.protocol);
  const showMcast = !isPlugin && isMcast(f.protocol);

  const errors = {
    name: validateName(f.name, names),
    port: isPlugin ? null : (validatePort(f.port) || (portOwner ? `Port ${f.port} is already used by “${portOwner}”.` : null)),
    auth: isPlugin || auths.some((a) => a.value === f.auth) ? null : 'This authentication type doesn’t work with the selected protocol.',
    tls: showTls && f.tls.length === 0 ? 'Choose at least one TLS version.' : null,
    group: showMcast ? validateGroup(f.group, f.protocol) : null,
    iface: showMcast ? validateIface(f.iface) : null,
    filtergroup: validateFilterGroups(f.filtergroup),
    archiveOnly: f.archiveOnly && !f.archive ? 'Turn on archive first. Archive only needs archiving.' : null,
    syncCacheRetentionSeconds: kind === 'streaming' ? validateRetention(f.syncCacheRetentionSeconds) : null,
  };
  const hasErrors = Object.values(errors).some(Boolean);
  const show = (k) => (submitted || touched[k]) && errors[k];
  const set = (k) => (v) => setF((s) => ({ ...s, [k]: v }));
  const blur = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  const changeProtocol = (p) => {
    setF((s) => {
      const ok = allowedAuths(p);
      const auth = ok.some((a) => a.value === s.auth) ? s.auth : ok[0].value;
      return { ...s, protocol: p, auth, group: isMcast(p) ? s.group : '', iface: isMcast(p) ? s.iface : '' };
    });
  };

  const toggleTls = (v) => setF((s) => ({
    ...s,
    tls: s.tls.includes(v) ? s.tls.filter((x) => x !== v) : TLS_VERSIONS.filter((x) => x === v || s.tls.includes(x)),
  }));

  const buildBody = () => {
    const name = f.name.trim();
    if (isPlugin) {
      // Mirrors the classic savePluginDataFeed defaults.
      return {
        name, type: 'Plugin', auth: 'ANONYMOUS', protocol: '', anongroup: false, archiveOnly: false, coreVersion: 2,
        archive: f.archive, sync: f.sync, federated: f.federated, syncCacheRetentionSeconds: 3600,
        tag: linesToList(f.tag), filtergroup: linesToList(f.filtergroup),
      };
    }
    const body = {
      name,
      protocol: f.protocol,
      auth: f.auth,
      port: Number(f.port),
      coreVersion: Number(f.coreVersion),
      archive: f.archive,
      anongroup: f.anongroup,
      archiveOnly: f.archiveOnly,
      filtergroup: linesToList(f.filtergroup),
    };
    if (Number(f.coreVersion) === 2) body.coreVersion2TlsVersions = (showTls ? f.tls : DEFAULT_TLS).join(',');
    if (showMcast) {
      body.group = f.group.trim();
      if (f.iface.trim()) body.iface = f.iface.trim();
    }
    if (kind === 'streaming') {
      Object.assign(body, {
        type: 'Streaming', sync: f.sync, federated: f.federated,
        syncCacheRetentionSeconds: Number(f.syncCacheRetentionSeconds), tag: linesToList(f.tag),
      });
    }
    return body;
  };

  const save = async (e) => {
    e.preventDefault();
    setSubmitted(true);
    if (hasErrors) return;
    setBusy(true);
    setServerError(null);
    try {
      await api.post(isFeed ? '/Marti/api/datafeeds' : '/Marti/api/inputs', buildBody());
      notify(isFeed
        ? `Added data feed “${f.name.trim()}”`
        : `Added input “${f.name.trim()}” on port ${f.port}`);
      onCreated();
    } catch (err) {
      setServerError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth>
      <form onSubmit={save} noValidate>
        <DialogTitle>{TITLES[kind]}</DialogTitle>
        <DialogContent dividers>
          {serverError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              The server didn’t accept this: {serverError} Fix the fields and try again.
            </Alert>
          )}
          <Stack spacing={2}>
            <TextField
              label="Name" required autoFocus value={f.name} onChange={(e) => set('name')(e.target.value)} onBlur={blur('name')}
              inputProps={{ maxLength: 30 }} error={!!show('name')}
              helperText={show('name') || 'Letters, numbers, spaces and underscores, up to 30 characters. Can’t be changed later.'}
            />

            {!isPlugin && (
              <>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                  <TextField
                    select label="Protocol" required value={f.protocol} onChange={(e) => changeProtocol(e.target.value)}
                    sx={{ flex: 2 }} helperText="Can’t be changed later."
                  >
                    {protocols.map((p) => <MenuItem key={p.value} value={p.value}>{p.label}</MenuItem>)}
                  </TextField>
                  <TextField
                    label="Port" required value={f.port} onChange={(e) => set('port')(e.target.value.replace(/[^0-9]/g, ''))}
                    onBlur={blur('port')} inputProps={{ inputMode: 'numeric', maxLength: 5 }} sx={{ flex: 1 }}
                    error={!!show('port')} helperText={show('port') || '1 to 65535'}
                  />
                </Stack>

                <TextField
                  select label="Authentication" required value={f.auth} onChange={(e) => set('auth')(e.target.value)}
                  error={!!errors.auth}
                  helperText={errors.auth || (auths.length === 1
                    ? 'TCP, UDP and multicast inputs can only be anonymous.'
                    : 'How clients prove who they are on this port. File and LDAP work only with STCP, TLS and COTTLS.')}
                >
                  {AUTHS.map((a) => (
                    <MenuItem key={a.value} value={a.value} disabled={!auths.some((x) => x.value === a.value)}>{a.label}</MenuItem>
                  ))}
                </TextField>

                <TextField select label="Core messaging version" value={f.coreVersion} onChange={(e) => set('coreVersion')(Number(e.target.value))}>
                  <MenuItem value={2}>2 (high performance)</MenuItem>
                  <MenuItem value={1}>1 (legacy)</MenuItem>
                </TextField>

                {showTls && (
                  <FormControl error={!!show('tls')} component="fieldset">
                    <FormLabel component="legend" sx={{ typography: 'body2' }}>TLS versions</FormLabel>
                    <FormGroup row>
                      {TLS_VERSIONS.map((v) => (
                        <FormControlLabel key={v} label={v} control={<Checkbox size="small" checked={f.tls.includes(v)} onChange={() => toggleTls(v)} />} />
                      ))}
                    </FormGroup>
                    <FormHelperText>
                      {show('tls') || (f.tls.some((v) => v === 'TLSv1' || v === 'TLSv1.1')
                        ? 'TLSv1 and TLSv1.1 are obsolete. Turn them on only for old clients that need them.'
                        : 'TLSv1.2 and TLSv1.3 cover current TAK clients.')}
                    </FormHelperText>
                  </FormControl>
                )}

                {showMcast && (
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                    <TextField
                      label="Multicast group" required value={f.group} onChange={(e) => set('group')(e.target.value)} onBlur={blur('group')}
                      sx={{ flex: 1 }} inputProps={{ maxLength: 15 }} error={!!show('group')}
                      helperText={show('group') || 'IPv4 multicast address, for example 239.2.3.1'}
                    />
                    <TextField
                      label="Interface" value={f.iface} onChange={(e) => set('iface')(e.target.value)} onBlur={blur('iface')}
                      sx={{ flex: 1 }} inputProps={{ maxLength: 15 }} error={!!show('iface')}
                      helperText={show('iface') || 'Optional network interface, for example eth0'}
                    />
                  </Stack>
                )}

                {kind === 'streaming' && (
                  <TextField
                    label="Sync cache retention (seconds)" value={f.syncCacheRetentionSeconds}
                    onChange={(e) => set('syncCacheRetentionSeconds')(e.target.value.replace(/[^0-9]/g, ''))}
                    onBlur={blur('syncCacheRetentionSeconds')} inputProps={{ inputMode: 'numeric', maxLength: 15 }}
                    error={!!show('syncCacheRetentionSeconds')}
                    helperText={show('syncCacheRetentionSeconds') || 'How long synced feed data is kept for clients that connect later.'}
                  />
                )}
              </>
            )}

            {isFeed && (
              <TextField
                label="Tags" multiline minRows={2} value={f.tag} onChange={(e) => set('tag')(e.target.value)}
                helperText="Optional. One tag per line."
              />
            )}

            <TextField
              label="Filter groups" multiline minRows={2} value={f.filtergroup} onChange={(e) => set('filtergroup')(e.target.value)}
              onBlur={blur('filtergroup')} error={!!show('filtergroup')}
              helperText={show('filtergroup') || (isFeed
                ? 'Optional. One group per line. Only these groups can see the feed. Leave empty for the anonymous group.'
                : 'Optional. One group per line, for example an LDAP DN like cn=ops,ou=groups,dc=example,dc=org.')}
            />

            <Box>
              <SwitchField
                label="Archive" checked={f.archive}
                onChange={(v) => setF((s) => ({ ...s, archive: v, archiveOnly: v ? s.archiveOnly : false }))}
                help="Store messages received here in the database."
              />
              {!isPlugin && (
                <>
                  <SwitchField
                    label="Archive only" checked={f.archiveOnly} onChange={set('archiveOnly')} disabled={!f.archive}
                    help="Store messages without sending them on to other clients." error={show('archiveOnly')}
                  />
                  <SwitchField
                    label="Anonymous group" checked={f.anongroup} onChange={set('anongroup')}
                    help="Also put clients on this port in the anonymous group."
                  />
                </>
              )}
              {isFeed && (
                <>
                  <SwitchField label="Sync" checked={f.sync} onChange={set('sync')} help="Keep recent feed data so newly connected clients get it." />
                  <SwitchField label="Federated" checked={f.federated} onChange={set('federated')} help="Share this feed’s data with federated servers." />
                </>
              )}
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={busy}>{busy ? 'Saving…' : SAVE_LABEL[kind]}</Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}
