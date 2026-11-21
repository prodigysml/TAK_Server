import React, { useMemo, useState } from 'react';
import {
  Alert, Box, Button, InputAdornment, Link, Paper, Stack, Tab, Tabs, TextField, Tooltip, Typography,
} from '@mui/material';
import { alpha } from '@mui/material/styles';
import { DataGrid } from '@mui/x-data-grid';
import SearchIcon from '@mui/icons-material/Search';
import RefreshIcon from '@mui/icons-material/Refresh';
import { api, seg } from '../api/client';
import { useApi } from '../api/useApi';
import PageHeader from '../components/PageHeader';
import ConfirmDialog from '../components/ConfirmDialog';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { useNotify } from '../components/Notify';
import StatusChip from './clientcerts/StatusChip';
import CertDetailDrawer from './clientcerts/CertDetailDrawer';
import {
  BASE, LIMITS, commonName, deriveStatus, formatAbsolute, formatFull, formatRelative, parseDate, plural, sanitize,
} from './clientcerts/certUtils';

// Each tab is the server's own list for that status (same calls as the classic page).
const TABS = [
  { key: 'all', label: 'All', path: `${BASE}/` },
  { key: 'active', label: 'Active', path: `${BASE}/active/` },
  { key: 'expired', label: 'Expired', path: `${BASE}/expired/` },
  { key: 'replaced', label: 'Replaced', path: `${BASE}/replaced/` },
  { key: 'revoked', label: 'Revoked', path: `${BASE}/revoked/` },
];

const CRL_NOTE = 'Revoked certificates are refused at connection only after the server reloads its revocation list, which this deployment does when it starts.';

const asList = (v) => (Array.isArray(v) ? v.map(sanitize) : []);

async function loadAll() {
  const lists = await Promise.all(TABS.map((t) => api.get(t.path)));
  return Object.fromEntries(TABS.map((t, i) => [t.key, asList(lists[i])]));
}

function DateCell({ value, warn }) {
  if (!value) return <Typography variant="body2" color="text.secondary" component="span">Not set</Typography>;
  return (
    <Tooltip title={formatFull(value)}>
      <Box sx={{ lineHeight: 1.25, py: 0.5 }}>
        <Typography variant="body2" component="div" color={warn ? 'warning.dark' : undefined} fontWeight={warn ? 600 : undefined}>
          {formatRelative(value)}
        </Typography>
        <Typography variant="caption" color="text.secondary" component="div">{formatAbsolute(value)}</Typography>
      </Box>
    </Tooltip>
  );
}

export default function ClientCerts() {
  const notify = useNotify();
  const { data, error, loading, reload } = useApi(loadAll, []);
  const [tab, setTab] = useState('all');
  const [search, setSearch] = useState('');
  const [selection, setSelection] = useState([]);
  const [detailRow, setDetail] = useState(null);
  const [confirm, setConfirm] = useState(null); // { kind: 'revoke'|'delete', rows, single }
  const [busy, setBusy] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const replacedIds = useMemo(() => new Set((data?.replaced || []).map((c) => c.id)), [data]);

  const statusOf = (row) => deriveStatus(row, replacedIds);

  const rows = useMemo(() => {
    const list = data?.[tab] || [];
    const q = search.trim().toLowerCase();
    const mapped = list.map((c) => ({ ...c, _status: deriveStatus(c, replacedIds) }));
    if (!q) return mapped;
    return mapped.filter((c) => [c.subjectDn, c.userDn, c.creatorDn, c.clientUid, c.serialNumber, c.hash]
      .some((v) => v && String(v).toLowerCase().includes(q)));
  }, [data, tab, search, replacedIds]);

  const selectedRows = useMemo(() => {
    const ids = new Set(selection);
    return (data?.[tab] || []).filter((c) => ids.has(c.id));
  }, [data, tab, selection]);

  const revokable = selectedRows.filter((c) => statusOf(c) !== 'revoked');
  const alreadyRevoked = selectedRows.length - revokable.length;
  const n = selectedRows.length;
  const over = {
    download: n > LIMITS.download,
    delete: n > LIMITS.delete,
    revoke: revokable.length > LIMITS.revoke,
  };

  const changeTab = (_, v) => { setTab(v); setSelection([]); };

  // Fetch the zip in the page so a server error shows as a message instead of
  // navigating away and losing the selection.
  const download = async () => {
    if (!n || over.download) return;
    const ids = selectedRows.map((c) => seg(c.id)).join(',');
    setDownloading(true);
    try {
      const res = await fetch(`${BASE}/download/${ids}`, { credentials: 'same-origin' });
      const type = res.headers.get('content-type') || '';
      if (!res.ok || type.includes('text/html') || type.includes('json')) {
        throw new Error(res.ok
          ? 'The server didn\u2019t return a zip file. Your session may have ended; reload the page and try again.'
          : `Couldn\u2019t download the certificates (server returned ${res.status}).`);
      }
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement('a');
      a.href = url;
      a.download = 'client-certificates.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      notify(`Downloaded ${plural(n, 'certificate')} as a zip file`);
    } catch (e) {
      notify(e);
    } finally {
      setDownloading(false);
    }
  };

  const runConfirm = async () => {
    const { kind, rows: targets, single } = confirm;
    setBusy(true);
    try {
      if (kind === 'revoke') {
        if (single) {
          await api.del(`${BASE}/${seg(targets[0].hash)}`);
        } else {
          await api.del(`${BASE}/revoke/${targets.map((c) => seg(c.id)).join(',')}`);
        }
        notify(single
          ? `Revoked the certificate for ${commonName(targets[0].subjectDn)}`
          : `Revoked ${plural(targets.length, 'certificate')}`);
      } else {
        await api.del(`${BASE}/delete/${targets.map((c) => seg(c.id)).join(',')}`);
        notify(single
          ? `Deleted the certificate record for ${commonName(targets[0].subjectDn)}`
          : `Deleted ${plural(targets.length, 'certificate record')}`);
        setDetail(null);
      }
      setSelection([]);
    } catch (e) {
      if (kind === 'revoke') {
        notify(new Error(`Revocation failed or only partly worked (${e.message}). The server marks certificates revoked before it updates the revocation list, so some may show as revoked without being in it. Check the server log, then try again.`));
      } else {
        notify(new Error(`Couldn’t delete the certificate records: ${e.message}`));
      }
    } finally {
      setBusy(false);
      setConfirm(null);
      reload(true);
    }
  };

  const columns = [
    {
      field: 'user',
      headerName: 'User',
      flex: 1.2,
      minWidth: 170,
      valueGetter: (_, row) => commonName(row.subjectDn),
      renderCell: ({ value, row }) => (
        <Tooltip title={row.subjectDn || ''}>
          <Link component="button" type="button" variant="body2" onClick={() => setDetail(row)} sx={{ textAlign: 'left' }}>
            {value || 'Unnamed certificate'}
          </Link>
        </Tooltip>
      ),
    },
    { field: 'clientUid', headerName: 'Device UID', flex: 1, minWidth: 150 },
    {
      field: 'serialNumber',
      headerName: 'Serial',
      minWidth: 140,
      flex: 0.8,
      renderCell: ({ value }) => (
        <Box component="span" sx={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12 }}>{value}</Box>
      ),
    },
    {
      field: 'creator',
      headerName: 'Created by',
      minWidth: 140,
      flex: 0.8,
      valueGetter: (_, row) => commonName(row.creatorDn),
      renderCell: ({ value, row }) => <Tooltip title={row.creatorDn || ''}><span>{value}</span></Tooltip>,
    },
    {
      field: 'issuanceDate',
      headerName: 'Issued',
      type: 'date',
      width: 130,
      valueGetter: (v) => parseDate(v),
      renderCell: ({ value }) => <DateCell value={value} />,
    },
    {
      field: 'expirationDate',
      headerName: 'Expires',
      type: 'date',
      width: 130,
      valueGetter: (v) => parseDate(v),
      renderCell: ({ value, row }) => <DateCell value={value} warn={row._status === 'expiring'} />,
    },
    {
      field: '_status',
      headerName: 'Status',
      width: 125,
      renderCell: ({ value }) => <StatusChip status={value} />,
    },
  ];

  // Follow the latest server copy of the open certificate so its status updates after a revoke.
  const detail = detailRow ? ((data?.all || []).find((c) => c.id === detailRow.id) || detailRow) : null;
  const counts = Object.fromEntries(TABS.map((t) => [t.key, data?.[t.key]?.length ?? 0]));
  const detailStatus = detail ? statusOf(detail) : null;

  const confirmBody = confirm && (confirm.kind === 'revoke' ? (
    <>
      <Typography variant="body2" sx={{ mb: 1 }}>
        {confirm.single
          ? `Revoke the certificate for ${confirm.rows[0].subjectDn}? The device is disconnected and can’t use this certificate again. This can’t be undone.`
          : `Revoke ${plural(confirm.rows.length, 'certificate')}? Each device is disconnected and can’t use its certificate again. This can’t be undone.`}
      </Typography>
      {!confirm.single && alreadyRevoked > 0 && (
        <Typography variant="body2" sx={{ mb: 1 }}>{plural(alreadyRevoked, 'selected certificate')} already revoked will be skipped.</Typography>
      )}
      <Typography variant="body2" color="text.secondary">{CRL_NOTE}</Typography>
    </>
  ) : (
    <>
      <Typography variant="body2" sx={{ mb: 1 }}>
        {confirm.single
          ? `Delete the record for ${confirm.rows[0].subjectDn}? It is removed from this list.`
          : `Delete ${plural(confirm.rows.length, 'certificate record')}? They are removed from this list.`}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        Deleting does not revoke a certificate. Revoke it first if the device should lose access.
      </Typography>
    </>
  ));

  return (
    <Box sx={{ minWidth: 0 }}>
      <PageHeader
        title="Client certificates"
        description="Certificates this server has issued to users and devices. Download, revoke or remove them."
        actions={<Button startIcon={<RefreshIcon />} onClick={() => reload()} disabled={loading}>Refresh</Button>}
      />

      <Tabs value={tab} onChange={changeTab} variant="scrollable" allowScrollButtonsMobile aria-label="Certificate status" sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}>
        {TABS.map((t) => <Tab key={t.key} value={t.key} label={data ? `${t.label} (${counts[t.key]})` : t.label} />)}
      </Tabs>

      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}

      {data && (
        <>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems={{ md: 'center' }} sx={{ mb: 1.5 }}>
            <TextField
              placeholder="Search user, DN, device UID, serial"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              inputProps={{ 'aria-label': 'Search certificates' }}
              InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
              sx={{ width: { xs: '100%', md: 340 } }}
            />
            <Box sx={{ flex: 1 }} />
            {n > 0 && (
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography variant="body2" color="text.secondary">{n} selected</Typography>
                <Button size="small" variant="outlined" onClick={download} disabled={over.download || downloading}>
                  Download {plural(n, 'certificate')}
                </Button>
                <Button
                  size="small" variant="outlined" color="error"
                  disabled={revokable.length === 0 || over.revoke}
                  onClick={() => setConfirm({ kind: 'revoke', rows: revokable })}
                >
                  Revoke {plural(revokable.length, 'certificate')}
                </Button>
                <Button size="small" color="error" disabled={over.delete} onClick={() => setConfirm({ kind: 'delete', rows: selectedRows })}>
                  Delete {plural(n, 'record')}
                </Button>
                <Button size="small" onClick={() => setSelection([])}>Clear selection</Button>
              </Stack>
            )}
          </Stack>

          {(over.download || over.delete || over.revoke) && (
            <Alert severity="warning" sx={{ mb: 1.5 }}>
              {n} certificates are selected. The server accepts up to {LIMITS.download} per download or delete and {LIMITS.revoke} per revocation
              {over.revoke && !over.download ? ` (${revokable.length} would be revoked)` : ''}. Select fewer and run it in batches.
            </Alert>
          )}
          {n > 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{CRL_NOTE}</Typography>
          )}

          {(data[tab] || []).length === 0 ? (
            <EmptyState
              title={tab === 'all' ? 'No client certificates yet' : `No ${TABS.find((t) => t.key === tab).label.toLowerCase()} certificates`}
              body={tab === 'all'
                ? 'Certificates appear here once users or devices enroll, or an admin issues one.'
                : 'Switch to All to see every certificate this server knows about.'}
              action={tab !== 'all' && <Button variant="outlined" onClick={() => changeTab(null, 'all')}>Show all certificates</Button>}
            />
          ) : (
            <Paper variant="outlined" sx={{ width: '100%', minWidth: 0, border: 0 }}>
              <DataGrid
                rows={rows}
                columns={columns}
                getRowId={(r) => r.id}
                autoHeight
                getRowHeight={() => 'auto'}
                checkboxSelection
                rowSelectionModel={selection}
                onRowSelectionModelChange={(m) => setSelection(m)}
                getRowClassName={(p) => (p.row._status === 'expiring' ? 'row-expiring' : '')}
                initialState={{
                  sorting: { sortModel: [{ field: 'issuanceDate', sort: 'desc' }] },
                  pagination: { paginationModel: { pageSize: 50 } },
                }}
                pageSizeOptions={[25, 50, 100]}
                localeText={{ noRowsLabel: 'No certificates match your search.', noResultsOverlayLabel: 'No certificates match your search.' }}
                sx={(theme) => ({
                  '& .row-expiring': { backgroundColor: alpha(theme.palette.warning.main, 0.08) },
                  '& .row-expiring:hover': { backgroundColor: alpha(theme.palette.warning.main, 0.14) },
                  '& .MuiDataGrid-cell': { display: 'flex', alignItems: 'center' },
                })}
              />
            </Paper>
          )}
        </>
      )}

      <CertDetailDrawer
        row={detail}
        status={detailStatus}
        onClose={() => setDetail(null)}
        onRevoke={(c) => setConfirm({ kind: 'revoke', rows: [c], single: true })}
        onDelete={(c) => setConfirm({ kind: 'delete', rows: [c], single: true })}
      />

      <ConfirmDialog
        open={!!confirm}
        title={confirm ? (confirm.kind === 'revoke'
          ? (confirm.single ? 'Revoke certificate' : `Revoke ${plural(confirm.rows.length, 'certificate')}`)
          : (confirm.single ? 'Delete certificate record' : `Delete ${plural(confirm.rows.length, 'certificate record')}`)) : ''}
        body={confirmBody}
        confirmLabel={confirm ? (confirm.kind === 'revoke'
          ? (confirm.single ? 'Revoke certificate' : `Revoke ${plural(confirm.rows.length, 'certificate')}`)
          : (confirm.single ? 'Delete record' : `Delete ${plural(confirm.rows.length, 'record')}`)) : ''}
        typeToConfirm={confirm && confirm.rows.length > 1 ? (confirm.kind === 'revoke' ? 'REVOKE' : 'DELETE') : undefined}
        busy={busy}
        onConfirm={runConfirm}
        onClose={() => setConfirm(null)}
      />
    </Box>
  );
}
