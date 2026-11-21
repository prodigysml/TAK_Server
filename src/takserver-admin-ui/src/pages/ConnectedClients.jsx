import React, { useCallback, useMemo, useState } from 'react';
import {
  Alert, Box, Button, Chip, FormControl, InputAdornment, InputLabel, Link, MenuItem, Paper, Select, Stack,
  TextField, Tooltip, Typography,
} from '@mui/material';
import {
  DataGrid, GridActionsCellItem, GridToolbarColumnsButton, GridToolbarContainer, GridToolbarExport,
} from '@mui/x-data-grid';
import SearchIcon from '@mui/icons-material/Search';
import PauseIcon from '@mui/icons-material/Pause';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import RefreshIcon from '@mui/icons-material/Refresh';
import AddIcon from '@mui/icons-material/Add';
import PageHeader from '../components/PageHeader';
import ConfirmDialog from '../components/ConfirmDialog';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { useNotify } from '../components/Notify';
import { api, seg } from '../api/client';
import { usePolling } from '../api/useApi';
import ClientDrawer from './connectedclients/ClientDrawer';
import AddSubscriptionDialog from './connectedclients/AddSubscriptionDialog';
import {
  PAGE_LIMIT, formatAgo, formatTime, loadColumnPrefs, matches, saveColumnPrefs, toRows,
} from './connectedclients/model';

const POLL_MS = 10000;
const ALL = '__all__';

const DEFAULT_VISIBILITY = {
  dn: false, clientUid: false, subscriptionUid: false, xpath: false, deviceIPAddress: false,
  battery: false, batteryStatus: false, batteryTemp: false, deviceDataRx: false, deviceDataTx: false,
  appFramerate: false, heapCurrentSize: false, heapFreeSize: false, heapMaxSize: false,
  storageAvailable: false, storageTotal: false,
};

const nameOf = (r) => r.callsign || r.clientUid || r.subscriptionUid || 'unnamed client';

function GridToolbar() {
  return (
    <GridToolbarContainer sx={{ px: 1, pt: 0.5 }}>
      <GridToolbarColumnsButton />
      <GridToolbarExport csvOptions={{ fileName: 'connected-clients' }} printOptions={{ disableToolbarButton: true }} />
    </GridToolbarContainer>
  );
}

export default function ConnectedClients() {
  const notify = useNotify();
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState('');
  const [groupFilter, setGroupFilter] = useState(ALL);
  const [protocolFilter, setProtocolFilter] = useState(ALL);
  const [selection, setSelection] = useState([]);
  const [detailId, setDetailId] = useState(null);
  const [confirm, setConfirm] = useState(null); // rows to disconnect
  const [busy, setBusy] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [columnVisibility, setColumnVisibility] = useState(() => loadColumnPrefs(DEFAULT_VISIBILITY));

  const { data, error, loading, reload } = usePolling(async () => {
    const subs = await api.get('/Marti/api/subscriptions/all', {
      query: { sortBy: 'CALLSIGN', direction: 'ASCENDING', page: 1, limit: PAGE_LIMIT },
    });
    return { subs: Array.isArray(subs) ? subs : [], at: Date.now() };
  }, paused ? 0 : POLL_MS);

  const rows = useMemo(() => toRows(data?.subs), [data]);
  const byId = useMemo(() => new Map(rows.map((r) => [r.id, r])), [rows]);

  const protocols = useMemo(() => {
    const m = new Map();
    rows.forEach((r) => m.set(r._protocol, (m.get(r._protocol) || 0) + 1));
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [rows]);
  const groupNames = useMemo(() => {
    const s = new Set();
    rows.forEach((r) => r._groups.forEach((g) => s.add(g.name)));
    return [...s].sort((a, b) => a.localeCompare(b));
  }, [rows]);
  const healthCounts = useMemo(() => {
    const c = { current: 0, stale: 0, dead: 0, none: 0, incognito: 0 };
    rows.forEach((r) => { c[r._health.key] += 1; if (r.incognito) c.incognito += 1; });
    return c;
  }, [rows]);

  const filtered = useMemo(() => rows.filter((r) => matches(r, search)
    && (groupFilter === ALL || r._groups.some((g) => g.name === groupFilter))
    && (protocolFilter === ALL || r._protocol === protocolFilter)), [rows, search, groupFilter, protocolFilter]);

  // Only rows the admin can currently see count as selected: a filter change must
  // never leave hidden clients queued for disconnect.
  const visibleIds = useMemo(() => new Set(filtered.map((r) => r.id)), [filtered]);
  const selectedRows = selection.filter((id) => visibleIds.has(id)).map((id) => byId.get(id)).filter((r) => r && r.subscriptionUid);
  const detailRow = detailId ? byId.get(detailId) : null;

  const askDisconnect = useCallback((targets) => setConfirm(targets.filter((r) => r.subscriptionUid)), []);

  const doDisconnect = async () => {
    const targets = confirm || [];
    setBusy(true);
    const failed = [];
    // One call per client, the same call the classic dashboard makes.
    for (const r of targets) {
      try {
        await api.del(`/Marti/api/subscriptions/delete/${seg(r.subscriptionUid)}`);
      } catch {
        failed.push(r);
      }
    }
    setBusy(false);
    setConfirm(null);
    const ok = targets.length - failed.length;
    if (failed.length === 0) {
      notify(targets.length === 1 ? `Disconnected ${nameOf(targets[0])}` : `Disconnected ${ok} clients`);
    } else {
      const names = failed.slice(0, 5).map(nameOf).join(', ') + (failed.length > 5 ? ` and ${failed.length - 5} more` : '');
      notify(new Error(ok
        ? `Disconnected ${ok} of ${targets.length} clients. Couldn’t disconnect ${names}; they may have already left. Refresh and try again.`
        : `Couldn’t disconnect ${names}. The client may have already left; refresh and try again.`));
    }
    const failedIds = new Set(failed.map((r) => r.id));
    setSelection((sel) => sel.filter((id) => failedIds.has(id)));
    if (detailId && targets.some((r) => r.id === detailId) && !failedIds.has(detailId)) setDetailId(null);
    reload(true);
  };

  const toggleIncognito = useCallback(async (r) => {
    const turningOn = !r.incognito;
    setBusy(true);
    try {
      await api.post(`/Marti/api/subscriptions/incognito/${seg(r.subscriptionUid)}`);
      notify(`${turningOn ? 'Turned on' : 'Turned off'} incognito for ${nameOf(r)}`);
    } catch (err) {
      notify(new Error(`Couldn’t change incognito for ${nameOf(r)}. ${err.message}`));
    } finally {
      setBusy(false);
      reload(true);
    }
  }, [notify, reload]);

  const columns = useMemo(() => [
    {
      field: 'health', headerName: 'Health', width: 128,
      valueGetter: (v, row) => row._health.rank,
      renderCell: ({ row }) => <Chip size="small" variant="outlined" color={row._health.color} label={row._health.label} />,
    },
    {
      field: 'callsign', headerName: 'Callsign', minWidth: 160, flex: 1,
      renderCell: ({ row }) => (
        <Link component="button" type="button" underline="hover" onClick={(e) => { e.stopPropagation(); setDetailId(row.id); }}
          sx={{ textAlign: 'left', font: 'inherit' }}>
          {row.callsign || row.clientUid || '(no callsign)'}
        </Link>
      ),
    },
    { field: 'username', headerName: 'Username', minWidth: 130, flex: 0.8 },
    { field: 'team', headerName: 'Team', width: 100 },
    { field: 'role', headerName: 'Role', width: 120 },
    {
      field: 'groups', headerName: 'Groups', minWidth: 180, flex: 1, sortable: false,
      valueGetter: (v, row) => row._groupsText,
      renderCell: ({ row }) => (
        <Tooltip title={row._groupsText || ''}><span>{row._groupsText}</span></Tooltip>
      ),
    },
    { field: 'protocol', headerName: 'Protocol', width: 110, valueGetter: (v, row) => row._protocol },
    { field: 'endpoint', headerName: 'IP and port', width: 160, valueGetter: (v, row) => row._endpoint },
    {
      field: 'lastReportMilliseconds', headerName: 'Last report', width: 130, type: 'number', align: 'left', headerAlign: 'left',
      valueFormatter: (v, row) => (row.lastReportMilliseconds ? formatAgo(row.lastReportDiffMilliseconds) : 'Never'),
      renderCell: ({ row, formattedValue }) => (
        <Tooltip title={formatTime(row.lastReportMilliseconds) || 'No report yet'}><span>{formattedValue}</span></Tooltip>
      ),
    },
    { field: 'pendingWrites', headerName: 'Pending writes', type: 'number', width: 120 },
    { field: 'numProcessed', headerName: 'Processed', type: 'number', width: 110 },
    { field: 'client', headerName: 'TAK client', minWidth: 150, flex: 0.8, valueGetter: (v, row) => row._client },
    {
      field: 'incognito', headerName: 'Incognito', width: 110, type: 'boolean',
      renderCell: ({ row }) => (row.incognito ? <Chip size="small" color="warning" label="Incognito" /> : null),
    },
    { field: 'dn', headerName: 'DN', minWidth: 220 },
    { field: 'clientUid', headerName: 'Client UID', minWidth: 200 },
    { field: 'subscriptionUid', headerName: 'Subscription UID', minWidth: 220 },
    { field: 'xpath', headerName: 'XPath', minWidth: 160 },
    { field: 'deviceIPAddress', headerName: 'Device IP', width: 140 },
    { field: 'battery', headerName: 'Battery', width: 90 },
    { field: 'batteryStatus', headerName: 'Battery status', width: 120 },
    { field: 'batteryTemp', headerName: 'Battery temp', width: 110 },
    { field: 'deviceDataRx', headerName: 'Data received', width: 120 },
    { field: 'deviceDataTx', headerName: 'Data sent', width: 110 },
    { field: 'appFramerate', headerName: 'Frame rate', width: 100 },
    { field: 'heapCurrentSize', headerName: 'Heap current', width: 120 },
    { field: 'heapFreeSize', headerName: 'Heap free', width: 110 },
    { field: 'heapMaxSize', headerName: 'Heap max', width: 110 },
    { field: 'storageAvailable', headerName: 'Storage available', width: 140 },
    { field: 'storageTotal', headerName: 'Storage total', width: 120 },
    {
      field: 'actions', type: 'actions', headerName: 'Actions', width: 80, hideable: false,
      getActions: ({ row }) => (row.subscriptionUid ? [
        <GridActionsCellItem key="details" label="View details" showInMenu onClick={() => setDetailId(row.id)} />,
        <GridActionsCellItem key="incog" label={row.incognito ? 'Turn off incognito' : 'Turn on incognito'} showInMenu
          disabled={busy} onClick={() => toggleIncognito(row)} />,
        <GridActionsCellItem key="del" label="Disconnect client" showInMenu disabled={busy}
          onClick={() => askDisconnect([row])} sx={{ color: 'error.main' }} />,
      ] : [
        <GridActionsCellItem key="details" label="View details" showInMenu onClick={() => setDetailId(row.id)} />,
      ]),
    },
  ], [busy, toggleIncognito, askDisconnect]);

  const filtersActive = search || groupFilter !== ALL || protocolFilter !== ALL;
  const clearFilters = () => { setSearch(''); setGroupFilter(ALL); setProtocolFilter(ALL); };
  const truncated = rows.length >= PAGE_LIMIT;

  return (
    <Box sx={{ minWidth: 0 }}>
      <PageHeader
        title="Connected clients"
        description="Clients and static subscriptions on this server. Updates every 10 seconds."
        actions={(
          <>
            <Button
              variant="outlined" size="small"
              startIcon={paused ? <PlayArrowIcon /> : <PauseIcon />}
              onClick={() => { if (paused) reload(true); setPaused((p) => !p); }}
              aria-pressed={paused}
            >
              {paused ? 'Resume updates' : 'Pause updates'}
            </Button>
            <Button variant="outlined" size="small" startIcon={<RefreshIcon />} onClick={() => reload(true)}>Refresh now</Button>
            <Button variant="contained" size="small" startIcon={<AddIcon />} onClick={() => setAddOpen(true)}>Add static subscription</Button>
          </>
        )}
      />

      {loading && !data && <Loading />}
      {error && !data && <ErrorState error={error} onRetry={reload} />}

      {data && (
        <>
          {error && (
            <Alert severity="warning" sx={{ mb: 2 }} action={<Button color="inherit" size="small" onClick={() => reload(true)}>Try again</Button>}>
              Couldn’t refresh the client list: {error.message} Showing data from {new Date(data.at).toLocaleTimeString()}.
            </Alert>
          )}
          {truncated && (
            <Alert severity="info" sx={{ mb: 2 }}>
              Showing the first {PAGE_LIMIT.toLocaleString()} clients. The server returns at most {PAGE_LIMIT.toLocaleString()} per request; use the classic page to page through the rest.
            </Alert>
          )}

          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={{ xs: 1.5, md: 4 }} alignItems={{ md: 'center' }}>
              <Box>
                <Typography variant="body2" color="text.secondary">Total</Typography>
                <Typography variant="h2" component="p">{rows.length.toLocaleString()}</Typography>
              </Box>
              <Box sx={{ minWidth: 0 }}>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>By protocol</Typography>
                <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                  {protocols.length === 0 && <Typography variant="body2" color="text.secondary">None</Typography>}
                  {protocols.map(([p, n]) => (
                    <Chip
                      key={p} size="small" label={`${p}: ${n}`}
                      variant={protocolFilter === p ? 'filled' : 'outlined'}
                      color={protocolFilter === p ? 'primary' : 'default'}
                      onClick={() => setProtocolFilter(protocolFilter === p ? ALL : p)}
                      aria-pressed={protocolFilter === p}
                    />
                  ))}
                </Stack>
              </Box>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>Health</Typography>
                <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                  <Chip size="small" variant="outlined" color="success" label={`Reporting: ${healthCounts.current}`} />
                  <Chip size="small" variant="outlined" color="warning" label={`Quiet: ${healthCounts.stale}`} />
                  <Chip size="small" variant="outlined" color="error" label={`Not reporting: ${healthCounts.dead + healthCounts.none}`} />
                  {healthCounts.incognito > 0 && <Chip size="small" color="warning" label={`Incognito: ${healthCounts.incognito}`} />}
                </Stack>
              </Box>
              <Box sx={{ ml: { md: 'auto' } }}>
                <Typography variant="body2" color="text.secondary">
                  {paused ? 'Updates paused' : 'Live'} · updated {new Date(data.at).toLocaleTimeString()}
                </Typography>
              </Box>
            </Stack>
          </Paper>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 1.5 }} alignItems={{ sm: 'center' }} flexWrap="wrap" useFlexGap>
            <TextField
              value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search callsign, username, UID or IP"
              inputProps={{ 'aria-label': 'Search clients' }}
              sx={{ minWidth: { sm: 300 }, flex: { sm: '1 1 300px' }, maxWidth: { sm: 420 } }}
              InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
            />
            <FormControl size="small" sx={{ minWidth: 180 }}>
              <InputLabel id="cc-group-label">Group</InputLabel>
              <Select labelId="cc-group-label" label="Group" value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)}>
                <MenuItem value={ALL}>All groups</MenuItem>
                {groupNames.map((g) => <MenuItem key={g} value={g}>{g}</MenuItem>)}
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 160 }}>
              <InputLabel id="cc-proto-label">Protocol</InputLabel>
              <Select labelId="cc-proto-label" label="Protocol" value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)}>
                <MenuItem value={ALL}>All protocols</MenuItem>
                {protocols.map(([p]) => <MenuItem key={p} value={p}>{p}</MenuItem>)}
              </Select>
            </FormControl>
            {filtersActive && <Button size="small" onClick={clearFilters}>Clear filters</Button>}
            <Box sx={{ flexGrow: 1 }} />
            {selectedRows.length > 0 && (
              <Button size="small" variant="outlined" color="error" disabled={busy} onClick={() => askDisconnect(selectedRows)}>
                Disconnect {selectedRows.length === 1 ? '1 client' : `${selectedRows.length} clients`}
              </Button>
            )}
          </Stack>

          {rows.length === 0 ? (
            <EmptyState
              title="No clients are connected"
              body="When a TAK client connects through one of your inputs it shows up here within 10 seconds. You can also push traffic to a fixed address with a static subscription."
              action={<Button variant="contained" onClick={() => setAddOpen(true)}>Add static subscription</Button>}
            />
          ) : filtered.length === 0 ? (
            <EmptyState
              title="No clients match these filters"
              body={`${rows.length.toLocaleString()} connected, none match your search or filters.`}
              action={<Button onClick={clearFilters}>Clear filters</Button>}
            />
          ) : (
            <Box sx={{ width: '100%', overflowX: 'auto' }}>
              <DataGrid
                rows={filtered}
                columns={columns}
                autoHeight
                checkboxSelection
                isRowSelectable={({ row }) => !!row.subscriptionUid}
                rowSelectionModel={selection}
                onRowSelectionModelChange={setSelection}
                checkboxSelectionVisibleOnly
                onCellClick={({ field, row }) => { if (field !== '__check__' && field !== 'actions') setDetailId(row.id); }}
                columnVisibilityModel={columnVisibility}
                onColumnVisibilityModelChange={(m) => { setColumnVisibility(m); saveColumnPrefs(m); }}
                initialState={{
                  sorting: { sortModel: [{ field: 'callsign', sort: 'asc' }] },
                  pagination: { paginationModel: { pageSize: 50 } },
                }}
                pageSizeOptions={[25, 50, 100, 250]}
                getRowClassName={({ row }) => (row.incognito ? 'cc-incognito' : '')}
                slots={{ toolbar: GridToolbar }}
                localeText={{ noRowsLabel: 'No clients' }}
                sx={{
                  minWidth: 640,
                  '& .MuiDataGrid-row': { cursor: 'pointer' },
                  '& .cc-incognito': { bgcolor: 'action.hover' },
                }}
              />
            </Box>
          )}
        </>
      )}

      <ClientDrawer
        row={detailRow}
        busy={busy}
        onClose={() => setDetailId(null)}
        onDisconnect={askDisconnect}
        onToggleIncognito={toggleIncognito}
      />

      <AddSubscriptionDialog
        open={addOpen}
        notify={notify}
        onClose={() => setAddOpen(false)}
        onAdded={() => { setAddOpen(false); reload(true); }}
      />

      <ConfirmDialog
        open={!!confirm}
        busy={busy}
        title={confirm && confirm.length === 1 ? `Disconnect ${nameOf(confirm[0])}?` : `Disconnect ${confirm?.length || 0} clients?`}
        body={(
          <>
            The server drops {confirm && confirm.length === 1 ? 'this connection' : 'these connections'} now. A TAK client usually reconnects on its own unless its certificate or account is also revoked.
            If {confirm && confirm.length === 1 ? 'it is a static subscription, it is' : 'any are static subscriptions, they are'} also removed from the server configuration.
            {confirm && confirm.length > 1 && (
              <Box component="span" sx={{ display: 'block', mt: 1 }}>
                {confirm.slice(0, 8).map(nameOf).join(', ')}{confirm.length > 8 ? ` and ${confirm.length - 8} more` : ''}
              </Box>
            )}
          </>
        )}
        confirmLabel={confirm && confirm.length === 1 ? 'Disconnect client' : `Disconnect ${confirm?.length || 0} clients`}
        typeToConfirm={confirm && confirm.length > 1 ? 'DISCONNECT' : undefined}
        onConfirm={doDisconnect}
        onClose={() => setConfirm(null)}
      />
    </Box>
  );
}
