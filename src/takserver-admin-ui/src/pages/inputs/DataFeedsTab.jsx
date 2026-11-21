import React, { useMemo, useState } from 'react';
import { Box, Button, Chip, Stack, ToggleButton, ToggleButtonGroup, Typography } from '@mui/material';
import { DataGrid, GridActionsCellItem } from '@mui/x-data-grid';
import EditIcon from '@mui/icons-material/EditOutlined';
import DeleteIcon from '@mui/icons-material/DeleteOutline';
import AddIcon from '@mui/icons-material/Add';
import { api, seg } from '../../api/client';
import ConfirmDialog from '../../components/ConfirmDialog';
import { EmptyState } from '../../components/States';
import { useNotify } from '../../components/Notify';
import GridToolbar from './GridToolbar';
import CreateDialog from './CreateDialog';
import EditFeedDialog from './EditFeedDialog';
import { ClientsChip, FlagChip } from './common';
import { PROTOCOL_SHORT, authLabel, formatBytes, num, tlsDisplay } from './model';

const TYPES = ['All', 'Streaming', 'Plugin', 'Federation'];

/** Streaming, plugin and federation data feeds. Federation feeds are created by federation, not here. */
export default function DataFeedsTab({ feeds, all, secConfig, reload }) {
  const notify = useNotify();
  const [type, setType] = useState('All');
  const [creating, setCreating] = useState(null); // 'streaming' | 'plugin'
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const [busy, setBusy] = useState(false);

  const rows = useMemo(() => feeds
    .filter((m) => type === 'All' || m.input.type === type)
    .map((m) => ({
      id: m.input.name,
      ...m.input,
      readsReceived: num(m.readsReceived),
      messagesReceived: num(m.messagesReceived),
      numClients: num(m.numClients),
      bytesRecieved: num(m.bytesRecieved),
      tlsShown: tlsDisplay(m.input, secConfig),
      tagsShown: (m.input.tag || []).join(', '),
      groupsShown: (m.input.filtergroup || []).join(', '),
    })), [feeds, type, secConfig]);

  const counts = useMemo(() => {
    const c = { All: feeds.length };
    feeds.forEach((m) => { c[m.input.type] = (c[m.input.type] || 0) + 1; });
    return c;
  }, [feeds]);

  const isPlugin = (r) => r.type === 'Plugin';

  const columns = useMemo(() => [
    { field: 'name', headerName: 'Name', minWidth: 150, flex: 1 },
    { field: 'type', headerName: 'Type', width: 105, renderCell: (p) => <Chip size="small" variant="outlined" label={p.value} /> },
    {
      field: 'protocol', headerName: 'Protocol', width: 95,
      valueGetter: (v, r) => (isPlugin(r) ? '' : v),
      valueFormatter: (v) => PROTOCOL_SHORT[String(v || '').toLowerCase()] || v || '',
    },
    {
      field: 'port', headerName: 'Port', width: 75,
      valueGetter: (v, r) => (isPlugin(r) || !v ? null : v), valueFormatter: (v) => (v == null ? '' : String(v)),
    },
    { field: 'auth', headerName: 'Authentication', width: 120, valueGetter: (v, r) => (isPlugin(r) ? '' : authLabel(v)) },
    {
      field: 'numClients', headerName: 'Status', type: 'number', width: 130, align: 'left', headerAlign: 'left',
      renderCell: (p) => (isPlugin(p.row) ? null : <ClientsChip count={p.value} />),
    },
    { field: 'tagsShown', headerName: 'Tags', minWidth: 120, flex: 1 },
    { field: 'groupsShown', headerName: 'Filter groups', minWidth: 140, flex: 1 },
    { field: 'sync', headerName: 'Sync', width: 80, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'archive', headerName: 'Archive', width: 90, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'archiveOnly', headerName: 'Archive only', width: 105, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'federated', headerName: 'Federated', width: 95, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'anongroup', headerName: 'Anonymous group', width: 130, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'syncCacheRetentionSeconds', headerName: 'Sync cache (s)', type: 'number', width: 115 },
    { field: 'coreVersion', headerName: 'Core version', width: 100 },
    { field: 'tlsShown', headerName: 'TLS', width: 150 },
    { field: 'group', headerName: 'Multicast group', width: 130 },
    { field: 'iface', headerName: 'Interface', width: 100 },
    { field: 'messagesReceived', headerName: 'Messages received', type: 'number', width: 140 },
    { field: 'readsReceived', headerName: 'Reads received', type: 'number', width: 120 },
    { field: 'bytesRecieved', headerName: 'Bytes received', type: 'number', width: 120, valueFormatter: (v) => formatBytes(v) },
    {
      field: 'actions', type: 'actions', headerName: 'Actions', width: 90,
      getActions: (p) => [
        <GridActionsCellItem key="e" icon={<EditIcon />} label={`Edit ${p.row.name}`} onClick={() => setEditing(p.row.name)} />,
        <GridActionsCellItem key="d" icon={<DeleteIcon />} label={`Delete ${p.row.name}`} onClick={() => setDeleting(p.row)} />,
      ],
    },
  ], []);

  const doDelete = async () => {
    const row = deleting;
    setBusy(true);
    try {
      await api.del(`/Marti/api/datafeeds/${seg(row.name)}`);
      notify(`Deleted data feed “${row.name}”`);
      setDeleting(null);
      reload(true);
    } catch (err) {
      notify(err.status === 404 || err.status === 400
        ? new Error(`Data feed “${row.name}” wasn’t deleted. It may already be gone or isn’t shared with your groups. Reload the list and check.`)
        : err);
    } finally {
      setBusy(false);
    }
  };

  const addButtons = (
    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
      <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating('streaming')}>Add streaming feed</Button>
      <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setCreating('plugin')}>Add plugin feed</Button>
    </Stack>
  );

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ sm: 'center' }} sx={{ mb: 2 }}>
        <Typography color="text.secondary" sx={{ maxWidth: 680 }}>
          Feeds that bring data in from a port, a server plugin or a federated server, scoped to groups and tags.
          Federation feeds appear here once a federation creates them.
        </Typography>
        {feeds.length > 0 && addButtons}
      </Stack>

      {feeds.length === 0 ? (
        <EmptyState
          title="No data feeds yet"
          body="Add a streaming feed to take data in on its own port, or a plugin feed for a server plugin to publish to."
          action={addButtons}
        />
      ) : (
        <>
          <ToggleButtonGroup
            size="small" exclusive value={type} onChange={(_, v) => v && setType(v)} aria-label="Filter by feed type"
            sx={{ mb: 1.5, flexWrap: 'wrap' }}
          >
            {TYPES.map((t) => <ToggleButton key={t} value={t}>{t} ({counts[t] || 0})</ToggleButton>)}
          </ToggleButtonGroup>
          <Box sx={{ width: '100%', overflowX: 'auto' }}>
            <DataGrid
              rows={rows}
              columns={columns}
              autoHeight
              slots={{ toolbar: GridToolbar }}
              initialState={{
                sorting: { sortModel: [{ field: 'name', sort: 'asc' }] },
                columns: {
                  columnVisibilityModel: {
                    anongroup: false, syncCacheRetentionSeconds: false, coreVersion: false, tlsShown: false,
                    group: false, iface: false, readsReceived: false, bytesRecieved: false, archiveOnly: false,
                  },
                },
                pagination: { paginationModel: { pageSize: 25 } },
              }}
              pageSizeOptions={[25, 50, 100]}
              localeText={{ noRowsLabel: `No ${type.toLowerCase()} feeds.`, noResultsOverlayLabel: 'No feeds match your search.' }}
            />
          </Box>
        </>
      )}

      <CreateDialog
        open={!!creating} kind={creating || 'streaming'} existing={all}
        onClose={() => setCreating(null)}
        onCreated={() => { setCreating(null); reload(true); }}
      />
      <EditFeedDialog
        name={editing}
        onClose={() => setEditing(null)}
        onSaved={() => { setEditing(null); reload(true); }}
      />
      <ConfirmDialog
        open={!!deleting}
        title={deleting ? `Delete data feed “${deleting.name}”?` : ''}
        body={deleting && (
          isPlugin(deleting)
            ? 'Plugins publishing to this feed will stop delivering data to clients. Its tags and filter groups are removed too.'
            : (
              <>
                {deleting.port ? `The server stops listening on port ${deleting.port}. ` : ''}
                {deleting.numClients > 0
                  ? <strong>{deleting.numClients === 1 ? '1 connected client' : `${deleting.numClients} connected clients`} on this feed will be disconnected. </strong>
                  : null}
                Its tags and filter groups are removed too.
              </>
            )
        )}
        confirmLabel="Delete data feed"
        busy={busy}
        onConfirm={doDelete}
        onClose={() => setDeleting(null)}
      />
    </Box>
  );
}
