import React, { useMemo, useState } from 'react';
import { Box, Button, Stack, Typography } from '@mui/material';
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
import EditInputDialog from './EditInputDialog';
import { ClientsChip, FlagChip } from './common';
import { PROTOCOL_SHORT, authLabel, formatBytes, num, tlsDisplay } from './model';

/** Inputs (server ports) table with add, edit and delete. */
export default function InputsTab({ inputs, all, secConfig, reload }) {
  const notify = useNotify();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const [busy, setBusy] = useState(false);

  const rows = useMemo(() => inputs.map((m) => ({
    id: m.input.name,
    ...m.input,
    readsReceived: num(m.readsReceived),
    messagesReceived: num(m.messagesReceived),
    numClients: num(m.numClients),
    bytesRecieved: num(m.bytesRecieved),
    tlsShown: tlsDisplay(m.input, secConfig),
    groupsShown: (m.input.filtergroup || []).join(', '),
  })), [inputs, secConfig]);

  const columns = useMemo(() => [
    { field: 'name', headerName: 'Name', minWidth: 150, flex: 1 },
    {
      field: 'protocol', headerName: 'Protocol', width: 100,
      valueFormatter: (v) => PROTOCOL_SHORT[String(v || '').toLowerCase()] || v,
    },
    { field: 'port', headerName: 'Port', type: 'number', width: 80, align: 'left', headerAlign: 'left', valueFormatter: (v) => String(v) },
    { field: 'auth', headerName: 'Authentication', width: 120, valueFormatter: (v) => authLabel(v) },
    {
      field: 'numClients', headerName: 'Status', type: 'number', width: 130, align: 'left', headerAlign: 'left',
      renderCell: (p) => <ClientsChip count={p.value} />,
    },
    { field: 'groupsShown', headerName: 'Filter groups', minWidth: 160, flex: 1, renderCell: (p) => p.value || <Typography variant="body2" color="text.secondary" component="span">None</Typography> },
    { field: 'coreVersion', headerName: 'Core version', width: 100 },
    { field: 'tlsShown', headerName: 'TLS', width: 150 },
    { field: 'archive', headerName: 'Archive', width: 90, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'archiveOnly', headerName: 'Archive only', width: 105, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'federated', headerName: 'Federated', width: 95, renderCell: (p) => <FlagChip value={p.value} /> },
    { field: 'anongroup', headerName: 'Anonymous group', width: 130, renderCell: (p) => <FlagChip value={p.value} /> },
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
      await api.del(`/Marti/api/inputs/${seg(row.name)}`);
      notify(`Deleted input “${row.name}” (port ${row.port})`);
      setDeleting(null);
      reload(true);
    } catch (err) {
      notify(err);
    } finally {
      setBusy(false);
    }
  };

  const addButton = <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>Add input</Button>;

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ sm: 'center' }} sx={{ mb: 2 }}>
        <Typography color="text.secondary" sx={{ maxWidth: 680 }}>
          Ports the server listens on for TAK clients. Counts refresh every few seconds.
        </Typography>
        {rows.length > 0 && addButton}
      </Stack>

      {rows.length === 0 ? (
        <EmptyState
          title="No inputs configured"
          body="Clients can’t connect until the server listens on at least one port."
          action={addButton}
        />
      ) : (
        <Box sx={{ width: '100%', overflowX: 'auto' }}>
          <DataGrid
            rows={rows}
            columns={columns}
            autoHeight
            slots={{ toolbar: GridToolbar }}
            initialState={{
              sorting: { sortModel: [{ field: 'port', sort: 'asc' }] },
              columns: {
                columnVisibilityModel: {
                  coreVersion: false, anongroup: false, group: false, iface: false, readsReceived: false, bytesRecieved: false,
                },
              },
              pagination: { paginationModel: { pageSize: 25 } },
            }}
            pageSizeOptions={[25, 50, 100]}
            localeText={{ noResultsOverlayLabel: 'No inputs match your search.' }}
            sx={{ minWidth: 0 }}
          />
        </Box>
      )}

      <CreateDialog
        open={creating} kind="input" existing={all}
        onClose={() => setCreating(false)}
        onCreated={() => { setCreating(false); reload(true); }}
      />
      <EditInputDialog
        name={editing}
        onClose={() => setEditing(null)}
        onSaved={() => { setEditing(null); reload(true); }}
      />
      <ConfirmDialog
        open={!!deleting}
        title={deleting ? `Delete input “${deleting.name}”?` : ''}
        body={deleting && (
          <>
            The server stops listening on {PROTOCOL_SHORT[String(deleting.protocol).toLowerCase()] || deleting.protocol} port {deleting.port} right away.{' '}
            {deleting.numClients > 0
              ? <strong>{deleting.numClients === 1 ? '1 connected client' : `${deleting.numClients} connected clients`} on this port will be disconnected</strong>
              : 'Any clients that connect on this port will be disconnected'}
            {' '}and can’t reconnect until you add an input on this port again.
          </>
        )}
        confirmLabel={deleting ? `Delete input on port ${deleting.port}` : 'Delete'}
        busy={busy}
        onConfirm={doDelete}
        onClose={() => setDeleting(null)}
      />
    </Box>
  );
}
