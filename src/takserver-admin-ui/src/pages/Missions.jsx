import React, { useEffect, useMemo, useState } from 'react';
import {
  Box, Button, Chip, InputAdornment, MenuItem, Stack, TextField, Tooltip, Typography,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import AddIcon from '@mui/icons-material/Add';
import SearchIcon from '@mui/icons-material/Search';
import RefreshIcon from '@mui/icons-material/Refresh';
import LockIcon from '@mui/icons-material/LockOutlined';
import { api } from '../api/client';
import { useApi } from '../api/useApi';
import PageHeader from '../components/PageHeader';
import ConfirmDialog from '../components/ConfirmDialog';
import { EmptyState, ErrorState } from '../components/States';
import { useNotify } from '../components/Notify';
import CreateMissionDialog from './missions/CreateMissionDialog';
import SendMissionDialog from './missions/SendMissionDialog';
import MissionDetail from './missions/MissionDetail';
import {
  asArray, expirationDate, formatDate, missionPath, parseDate, plural, text,
} from './missions/missionUtils';

// Grid field -> database column the server sorts by (pagedmissions uses native SQL).
const SORT_COLUMNS = {
  name: 'name',
  creatorUid: 'creatoruid',
  createTime: 'create_time',
  tool: 'tool',
  expiration: 'expiration',
};

// Each search mode maps to one pagedmissions filter; the server applies only one at a time.
const SEARCH_BY = [
  { value: 'name', label: 'Name', param: 'nameFilter', hint: 'Part of the mission name (case sensitive)' },
  { value: 'uid', label: 'Item UID', param: 'uidFilter', hint: 'Part of an item UID in the mission' },
  { value: 'tool', label: 'Tool', param: 'tool', hint: 'Exact tool, for example public or vbm' },
];

const PAGE_SIZES = [25, 50, 100];

function toRow(m, i) {
  const contents = asArray(m.contents);
  const uids = asArray(m.uids);
  return {
    id: text(m.guid) || `${text(m.name)}#${i}`,
    name: text(m.name),
    description: text(m.description),
    creatorUid: text(m.creatorUid),
    createTime: parseDate(m.createTime),
    groups: asArray(m.groups).map(text),
    tool: text(m.tool),
    contentCount: contents.length,
    uidCount: uids.length,
    expiration: expirationDate(m.expiration),
    passwordProtected: m.passwordProtected === true,
  };
}

const hidden = (row) => row.passwordProtected && row.contentCount === 0 && row.uidCount === 0;

export default function Missions() {
  const notify = useNotify();
  const [pagination, setPagination] = useState({ page: 0, pageSize: 25 });
  const [sortModel, setSortModel] = useState([{ field: 'createTime', sort: 'desc' }]);
  const [searchBy, setSearchBy] = useState('name');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null); // mission name shown in the drawer
  const [createOpen, setCreateOpen] = useState(false);
  const [sendMode, setSendMode] = useState(null); // 'send' | 'invite'
  const [toDelete, setToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  // Debounce typing so each keystroke doesn't hit the server.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(searchInput.trim());
      setPagination((p) => (p.page === 0 ? p : { ...p, page: 0 }));
    }, 350);
    return () => clearTimeout(t);
  }, [searchInput]);

  const mode = SEARCH_BY.find((s) => s.value === searchBy) || SEARCH_BY[0];
  const sort = sortModel[0];
  const filtered = !!search;

  const list = useApi(() => api.get('/Marti/api/pagedmissions', {
    query: {
      passwordProtected: true,
      defaultRole: true,
      page: pagination.page,
      pagesize: pagination.pageSize,
      sort: sort && SORT_COLUMNS[sort.field],
      ascending: sort ? sort.sort === 'asc' : undefined,
      [mode.param]: search || undefined,
    },
  }), [pagination.page, pagination.pageSize, sort?.field, sort?.sort, mode.param, search, refreshKey]);

  // missioncount ignores every filter, so it only sizes the unfiltered list.
  const count = useApi(
    () => api.get('/Marti/api/missioncount', { query: { passwordProtected: true, defaultRole: true } }),
    [refreshKey],
  );

  // Searching by item UID can return one row per matching UID for the same
  // mission; keep the first so row ids stay unique.
  const rows = useMemo(() => {
    const seen = new Set();
    return asArray(list.data).filter((m) => {
      const g = text(m.guid);
      if (!g) return true;
      if (seen.has(g)) return false;
      seen.add(g);
      return true;
    }).map(toRow);
  }, [list.data]);
  const pageFull = rows.length === pagination.pageSize;
  const offset = pagination.page * pagination.pageSize;

  let rowCount;
  if (filtered || typeof count.data !== 'number') {
    rowCount = pageFull ? -1 : offset + rows.length;
  } else {
    rowCount = pageFull ? Math.max(count.data, offset + rows.length) : offset + rows.length;
  }
  const paginationMeta = useMemo(() => ({ hasNextPage: pageFull }), [pageFull]);

  const refresh = () => setRefreshKey((k) => k + 1);

  async function confirmDelete() {
    const name = toDelete;
    setDeleting(true);
    try {
      await api.del(missionPath(name));
      notify(`Deleted mission ${name}`);
      setToDelete(null);
      if (selected === name) setSelected(null);
      refresh();
    } catch (err) {
      notify(err);
    } finally {
      setDeleting(false);
    }
  }

  const columns = useMemo(() => [
    {
      field: 'name', headerName: 'Name', flex: 1.4, minWidth: 200,
      renderCell: ({ row }) => (
        <Stack direction="row" spacing={0.75} alignItems="center" sx={{ minWidth: 0, height: '100%' }}>
          <Typography variant="body2" fontWeight={500} noWrap title={row.name}>{row.name}</Typography>
          {row.passwordProtected && (
            <Chip size="small" variant="outlined" color="warning" icon={<LockIcon />} label="Password" sx={{ flexShrink: 0 }} />
          )}
        </Stack>
      ),
    },
    { field: 'creatorUid', headerName: 'Creator', flex: 1, minWidth: 140, valueFormatter: (v) => v || '—' },
    {
      field: 'createTime', headerName: 'Created', width: 170,
      valueFormatter: (v) => (v ? formatDate(v) : ''),
    },
    {
      field: 'groups', headerName: 'Groups', flex: 1, minWidth: 160, sortable: false,
      valueFormatter: (v) => (Array.isArray(v) ? v.join(', ') : ''),
      renderCell: ({ value }) => (
        <Tooltip title={value.join(', ')}>
          <Typography variant="body2" noWrap>{value.length ? value.join(', ') : '—'}</Typography>
        </Tooltip>
      ),
    },
    { field: 'tool', headerName: 'Tool', width: 100 },
    {
      field: 'contentCount', headerName: 'Files', type: 'number', width: 80, sortable: false,
      renderCell: ({ row }) => (hidden(row)
        ? <Tooltip title="Hidden for password-protected missions"><span>—</span></Tooltip>
        : row.contentCount),
    },
    {
      field: 'uidCount', headerName: 'Items', type: 'number', width: 80, sortable: false,
      renderCell: ({ row }) => (hidden(row)
        ? <Tooltip title="Hidden for password-protected missions"><span>—</span></Tooltip>
        : row.uidCount),
    },
    {
      field: 'expiration', headerName: 'Expires', width: 170,
      renderCell: ({ value }) => {
        if (!value) return <Typography variant="body2" color="text.secondary" component="span">Never</Typography>;
        const past = value.getTime() < Date.now();
        return past
          ? <Chip size="small" variant="outlined" color="error" label={`Expired ${formatDate(value)}`} />
          : formatDate(value);
      },
    },
  ], []);

  const firstLoad = list.loading && list.data === undefined;
  const noMissions = !filtered && !list.loading && !list.error && rows.length === 0 && pagination.page === 0;

  return (
    <Box>
      <PageHeader
        title="Missions"
        description="Data sync missions shared with TAK clients: who can see them, what they hold, and who is subscribed."
        actions={(
          <>
            <Button startIcon={<RefreshIcon />} onClick={refresh}>Refresh</Button>
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>Create mission</Button>
          </>
        )}
      />

      {noMissions ? (
        <EmptyState
          title="No missions yet"
          body="Create a mission to share files, map items and data feeds with a group of TAK clients."
          action={<Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>Create mission</Button>}
        />
      ) : (
        <>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }} alignItems={{ sm: 'flex-start' }}>
            <TextField
              select label="Search by" value={searchBy} sx={{ minWidth: 140 }}
              onChange={(e) => { setSearchBy(e.target.value); setPagination((p) => ({ ...p, page: 0 })); }}
            >
              {SEARCH_BY.map((s) => <MenuItem key={s.value} value={s.value}>{s.label}</MenuItem>)}
            </TextField>
            <TextField
              label={`Search missions by ${mode.label.toLowerCase()}`} value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              helperText={mode.hint}
              sx={{ flex: 1, maxWidth: { sm: 420 } }}
              InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
            />
          </Stack>

          {list.error && <ErrorState error={list.error} onRetry={() => list.reload()} />}

          <Box sx={{ width: '100%', overflowX: 'auto' }}>
            <DataGrid
              autoHeight
              rows={rows}
              columns={columns}
              loading={list.loading}
              paginationMode="server"
              sortingMode="server"
              filterMode="server"
              disableColumnFilter
              paginationModel={pagination}
              onPaginationModelChange={setPagination}
              pageSizeOptions={PAGE_SIZES}
              rowCount={rowCount}
              paginationMeta={paginationMeta}
              sortModel={sortModel}
              onSortModelChange={(m) => { setSortModel(m); setPagination((p) => ({ ...p, page: 0 })); }}
              onRowClick={({ row }) => setSelected(row.name)}
              getRowClassName={() => 'mission-row'}
              localeText={{
                noRowsLabel: filtered ? `No missions match “${search}”.` : 'No missions on this page.',
              }}
              sx={{
                minWidth: 880,
                '& .mission-row': { cursor: 'pointer' },
                '& .MuiDataGrid-cell:focus-within': { outline: 'none' },
              }}
            />
          </Box>
          {!firstLoad && typeof count.data === 'number' && !filtered && (
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {plural(count.data, 'mission')} on the server. Select a row to see files, subscribers and recent changes.
            </Typography>
          )}
        </>
      )}

      <MissionDetail
        name={selected}
        onClose={() => setSelected(null)}
        onDelete={() => setToDelete(selected)}
        onSend={() => setSendMode('send')}
        onInvite={() => setSendMode('invite')}
      />

      <CreateMissionDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(name) => {
          setCreateOpen(false);
          notify(`Created mission ${name}`);
          refresh();
          setSelected(name);
        }}
      />

      <SendMissionDialog mode={sendMode} missionName={selected || ''} onClose={() => setSendMode(null)} />

      <ConfirmDialog
        open={!!toDelete}
        title={`Delete mission ${toDelete || ''}?`}
        body="Every client loses the mission and its subscriptions. The server first saves an archive copy, listed under Archived missions in the classic manager; files themselves stay on the server."
        confirmLabel="Delete mission"
        typeToConfirm={toDelete || undefined}
        busy={deleting}
        onConfirm={confirmDelete}
        onClose={() => setToDelete(null)}
      />
    </Box>
  );
}
