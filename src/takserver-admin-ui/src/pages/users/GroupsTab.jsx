import React, { useMemo, useState } from 'react';
import {
  Box, Button, InputAdornment, Paper, Stack, TextField, ToggleButton, ToggleButtonGroup, Typography,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import SearchIcon from '@mui/icons-material/Search';
import { useApi } from '../../api/useApi';
import { EmptyState, ErrorState } from '../../components/States';
import DirectionChip from './DirectionChip';
import { DIRECTION_HELP, usersApi } from './model';

// Groups as the file stores them: a group exists while at least one user is in it.
export default function GroupsTab({ groups, loading, onEditGroups, onShowUsers, onAddUser, reloadKey }) {
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null);
  const [dir, setDir] = useState('all');

  const groupRows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return groups.filter((g) => !q || g.toLowerCase().includes(q)).map((g) => ({ id: g, name: g }));
  }, [groups, search]);

  const members = useApi(
    () => (selected ? usersApi.usersInGroup(selected) : Promise.resolve(null)),
    [selected, reloadKey],
  );
  const memberRows = useMemo(
    () => (members.data || []).filter((m) => dir === 'all' || m.direction === dir).map((m) => ({ id: m.name, ...m })),
    [members.data, dir],
  );

  if (!loading && groups.length === 0) {
    return (
      <EmptyState
        title="No groups yet"
        body="Groups appear here once a user is assigned to one. Add a user and give them a group to create it."
        action={<Button variant="contained" onClick={onAddUser}>Add user</Button>}
      />
    );
  }

  return (
    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="stretch">
      <Box sx={{ width: { xs: '100%', md: 320 }, flexShrink: 0, minWidth: 0 }}>
        <TextField
          fullWidth label="Search groups" value={search} onChange={(e) => setSearch(e.target.value)} sx={{ mb: 1.5 }}
          InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
        />
        <Box sx={{ height: { xs: 320, md: 560 } }}>
          <DataGrid
            rows={groupRows}
            columns={[{ field: 'name', headerName: 'Group', flex: 1, minWidth: 160 }]}
            loading={loading}
            onRowClick={(p) => setSelected(p.row.name)}
            rowSelectionModel={selected ? [selected] : []}
            onRowSelectionModelChange={(m) => { if (m.length) setSelected(String(m[0])); }}
            disableRowSelectionOnClick={false}
            hideFooterSelectedRowCount
            initialState={{ sorting: { sortModel: [{ field: 'name', sort: 'asc' }] } }}
            localeText={{ noRowsLabel: search ? 'No groups match your search' : 'No groups' }}
            sx={{ '& .MuiDataGrid-row': { cursor: 'pointer' } }}
            aria-label="Groups"
          />
        </Box>
      </Box>

      <Paper variant="outlined" sx={{ flex: 1, minWidth: 0, p: 2 }}>
        {!selected ? (
          <Box sx={{ py: 6, textAlign: 'center' }}>
            <Typography variant="h3" component="p">Pick a group</Typography>
            <Typography color="text.secondary" sx={{ mt: 1 }}>Select a group on the left to see who’s in it and in which direction.</Typography>
          </Box>
        ) : (
          <>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} justifyContent="space-between" alignItems={{ sm: 'center' }} sx={{ mb: 1 }}>
              <Typography variant="h2" component="h2" sx={{ wordBreak: 'break-all' }}>{selected}</Typography>
              <Button size="small" onClick={() => onShowUsers(selected)}>Filter users list by this group</Button>
            </Stack>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{DIRECTION_HELP}</Typography>
            <ToggleButtonGroup exclusive size="small" value={dir} onChange={(_, v) => v && setDir(v)} aria-label="Filter by direction" sx={{ mb: 1.5, flexWrap: 'wrap' }}>
              <ToggleButton value="all">All</ToggleButton>
              <ToggleButton value="both">Both</ToggleButton>
              <ToggleButton value="in">In only</ToggleButton>
              <ToggleButton value="out">Out only</ToggleButton>
            </ToggleButtonGroup>
            {members.error ? (
              <ErrorState error={members.error} onRetry={members.reload} />
            ) : (
              <Box sx={{ height: 440 }}>
                <DataGrid
                  rows={memberRows}
                  loading={members.loading}
                  columns={[
                    { field: 'name', headerName: 'User', flex: 1, minWidth: 160 },
                    { field: 'direction', headerName: 'Direction', width: 130, renderCell: (p) => <DirectionChip direction={p.value} /> },
                    {
                      field: 'edit', headerName: '', width: 120, sortable: false, filterable: false, disableColumnMenu: true,
                      renderCell: (p) => <Button size="small" onClick={() => onEditGroups(p.row.name)}>Edit groups</Button>,
                    },
                  ]}
                  initialState={{ sorting: { sortModel: [{ field: 'name', sort: 'asc' }] } }}
                  localeText={{ noRowsLabel: dir === 'all' ? 'No users in this group' : 'No users with this direction' }}
                  aria-label={`Users in ${selected}`}
                />
              </Box>
            )}
          </>
        )}
      </Paper>
    </Stack>
  );
}
