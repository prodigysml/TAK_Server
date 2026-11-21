import React, { useCallback, useMemo, useState } from 'react';
import {
  Alert, Autocomplete, Box, Button, IconButton, InputAdornment, Stack, Tab, Tabs, TextField, Tooltip, Typography,
} from '@mui/material';
import { DataGrid, GridActionsCellItem } from '@mui/x-data-grid';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import GroupAddIcon from '@mui/icons-material/GroupAdd';
import RefreshIcon from '@mui/icons-material/Refresh';
import SearchIcon from '@mui/icons-material/Search';
import GroupsIcon from '@mui/icons-material/Groups';
import KeyIcon from '@mui/icons-material/Key';
import DeleteIcon from '@mui/icons-material/DeleteOutline';
import PageHeader from '../components/PageHeader';
import ConfirmDialog from '../components/ConfirmDialog';
import { EmptyState, ErrorState } from '../components/States';
import { useNotify } from '../components/Notify';
import { useApi } from '../api/useApi';
import AddUserDialog from './users/AddUserDialog';
import BulkAddDialog from './users/BulkAddDialog';
import EditGroupsDialog from './users/EditGroupsDialog';
import ChangePasswordDialog from './users/ChangePasswordDialog';
import GroupsTab from './users/GroupsTab';
import DirectionChip from './users/DirectionChip';
import { DIRECTION_HELP, isProtectedAdmin, usersApi } from './users/model';

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

export default function Users() {
  const notify = useNotify();
  const [tab, setTab] = useState('users');
  const [search, setSearch] = useState('');
  const [groupFilter, setGroupFilter] = useState(null);
  const [selection, setSelection] = useState([]);
  const [dialog, setDialog] = useState(null); // 'add' | 'bulk'
  const [editUser, setEditUser] = useState(null);
  const [passwordUser, setPasswordUser] = useState(null);
  const [toDelete, setToDelete] = useState(null); // string[]
  const [deleting, setDeleting] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  const usersQ = useApi(() => usersApi.listUsers(), []);
  const groupsQ = useApi(() => usersApi.listGroups(), []);
  const members = useApi(
    () => (groupFilter ? usersApi.usersInGroup(groupFilter) : Promise.resolve(null)),
    [groupFilter, reloadKey],
  );

  const users = usersQ.data || [];
  const groups = groupsQ.data || [];

  const refresh = useCallback(() => {
    usersQ.reload(true);
    groupsQ.reload(true);
    setReloadKey((k) => k + 1);
  }, [usersQ.reload, groupsQ.reload]); // eslint-disable-line react-hooks/exhaustive-deps

  const memberMap = useMemo(() => new Map((members.data || []).map((m) => [m.name, m.direction])), [members.data]);
  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return users
      .filter((u) => !q || u.toLowerCase().includes(q))
      .filter((u) => !groupFilter || memberMap.has(u))
      .map((u) => ({ id: u, username: u, direction: memberMap.get(u) }));
  }, [users, search, groupFilter, memberMap]);

  const columns = useMemo(() => {
    const cols = [{ field: 'username', headerName: 'Username', flex: 1, minWidth: 180 }];
    if (groupFilter) {
      cols.push({
        field: 'direction', headerName: `Direction in ${groupFilter}`, width: 200,
        renderCell: (p) => (p.value ? <DirectionChip direction={p.value} /> : null),
      });
    }
    cols.push({
      field: 'actions', type: 'actions', headerName: 'Actions', width: 150,
      getActions: (p) => {
        const protectedAdmin = isProtectedAdmin(p.row.username);
        return [
          <GridActionsCellItem key="groups" icon={<Tooltip title="Edit groups"><GroupsIcon fontSize="small" /></Tooltip>} label={`Edit groups for ${p.row.username}`} onClick={() => setEditUser(p.row.username)} />,
          <GridActionsCellItem key="pw" icon={<Tooltip title="Change password"><KeyIcon fontSize="small" /></Tooltip>} label={`Change password for ${p.row.username}`} onClick={() => setPasswordUser(p.row.username)} />,
          <GridActionsCellItem
            key="del"
            icon={<Tooltip title={protectedAdmin ? 'The bootstrap admin account is protected and can’t be deleted' : 'Delete user'}><DeleteIcon fontSize="small" /></Tooltip>}
            label={`Delete ${p.row.username}`}
            disabled={protectedAdmin}
            onClick={() => setToDelete([p.row.username])}
          />,
        ];
      },
    });
    return cols;
  }, [groupFilter]);

  const confirmDelete = async () => {
    const names = toDelete || [];
    setDeleting(true);
    const failed = [];
    for (const name of names) {
      try {
        // Sequential: the server rewrites UserAuthenticationFile.xml on every change.
        // eslint-disable-next-line no-await-in-loop
        await usersApi.deleteUser(name);
      } catch (err) {
        failed.push({ name, err });
      }
    }
    setDeleting(false);
    setToDelete(null);
    setSelection((s) => s.filter((id) => failed.some((f) => f.name === id)));
    const ok = names.length - failed.length;
    if (failed.length === 0) {
      notify(names.length === 1 ? `Deleted user ${names[0]}` : `Deleted ${plural(ok, 'user')}`);
    } else {
      const first = failed[0];
      notify(new Error(`${ok ? `Deleted ${plural(ok, 'user')}, but c` : 'C'}ouldn’t delete ${failed.map((f) => f.name).slice(0, 5).join(', ')}${failed.length > 5 ? ` and ${failed.length - 5} more` : ''}. ${first.err.message}`));
    }
    refresh();
  };

  const showUsersInGroup = (g) => { setGroupFilter(g); setSearch(''); setTab('users'); };

  const loadError = usersQ.error || groupsQ.error;

  return (
    <Box sx={{ minWidth: 0 }}>
      <PageHeader
        title="Users and groups"
        description="Manage the file-based users in UserAuthenticationFile.xml: who can sign in with a password and which groups they share data with. Certificate-only and LDAP users aren’t listed here."
        actions={(
          <>
            <Button variant="contained" startIcon={<PersonAddIcon />} onClick={() => setDialog('add')}>Add user</Button>
            <Button variant="outlined" startIcon={<GroupAddIcon />} onClick={() => setDialog('bulk')}>Add users in bulk</Button>
          </>
        )}
      />

      <Stack direction="row" alignItems="center" sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} aria-label="Users or groups" sx={{ flex: 1, minWidth: 0 }} variant="scrollable" allowScrollButtonsMobile>
          <Tab value="users" label={usersQ.data ? `Users (${users.length})` : 'Users'} />
          <Tab value="groups" label={groupsQ.data ? `Groups (${groups.length})` : 'Groups'} />
        </Tabs>
        <Tooltip title="Reload users and groups">
          <IconButton onClick={refresh} aria-label="Reload users and groups"><RefreshIcon /></IconButton>
        </Tooltip>
      </Stack>

      {loadError && <ErrorState error={loadError} onRetry={() => { usersQ.reload(); groupsQ.reload(); }} />}

      {tab === 'users' && !usersQ.error && (
        !usersQ.loading && users.length === 0 ? (
          <EmptyState
            title="No file-based users yet"
            body="Add a user to let someone sign in with a username and password."
            action={<Button variant="contained" onClick={() => setDialog('add')}>Add user</Button>}
          />
        ) : (
          <>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 1.5 }} alignItems={{ sm: 'flex-start' }}>
              <TextField
                label="Search users" value={search} onChange={(e) => setSearch(e.target.value)} sx={{ width: { xs: '100%', sm: 280 } }}
                InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
              />
              <Autocomplete
                options={groups} value={groupFilter} onChange={(_, v) => setGroupFilter(v)}
                sx={{ width: { xs: '100%', sm: 280 } }}
                renderInput={(params) => <TextField {...params} label="Only users in group" placeholder="Any group" />}
              />
              <Box sx={{ flex: 1 }} />
              {selection.length > 0 && (
                <Button color="error" variant="outlined" startIcon={<DeleteIcon />} onClick={() => setToDelete([...selection])}>
                  Delete {plural(selection.length, 'user')}
                </Button>
              )}
            </Stack>
            {groupFilter && (
              <Alert severity="info" sx={{ mb: 1.5 }} onClose={() => setGroupFilter(null)}>
                Showing users in {groupFilter}. {DIRECTION_HELP}
              </Alert>
            )}
            {members.error && <ErrorState error={members.error} onRetry={members.reload} />}
            <Box sx={{ height: 560, width: '100%' }}>
              <DataGrid
                rows={rows}
                columns={columns}
                loading={usersQ.loading || (!!groupFilter && members.loading)}
                checkboxSelection
                isRowSelectable={(p) => !isProtectedAdmin(p.row.username)}
                rowSelectionModel={selection}
                onRowSelectionModelChange={(m) => setSelection(m)}
                initialState={{ sorting: { sortModel: [{ field: 'username', sort: 'asc' }] }, pagination: { paginationModel: { pageSize: 100 } } }}
                pageSizeOptions={[25, 50, 100]}
                localeText={{ noRowsLabel: search || groupFilter ? 'No users match these filters' : 'No users' }}
                aria-label="Users"
              />
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              The takadmin account is protected and can’t be deleted.
            </Typography>
          </>
        )
      )}

      {tab === 'groups' && !groupsQ.error && (
        <GroupsTab
          groups={groups} loading={groupsQ.loading} reloadKey={reloadKey}
          onEditGroups={setEditUser} onShowUsers={showUsersInGroup} onAddUser={() => setDialog('add')}
        />
      )}

      <AddUserDialog
        open={dialog === 'add'} onClose={() => setDialog(null)} users={users} groups={groups}
        onCreated={() => { setDialog(null); refresh(); }}
      />
      <BulkAddDialog open={dialog === 'bulk'} onClose={() => setDialog(null)} users={users} groups={groups} onCreated={refresh} />
      <EditGroupsDialog username={editUser} groups={groups} onClose={() => setEditUser(null)} onSaved={() => { setEditUser(null); refresh(); }} />
      <ChangePasswordDialog username={passwordUser} onClose={() => setPasswordUser(null)} />
      <ConfirmDialog
        open={!!toDelete}
        title={toDelete && toDelete.length === 1 ? `Delete user ${toDelete[0]}?` : `Delete ${plural(toDelete?.length || 0, 'user')}?`}
        body={toDelete && (toDelete.length === 1
          ? 'They won’t be able to sign in with this username and password again. Their certificates, if any, aren’t revoked. This can’t be undone.'
          : `${toDelete.slice(0, 8).join(', ')}${toDelete.length > 8 ? ` and ${toDelete.length - 8} more` : ''} won’t be able to sign in again. Certificates aren’t revoked. This can’t be undone.`)}
        confirmLabel={deleting ? 'Deleting…' : (toDelete && toDelete.length === 1 ? 'Delete user' : `Delete ${plural(toDelete?.length || 0, 'user')}`)}
        typeToConfirm={toDelete && toDelete.length > 1 ? 'delete' : undefined}
        busy={deleting}
        onConfirm={confirmDelete}
        onClose={() => setToDelete(null)}
      />
    </Box>
  );
}
