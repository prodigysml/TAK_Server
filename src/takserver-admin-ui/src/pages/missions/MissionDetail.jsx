import React from 'react';
import {
  Alert, Box, Button, Chip, Divider, Drawer, IconButton, Link, Stack, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import DownloadIcon from '@mui/icons-material/DownloadOutlined';
import SendIcon from '@mui/icons-material/SendOutlined';
import MailIcon from '@mui/icons-material/MailOutline';
import DeleteIcon from '@mui/icons-material/DeleteOutline';
import LockIcon from '@mui/icons-material/LockOutlined';
import { api } from '../../api/client';
import { useApi } from '../../api/useApi';
import { Loading } from '../../components/States';
import {
  asArray, expirationDate, fileHref, formatBytes, formatDate, missionPath, plural, roleLabel, text,
} from './missionUtils';

const CHANGES_WINDOW_SECONDS = 7 * 24 * 60 * 60;
const MAX_CHANGES = 25;
const MAX_UIDS_SHOWN = 50;

const CHANGE_LABELS = {
  CREATE_MISSION: 'Mission created',
  DELETE_MISSION: 'Mission deleted',
  ADD_CONTENT: 'Added',
  REMOVE_CONTENT: 'Removed',
  CREATE_MISSION_FEED: 'Data feed added',
  DELETE_MISSION_FEED: 'Data feed removed',
};

function Section({ title, count, children }) {
  return (
    <Box component="section" sx={{ mt: 3 }}>
      <Typography variant="h3" component="h3" sx={{ mb: 1 }}>
        {title}
        {count !== undefined && <Typography component="span" color="text.secondary" sx={{ ml: 1, fontWeight: 400 }}>{count}</Typography>}
      </Typography>
      {children}
    </Box>
  );
}

function Field({ label, children }) {
  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '140px 1fr' }, columnGap: 2, py: 0.5 }}>
      <Typography variant="body2" color="text.secondary">{label}</Typography>
      <Typography variant="body2" component="div" sx={{ overflowWrap: 'anywhere' }}>{children}</Typography>
    </Box>
  );
}

const Muted = ({ children }) => <Typography variant="body2" color="text.secondary">{children}</Typography>;

function ChipList({ items, empty }) {
  if (!items.length) return <Muted>{empty}</Muted>;
  return (
    <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap">
      {items.map((i) => <Chip key={i} size="small" variant="outlined" label={i} />)}
    </Stack>
  );
}

// Optional sections: a failure here shouldn't hide the rest of the mission.
function SubLoad({ req, what, children }) {
  if (req.loading && req.data === undefined) return <Loading />;
  if (req.error) {
    return (
      <Alert severity="warning" action={<Button color="inherit" size="small" onClick={() => req.reload()}>Try again</Button>}>
        Couldn’t load {what}: {req.error.message}
      </Alert>
    );
  }
  return children;
}

function describeChange(c) {
  const r = c.contentResource;
  if (r && (r.name || r.filename)) return text(r.name || r.filename);
  if (c.details && (c.details.callsign || c.details.title)) return text(c.details.callsign || c.details.title);
  return text(c.contentUid);
}

export default function MissionDetail({ name, onClose, onDelete, onSend, onInvite }) {
  const open = name !== null;

  const mission = useApi(async () => {
    if (!open) return undefined;
    const d = await api.get(missionPath(name));
    return Array.isArray(d) ? d[0] : d;
  }, [name]);
  const subs = useApi(
    () => (open ? api.get(missionPath(name, '/subscriptions/roles')) : Promise.resolve(undefined)),
    [name],
  );
  const changes = useApi(
    () => (open
      ? api.get(missionPath(name, '/changes'), { query: { secago: CHANGES_WINDOW_SECONDS, squashed: true } })
      : Promise.resolve(undefined)),
    [name],
  );

  const m = mission.data;
  const contents = asArray(m?.contents).map((c) => c && c.data).filter(Boolean);
  const uids = asArray(m?.uids).map((u) => u && u.data).filter((u) => typeof u === 'string');
  const feeds = asArray(m?.feeds);
  const expires = expirationDate(m?.expiration);
  const subscribers = asArray(subs.data);
  const changeList = asArray(changes.data)
    .slice()
    .sort((a, b) => String(b.serverTime || b.timestamp || '').localeCompare(String(a.serverTime || a.timestamp || '')))
    .slice(0, MAX_CHANGES);

  return (
    <Drawer
      anchor="right" open={open} onClose={onClose}
      PaperProps={{ sx: { width: { xs: '100%', sm: 600 }, maxWidth: '100vw' } }}
    >
      <Box sx={{ p: { xs: 2, sm: 3 } }} role="region" aria-label={name ? `Mission ${name}` : 'Mission details'}>
        <Stack direction="row" alignItems="flex-start" spacing={1}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="h2" component="h2" sx={{ overflowWrap: 'anywhere' }}>{name}</Typography>
            {m && (
              <Stack direction="row" spacing={1} sx={{ mt: 1 }} useFlexGap flexWrap="wrap">
                <Chip size="small" variant="outlined" label={`Tool: ${text(m.tool) || 'none'}`} />
                {m.passwordProtected && <Chip size="small" variant="outlined" color="warning" icon={<LockIcon />} label="Password protected" />}
                {expires && (
                  <Chip
                    size="small" variant="outlined" color={expires.getTime() < Date.now() ? 'error' : 'default'}
                    label={`${expires.getTime() < Date.now() ? 'Expired' : 'Expires'} ${formatDate(expires)}`}
                  />
                )}
              </Stack>
            )}
          </Box>
          <IconButton aria-label="Close mission details" onClick={onClose}><CloseIcon /></IconButton>
        </Stack>

        {name && /[\/\\]/.test(name) && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            This mission&apos;s name contains a slash, which the server refuses inside a web address, so it can&apos;t be opened or changed here. Manage it from a TAK client.
          </Alert>
        )}

        {name && (
          <Stack direction="row" spacing={1} sx={{ mt: 2 }} useFlexGap flexWrap="wrap">
            <Button size="small" variant="outlined" startIcon={<SendIcon />} onClick={onSend}>Send package</Button>
            <Button size="small" variant="outlined" startIcon={<MailIcon />} onClick={onInvite}>Invite clients</Button>
            <Button size="small" variant="outlined" startIcon={<DownloadIcon />} href={missionPath(name, '/archive')}>Download archive</Button>
            <Button size="small" variant="outlined" startIcon={<DownloadIcon />} href={`${missionPath(name, '/kml')}?download=true`}>Download KML</Button>
            <Button size="small" variant="outlined" color="error" startIcon={<DeleteIcon />} onClick={onDelete}>Delete mission</Button>
          </Stack>
        )}

        <Divider sx={{ mt: 2 }} />

        {mission.loading && !m && <Loading />}
        {mission.error && (
          <Alert severity="error" sx={{ mt: 2 }} action={<Button color="inherit" size="small" onClick={() => mission.reload()}>Try again</Button>}>
            Couldn’t load this mission: {mission.error.message}
          </Alert>
        )}

        {m && (
          <>
            <Section title="Details">
              <Field label="Description">{text(m.description) || <Muted>None</Muted>}</Field>
              <Field label="Created">{formatDate(m.createTime) || <Muted>Unknown</Muted>}</Field>
              <Field label="Creator UID">{text(m.creatorUid) || <Muted>Not recorded</Muted>}</Field>
              <Field label="Last edited">{formatDate(m.lastEdited) || <Muted>Never</Muted>}</Field>
              <Field label="Default role">{roleLabel(m.defaultRole?.type)}</Field>
              <Field label="Chat room">{text(m.chatRoom) || <Muted>None</Muted>}</Field>
              <Field label="Expires">{expires ? formatDate(expires) : <Muted>Never</Muted>}</Field>
              <Field label="Items (UIDs)">{plural(uids.length, 'item')}</Field>
              <Field label="GUID">{text(m.guid)}</Field>
            </Section>

            <Section title="Groups" count={asArray(m.groups).length}>
              <ChipList items={asArray(m.groups).map(text)} empty="No groups." />
            </Section>

            <Section title="Keywords" count={asArray(m.keywords).length}>
              <ChipList items={asArray(m.keywords).map(text)} empty="No keywords." />
            </Section>

            {m.passwordProtected && contents.length === 0 && uids.length === 0 && (
              <Alert severity="info" sx={{ mt: 3 }}>
                This mission is password protected, so the server may hide its files and items here. Use the classic manager or a TAK client with the password to see them.
              </Alert>
            )}

            <Section title="Files" count={contents.length}>
              {contents.length === 0 ? <Muted>No files in this mission.</Muted> : (
                <TableContainer sx={{ border: 1, borderColor: 'divider', borderRadius: 1 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow><TableCell>Name</TableCell><TableCell align="right">Size</TableCell><TableCell>Added by</TableCell></TableRow>
                    </TableHead>
                    <TableBody>
                      {contents.map((r) => (
                        <TableRow key={text(r.hash) || text(r.name)}>
                          <TableCell sx={{ overflowWrap: 'anywhere' }}>
                            {r.hash
                              ? <Link href={fileHref(r.hash)} underline="hover">{text(r.name || r.filename) || text(r.hash)}</Link>
                              : text(r.name || r.filename)}
                          </TableCell>
                          <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>{formatBytes(r.size)}</TableCell>
                          <TableCell sx={{ overflowWrap: 'anywhere' }}>
                            {text(r.submitter) || text(r.creatorUid) || '—'}
                            {r.submissionTime && <Typography variant="caption" color="text.secondary" component="div">{formatDate(r.submissionTime)}</Typography>}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Section>

            {uids.length > 0 && (
              <Section title="Items" count={uids.length}>
                <Box sx={{ maxHeight: 180, overflowY: 'auto', border: 1, borderColor: 'divider', borderRadius: 1, p: 1 }}>
                  {uids.slice(0, MAX_UIDS_SHOWN).map((u) => (
                    <Typography key={u} variant="body2" sx={{ overflowWrap: 'anywhere' }}>{u}</Typography>
                  ))}
                  {uids.length > MAX_UIDS_SHOWN && <Muted>and {uids.length - MAX_UIDS_SHOWN} more</Muted>}
                </Box>
              </Section>
            )}

            <Section title="Data feeds" count={feeds.length}>
              <ChipList items={feeds.map((f) => text(f && (f.name || f.dataFeedUid))).filter(Boolean)} empty="No data feeds." />
            </Section>
          </>
        )}

        {name && (
          <>
            <Section title="Subscribers" count={subs.data ? subscribers.length : undefined}>
              <SubLoad req={subs} what="subscribers">
                {subscribers.length === 0 ? <Muted>Nobody is subscribed. Invite clients to add them.</Muted> : (
                  <TableContainer sx={{ border: 1, borderColor: 'divider', borderRadius: 1, maxHeight: 320 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow><TableCell>User</TableCell><TableCell>Client UID</TableCell><TableCell>Role</TableCell><TableCell>Since</TableCell></TableRow>
                      </TableHead>
                      <TableBody>
                        {subscribers.map((s, i) => (
                          <TableRow key={`${text(s.clientUid)}-${i}`}>
                            <TableCell sx={{ overflowWrap: 'anywhere' }}>{text(s.username) || '—'}</TableCell>
                            <TableCell sx={{ overflowWrap: 'anywhere' }}>{text(s.clientUid)}</TableCell>
                            <TableCell sx={{ whiteSpace: 'nowrap' }}>
                              <Chip
                                size="small" variant="outlined"
                                color={s.role?.type === 'MISSION_OWNER' ? 'primary' : 'default'}
                                label={roleLabel(s.role?.type)}
                              />
                            </TableCell>
                            <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatDate(s.createTime)}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </SubLoad>
            </Section>

            <Section title="Changes in the last 7 days" count={changes.data ? asArray(changes.data).length : undefined}>
              <SubLoad req={changes} what="recent changes">
                {changeList.length === 0 ? <Muted>No changes in the last 7 days.</Muted> : (
                  <Stack divider={<Divider flexItem />} sx={{ border: 1, borderColor: 'divider', borderRadius: 1 }}>
                    {changeList.map((c, i) => (
                      <Box key={i} sx={{ px: 1.5, py: 0.75 }}>
                        <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                          {CHANGE_LABELS[c.type] || text(c.type)} {describeChange(c)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {formatDate(c.serverTime || c.timestamp)}{c.creatorUid ? ` by ${text(c.creatorUid)}` : ''}
                        </Typography>
                      </Box>
                    ))}
                    {asArray(changes.data).length > MAX_CHANGES && (
                      <Box sx={{ px: 1.5, py: 0.75 }}><Muted>Showing the latest {MAX_CHANGES}.</Muted></Box>
                    )}
                  </Stack>
                )}
              </SubLoad>
            </Section>
          </>
        )}
      </Box>
    </Drawer>
  );
}
