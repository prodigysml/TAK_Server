// REST calls and rules for file-based user management.
// Controller: takserver-war/.../useraccountmanagement/FileUserAccountManagementApi.java
// (@RequestMapping "/user-management/api"). Only users in UserAuthenticationFile.xml.
import { api, seg } from '../../api/client';

const BASE = '/user-management/api';

const byName = (a, b) => a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true });
const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);

export const usersApi = {
  // Set<UsernameModel> -> [{ username }]
  async listUsers() {
    const res = await api.get(`${BASE}/list-users`);
    return (Array.isArray(res) ? res : []).map((u) => u?.username).filter((u) => typeof u === 'string').sort(byName);
  },
  // Set<GroupNameModel> -> [{ groupname }]
  async listGroups() {
    const res = await api.get(`${BASE}/list-groupnames`);
    return (Array.isArray(res) ? res : []).map((g) => g?.groupname).filter((g) => typeof g === 'string').sort(byName);
  },
  // SimpleGroupWithUsersModel { groupname, usersInGroupList, usersInGroupListIN, usersInGroupListOUT }
  async usersInGroup(group) {
    const res = await api.get(`${BASE}/users-in-group/${seg(group)}`);
    return membersFromLists(res?.usersInGroupListIN, res?.usersInGroupListOUT, res?.usersInGroupList);
  },
  // SimpleUserGroupModel { username, groupList, groupListIN, groupListOUT }
  async groupsForUser(username) {
    const res = await api.get(`${BASE}/get-groups-for-user/${seg(username)}`);
    return membersFromLists(res?.groupListIN, res?.groupListOUT, res?.groupList);
  },
  // NewUserModel. Every list must be an array: the server calls Arrays.asList on each.
  createUser(username, password, assignments) {
    return api.post(`${BASE}/new-user`, { username, password, ...listsFromAssignments(assignments) });
  },
  // UserGenerationInBulkModel -> List<UserPasswordModel> [{ username, password }]
  async createUsers(usernameExpression, startN, endN, assignments) {
    const res = await api.post(`${BASE}/new-users`, { usernameExpression, startN, endN, ...listsFromAssignments(assignments) });
    return (Array.isArray(res) ? res : []).filter((r) => r && typeof r.username === 'string');
  },
  updateGroups(username, assignments) {
    return api.put(`${BASE}/update-groups`, { username, ...listsFromAssignments(assignments) });
  },
  changePassword(username, password) {
    return api.put(`${BASE}/change-user-password`, { username, password });
  },
  deleteUser(username) {
    return api.del(`${BASE}/delete-user/${seg(username)}`);
  },
};

// Direction model. TAK stores three lists per user: groupListIN, groupListOUT and
// groupList (both). FileAuthenticator treats groupList as IN + OUT, so a name in
// both IN and OUT is the same as "both".
export const DIRECTIONS = [
  { value: 'both', label: 'Both', help: 'Sends to and receives from the group. The usual choice.' },
  { value: 'in', label: 'In only', help: 'The user’s devices send data to the group but don’t receive it.' },
  { value: 'out', label: 'Out only', help: 'The user’s devices receive the group’s data but don’t send to it.' },
];
export const directionLabel = (d) => DIRECTIONS.find((x) => x.value === d)?.label || d;
export const DIRECTION_HELP =
  'Direction controls how data flows for this user. In: their devices send data into the group. Out: they receive the group’s data. Both: they send and receive.';

// Map of name -> 'in' | 'out' | 'both', as sorted [{ name, direction }].
export function membersFromLists(inList, outList, bothList) {
  const map = new Map();
  const add = (name, dir) => {
    const prev = map.get(name);
    map.set(name, !prev || prev === dir ? dir : 'both');
  };
  strings(inList).forEach((n) => add(n, 'in'));
  strings(outList).forEach((n) => add(n, 'out'));
  strings(bothList).forEach((n) => map.set(n, 'both'));
  return [...map.entries()].map(([name, direction]) => ({ name, direction })).sort((a, b) => byName(a.name, b.name));
}

export function listsFromAssignments(assignments = []) {
  const pick = (d) => assignments.filter((a) => a.direction === d).map((a) => a.name);
  return { groupList: pick('both'), groupListIN: pick('in'), groupListOUT: pick('out') };
}

// Rules mirrored from the server so admins see problems before submitting.
// tak.server.util.UsernameUtils.isValidUsername
export const USERNAME_RULE = 'At least 4 characters: letters, numbers, dots, underscores and hyphens.';
export const isValidUsername = (u) => typeof u === 'string' && u.length >= 4 && /^[a-zA-Z0-9_.-]+$/.test(u);
// Protected bootstrap admin (UsernameUtils.isProtectedAdmin): the server refuses to delete it.
export const isProtectedAdmin = (u) => typeof u === 'string' && u.trim().toLowerCase() === 'takadmin';

// Group names: same rule the classic "Add new group" dialog enforced.
export const GROUP_RULE = 'At least 4 characters: letters, numbers, dots, underscores and hyphens.';
export const isValidGroupName = (g) => typeof g === 'string' && g.length >= 4 && /^[a-zA-Z0-9_.-]+$/.test(g);

// tak.server.util.PasswordUtils.SPECIAL_CHARS_PATTERN
export const PASSWORD_SPECIALS = '-_!@#$%^&*(){}[]+=~`|:;<>,./?\\';
const SPECIAL_RE = /[-_!@#$%^&*(){}+=~`|:;<>,./?[\]\\]/;
export const PASSWORD_RULES = [
  { id: 'len', label: 'At least 15 characters', test: (p) => p.length >= 15 },
  { id: 'upper', label: 'An uppercase letter', test: (p) => /[A-Z]/.test(p) },
  { id: 'lower', label: 'A lowercase letter', test: (p) => /[a-z]/.test(p) },
  { id: 'digit', label: 'A number', test: (p) => /[0-9]/.test(p) },
  { id: 'special', label: `A symbol from ${PASSWORD_SPECIALS}`, test: (p) => SPECIAL_RE.test(p) },
  { id: 'clean', label: 'No spaces or quote marks', test: (p) => p.length > 0 && !/[\s'"]/.test(p) },
];
export const isValidPassword = (p) => typeof p === 'string' && PASSWORD_RULES.every((r) => r.test(p));
