import DashboardIcon from '@mui/icons-material/SpaceDashboardOutlined';
import PeopleIcon from '@mui/icons-material/PeopleAltOutlined';
import BadgeIcon from '@mui/icons-material/BadgeOutlined';
import LanIcon from '@mui/icons-material/LanOutlined';
import InputIcon from '@mui/icons-material/SettingsInputAntennaOutlined';
import FlagIcon from '@mui/icons-material/FlagOutlined';
import HistoryIcon from '@mui/icons-material/HistoryToggleOffOutlined';

import Overview from './pages/Overview';
import Users from './pages/Users';
import ClientCerts from './pages/ClientCerts';
import ConnectedClients from './pages/ConnectedClients';
import Inputs from './pages/Inputs';
import Missions from './pages/Missions';
import DataRetention from './pages/DataRetention';

// classic: the page this replaces, linked from the top bar so admins can fall back.
export const sections = [
  {
    title: null,
    items: [{ path: '/', label: 'Overview', icon: DashboardIcon, element: Overview, classic: '/Marti/metrics/index.html' }],
  },
  {
    title: 'People',
    items: [
      { path: '/users', label: 'Users and groups', icon: PeopleIcon, element: Users, classic: '/user-management/index.html' },
      { path: '/certs', label: 'Client certificates', icon: BadgeIcon, element: ClientCerts, classic: '/Marti/clientcerts/index.html' },
    ],
  },
  {
    title: 'Network',
    items: [
      { path: '/clients', label: 'Connected clients', icon: LanIcon, element: ConnectedClients, classic: '/Marti/clients/index.html' },
      { path: '/inputs', label: 'Inputs and data feeds', icon: InputIcon, element: Inputs, classic: '/Marti/inputs/index.html' },
    ],
  },
  {
    title: 'Data',
    items: [
      { path: '/missions', label: 'Missions', icon: FlagIcon, element: Missions, classic: '/Marti/MissionManager.html' },
      { path: '/retention', label: 'Data retention', icon: HistoryIcon, element: DataRetention, classic: '/Marti/data_retention/index.html' },
    ],
  },
];

export const allRoutes = sections.flatMap((s) => s.items);

export function findRoute(path) {
  return allRoutes.find((r) => r.path === path) || allRoutes[0];
}
