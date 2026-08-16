export type AdminStatus = {
  version?: string;
  running?: boolean;
  lan_interface?: string[];
  wan_interface?: string[];
  generation?: string;
  previous_generation?: string;
  sync_warning?: string;
  upload_rate?: number;
  download_rate?: number;
  upload_total?: number;
  download_total?: number;
  active_connections?: number;
  udp_sessions?: number;
  rss_bytes?: number;
  fd_count?: number;
  traffic_samples?: { ts: number; up: number; down: number }[];
};

export type AdminGroupMember = {
  name: string;
  alive: boolean;
  latency_ms?: number | null;
};

export type AdminGroup = {
  name: string;
  selectable: boolean;
  policy: string;
  selected: string;
  selection_members: string[];
  members: AdminGroupMember[];
};

export type AdminLogs = {
  lines: string[];
};

export type AdminReload = {
  queued: boolean;
};

export type AdminConnection = {
  id: string;
  network: string;
  src: string;
  dst: string;
  domain?: string;
  mac?: string;
  outbound: string;
  dialer?: string;
  policy?: string;
  start?: string;
  upload: number;
  download: number;
};

export type AdminConnectionsSnapshot = {
  total: number;
  truncated: boolean;
  connections: AdminConnection[];
};

export type ConnectionFilter = {
  outbound?: string;
  src?: string;
  mac?: string;
  limit?: number;
};

export type AdminError = {
  error?: string;
};
