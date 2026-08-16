import type { AdminConnection } from "@/api/types";

const chipKeys = ["dialer", "network", "sniffed", "ip", "policy", "pname", "mac", "outbound"] as const;
const sensitiveKey = /password|secret|token|uri|url|auth|key$/i;

export type LogKind = "conn" | "dns" | "sys";

export type LogChip = { k: string; v: string };

export type ParsedLog = {
  seq: number;
  seqLabel: string;
  raw: string;
  level: string;
  time: string;
  timeShort: string;
  msg: string;
  fields: Record<string, string>;
  conn: { from: string; to: string } | null;
  kind: LogKind;
  kindLabel: string;
  match: string;
  chips: LogChip[];
};

export function kindLabel(kind: LogKind): string {
  if (kind === "conn") return "连接";
  if (kind === "dns") return "DNS";
  return "系统";
}

export function unescapeLogValue(raw: string): string {
  if (raw.charAt(0) !== '"') return raw;
  try {
    return JSON.parse(raw) as string;
  } catch {
    return raw.slice(1, -1).replace(/\\"/g, '"');
  }
}

export function parseLogrusFields(raw: string): Record<string, string> {
  const fields: Record<string, string> = {};
  const re = /([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"\\])*"|[^\s]*)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(raw))) {
    fields[match[1]] = unescapeLogValue(match[2]);
  }
  return fields;
}

export function normalizeLevel(level: string): string {
  const value = String(level || "info").toLowerCase();
  if (value === "warn") return "warning";
  return value;
}

export function formatTimeShort(time: string): string {
  if (!time) return "";
  const clock = String(time).match(/(\d{2}:\d{2}:\d{2})/);
  if (clock) return clock[1];
  const parsed = new Date(time);
  if (!isNaN(parsed.getTime())) {
    return parsed.toTimeString().slice(0, 8);
  }
  return String(time);
}

export function parseConn(msg: string): { from: string; to: string } | null {
  const token = " <-> ";
  const idx = String(msg).indexOf(token);
  if (idx === -1) return null;
  return { from: msg.slice(0, idx), to: msg.slice(idx + token.length) };
}

export function classifyLog(msg: string, fields: Record<string, string>): LogKind {
  if (parseConn(msg) || fields.outbound || fields.dialer) return "conn";
  if (/dns/i.test(msg) || fields.upstream) return "dns";
  return "sys";
}

function parsePrefixedLine(raw: string): RegExpMatchArray | null {
  return raw.match(/^(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|PANIC)\s*\[([^\]]*)\]\s*(.*)$/i);
}

export function logChips(fields: Record<string, string>): LogChip[] {
  const chips: LogChip[] = [];
  for (const key of chipKeys) {
    const value = fields[key];
    if (value == null || value === "") continue;
    if (sensitiveKey.test(key)) continue;
    if (String(value).indexOf("://") !== -1) continue;
    chips.push({ k: key, v: String(value) });
  }
  return chips;
}

export function parseLogLine(raw: string, seq: number): ParsedLog {
  const line = String(raw).replace(/\r$/, "");
  let level = "info";
  let time = "";
  let msg = line;
  let fields: Record<string, string> = {};

  if (line.charAt(0) === "{") {
    try {
      const obj = JSON.parse(line) as Record<string, string>;
      level = normalizeLevel(obj.level || obj.type || "info");
      time = obj.time || obj.timestamp || "";
      msg = obj.msg || obj.message || obj.payload || line;
      fields = obj;
    } catch {
      fields = {};
    }
  } else {
    const prefixed = parsePrefixedLine(line);
    if (prefixed) {
      level = normalizeLevel(prefixed[1]);
      time = prefixed[2];
      const rest = prefixed[3] || "";
      const split = rest.match(/\s+([A-Za-z_][A-Za-z0-9_]*)=/);
      if (split && split.index != null) {
        msg = rest.slice(0, split.index).trim() || msg;
        fields = parseLogrusFields(rest.slice(split.index));
        if (fields.msg) msg = fields.msg;
      } else {
        msg = rest.trim();
        fields = parseLogrusFields(rest);
      }
    } else {
      fields = parseLogrusFields(line);
      if (fields.level || fields.msg) {
        level = normalizeLevel(fields.level || "info");
        time = fields.time || fields.timestamp || "";
        msg = fields.msg || line;
      }
    }
  }

  const conn = parseConn(msg);
  const kind = classifyLog(msg, fields);
  return {
    seq,
    seqLabel: String(seq).padStart(3, "0"),
    raw: line,
    level,
    time,
    timeShort: formatTimeShort(time),
    msg,
    fields,
    conn,
    kind,
    kindLabel: kindLabel(kind),
    match: fields.outbound || "",
    chips: logChips(fields),
  };
}

export function parseLogLineSafe(raw: string, seq: number): ParsedLog {
  try {
    return parseLogLine(raw, seq);
  } catch {
    return {
      seq,
      seqLabel: String(seq).padStart(3, "0"),
      raw: String(raw),
      level: "info",
      time: "",
      timeShort: "",
      msg: String(raw),
      fields: {},
      conn: null,
      kind: "sys",
      kindLabel: "系统",
      match: "",
      chips: [],
    };
  }
}

export function policyLabel(policy: string): string {
  if (policy === "first_alive") return "first_alive（fallback，自动）";
  if (policy === "fixed") return "fixed（select）";
  if (policy === "min_avg10") return "min_avg10（url-test）";
  if (policy === "min_moving_avg") return "min_moving_avg（url-test）";
  if (policy === "min") return "min（url-test）";
  return policy || "—";
}

export function latencyClass(alive: boolean, latencyMs?: number | null): string {
  if (!alive || latencyMs == null) return "text-base-content/40";
  if (latencyMs < 150) return "text-success";
  if (latencyMs < 400) return "text-warning";
  return "text-error";
}

export function latencyText(alive: boolean, latencyMs?: number | null): string {
  if (!alive) return "超时";
  if (latencyMs == null) return "—";
  return latencyMs + " ms";
}

export function displayedSelected(group: { selected?: string; policy?: string; members?: { name: string; alive: boolean; latency_ms?: number | null }[] }): string {
  if (group.selected) return group.selected;
  const members = group.members || [];
  if (group.policy === "first_alive") {
    const alive = members.find((m) => m.alive);
    return alive ? alive.name : "检查中";
  }
  if (group.policy && group.policy.indexOf("min") === 0) {
    const alive = members.filter((m) => m.alive && m.latency_ms != null);
    if (!alive.length) return "检查中";
    alive.sort((a, b) => (a.latency_ms || 0) - (b.latency_ms || 0));
    return alive[0].name;
  }
  return "—";
}

export function byteRate(prev: number, next: number, elapsedMs: number): number {
  if (elapsedMs <= 0) return 0;
  const delta = next - prev;
  if (delta <= 0) return 0;
  return (delta * 1000) / elapsedMs;
}

export type ConnectionView = AdminConnection & {
  uploadRate: number;
  downloadRate: number;
  closed: boolean;
};

export type FilterOption = { value: string; label: string };

export function srcHost(src: string): string {
  const value = String(src || "");
  if (!value || value === "invalid AddrPort") return "";
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end > 1 ? value.slice(1, end) : value;
  }
  const colon = value.lastIndexOf(":");
  if (colon <= 0) return value;
  const host = value.slice(0, colon);
  if (host.includes(".")) return host;
  return value;
}

export function displayEndpoint(value: string): string {
  const text = String(value || "").trim();
  if (!text || text === "invalid AddrPort") return "";
  return text;
}

export function lookupCachedMac(hints: SrcMacHint[], src: string): string {
  const host = srcHost(src);
  if (!host) return "";
  for (const hint of hints) {
    if ((srcHost(hint.src) || hint.src) === host && hint.mac) return hint.mac;
  }
  return "";
}

export type SrcMacHint = { src: string; mac?: string };

const srcMacLimit = 256;

export function mergeSrcMacHints(cache: SrcMacHint[], rows: SrcMacHint[], limit = srcMacLimit): SrcMacHint[] {
  const byHost = new Map<string, Set<string>>();
  const order: string[] = [];

  function touch(host: string, mac: string): void {
    let macs = byHost.get(host);
    if (!macs) {
      macs = new Set();
      byHost.set(host, macs);
      order.push(host);
    } else {
      const index = order.indexOf(host);
      if (index >= 0) {
        order.splice(index, 1);
        order.push(host);
      }
    }
    if (mac) macs.add(mac);
  }

  for (const item of cache) {
    const host = srcHost(item.src) || String(item.src || "").trim();
    if (!host) continue;
    touch(host, String(item.mac || "").toLowerCase());
  }
  for (const row of rows) {
    const host = srcHost(row.src);
    if (!host) continue;
    touch(host, String(row.mac || "").toLowerCase());
  }

  return order.slice(-limit).flatMap((host) => {
    const macs = [...(byHost.get(host) || [])].filter(Boolean).sort();
    if (!macs.length) return [{ src: host }];
    return macs.map((mac) => ({ src: host, mac }));
  });
}

export function connectionSrcOptions(rows: { src: string; mac?: string }[]): FilterOption[] {
  const byHost = new Map<string, Set<string>>();
  for (const row of rows) {
    const host = srcHost(row.src);
    if (!host) continue;
    const macs = byHost.get(host) || new Set<string>();
    if (row.mac) macs.add(row.mac);
    byHost.set(host, macs);
  }
  return [...byHost.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([host, macs]) => ({
      value: host,
      label: macs.size ? host + " (" + [...macs].sort().join(", ") + ")" : host,
    }));
}

export function connectionMacOptions(rows: { src: string; mac?: string }[]): FilterOption[] {
  const byMac = new Map<string, Set<string>>();
  for (const row of rows) {
    const mac = String(row.mac || "").toLowerCase();
    if (!mac) continue;
    const srcs = byMac.get(mac) || new Set<string>();
    srcs.add(srcHost(row.src) || row.src);
    byMac.set(mac, srcs);
  }
  return [...byMac.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([mac, srcs]) => {
      const list = [...srcs].sort();
      const shown = list.slice(0, 4);
      const extra = list.length > 4 ? " +" + String(list.length - 4) : "";
      return { value: mac, label: mac + " (" + shown.join(", ") + extra + ")" };
    });
}

export function uniqueOutbounds(groups: { name: string }[], rows: { outbound?: string }[]): string[] {
  const names = new Set<string>(["direct", "block"]);
  for (const group of groups) {
    if (group.name) names.add(group.name);
  }
  for (const row of rows) {
    if (row.outbound) names.add(row.outbound);
  }
  return [...names].sort((a, b) => a.localeCompare(b));
}

export function filterConnectionViews<T extends { src: string; mac?: string }>(rows: T[], src: string, mac: string): T[] {
  const srcQ = src.trim();
  const macQ = mac.trim().toLowerCase();
  if (!srcQ && !macQ) return rows;
  return rows.filter((row) => {
    if (srcQ && srcHost(row.src) !== srcQ && row.src !== srcQ) return false;
    if (macQ && String(row.mac || "").toLowerCase() !== macQ) return false;
    return true;
  });
}

export function networkFamily(network: string): "tcp" | "udp" | "other" {
  const value = String(network || "").toLowerCase();
  if (value.indexOf("tcp") === 0) return "tcp";
  if (value.indexOf("udp") === 0) return "udp";
  return "other";
}

export function uniqueDialers(rows: { dialer?: string }[]): string[] {
  const names = new Set<string>();
  for (const row of rows) {
    if (row.dialer) names.add(row.dialer);
  }
  return [...names].sort((a, b) => a.localeCompare(b));
}

export function uniqueNetworks(rows: { network?: string }[]): string[] {
  const names = new Set<string>();
  for (const row of rows) {
    const family = networkFamily(row.network || "");
    if (family !== "other") names.add(family);
  }
  return [...names].sort((a, b) => a.localeCompare(b));
}

export type ConnectionFilterState = {
  src?: string;
  mac?: string;
  network?: string;
  dialer?: string;
  closed?: "active" | "closed" | "all";
  search?: string;
  exclude?: string;
  excludeOn?: boolean;
};

function connectionSearchBlob(row: {
  src?: string;
  dst?: string;
  domain?: string;
  mac?: string;
  outbound?: string;
  dialer?: string;
  network?: string;
  policy?: string;
}): string {
  return [row.src, row.dst, row.domain, row.mac, row.outbound, row.dialer, row.network, row.policy]
    .join(" ")
    .toLowerCase();
}

export function applyConnectionFilters<T extends ConnectionView>(rows: T[], filter: ConnectionFilterState): T[] {
  const srcQ = (filter.src || "").trim();
  const macQ = (filter.mac || "").trim().toLowerCase();
  const networkQ = (filter.network || "").trim().toLowerCase();
  const dialerQ = (filter.dialer || "").trim();
  const closed = filter.closed || "all";
  const terms = (filter.search || "")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  let excludeRe: RegExp | null = null;
  const exclude = (filter.exclude || "").trim();
  if (filter.excludeOn && exclude) {
    try {
      excludeRe = new RegExp(exclude, "i");
    } catch {
      excludeRe = null;
    }
  }
  return rows.filter((row) => {
    if (closed === "active" && row.closed) return false;
    if (closed === "closed" && !row.closed) return false;
    if (srcQ && srcHost(row.src) !== srcQ && row.src !== srcQ) return false;
    if (macQ && String(row.mac || "").toLowerCase() !== macQ) return false;
    if (networkQ && networkFamily(row.network) !== networkQ) return false;
    if (dialerQ && row.dialer !== dialerQ) return false;
    const blob = connectionSearchBlob(row);
    if (terms.length && !terms.every((term) => blob.includes(term))) return false;
    if (filter.excludeOn && exclude) {
      const hit = excludeRe ? excludeRe.test(blob) : blob.includes(exclude.toLowerCase());
      if (hit) return false;
    }
    return true;
  });
}

export type RateScale = { divisor: number; unit: string; niceMax: number };

export function niceCeil(value: number): number {
  if (value <= 0) return 1;
  const exp = Math.floor(Math.log10(value));
  const base = 10 ** exp;
  const frac = value / base;
  const nice = frac <= 1 ? 1 : frac <= 2 ? 2 : frac <= 5 ? 5 : 10;
  return nice * base;
}

export function rateScale(values: number[]): RateScale {
  const max = Math.max(0, ...values);
  const units = [
    { divisor: 1, unit: "B/s" },
    { divisor: 1000, unit: "kB/s" },
    { divisor: 1000 * 1000, unit: "MB/s" },
    { divisor: 1000 * 1000 * 1000, unit: "GB/s" },
  ];
  let picked = units[0];
  for (const unit of units) {
    if (max >= unit.divisor) picked = unit;
  }
  const scaled = max / picked.divisor;
  return { divisor: picked.divisor, unit: picked.unit, niceMax: niceCeil(scaled * 1.05) };
}

export function connectionAgeMs(start: string, nowMs = Date.now()): number {
  const ts = Date.parse(start);
  if (!Number.isFinite(ts) || ts <= 0) return 0;
  return Math.max(0, nowMs - ts);
}

export function connectionAge(start: string, nowMs = Date.now()): string {
  const ms = connectionAgeMs(start, nowMs);
  if (!ms) return start ? "0s" : "—";
  let sec = Math.floor(ms / 1000);
  const hours = Math.floor(sec / 3600);
  sec -= hours * 3600;
  const minutes = Math.floor(sec / 60);
  sec -= minutes * 60;
  if (hours) return hours + "h " + minutes + "m";
  if (minutes) return minutes + "m " + sec + "s";
  return sec + "s";
}

export type TrafficBucket = {
  name: string;
  count: number;
  upload: number;
  download: number;
  uploadRate: number;
  downloadRate: number;
};

export type TrafficSamplePoint = { ts: number; up: number; down: number };

export function liveSessionTraffic(rows: ConnectionView[]): TrafficBucket {
  const bucket: TrafficBucket = { name: "session", count: 0, upload: 0, download: 0, uploadRate: 0, downloadRate: 0 };
  for (const row of rows) {
    if (row.closed) continue;
    bucket.count += 1;
    bucket.upload += row.upload || 0;
    bucket.download += row.download || 0;
    bucket.uploadRate += row.uploadRate || 0;
    bucket.downloadRate += row.downloadRate || 0;
  }
  return bucket;
}

export function appendTrafficSample(samples: TrafficSamplePoint[], point: TrafficSamplePoint, limit = 150): TrafficSamplePoint[] {
  const next = samples.concat(point);
  return next.length > limit ? next.slice(next.length - limit) : next;
}

function addBucket(map: Map<string, TrafficBucket>, name: string, row: ConnectionView): void {
  const key = name || "—";
  const cur = map.get(key) || { name: key, count: 0, upload: 0, download: 0, uploadRate: 0, downloadRate: 0 };
  cur.count += 1;
  cur.upload += row.upload || 0;
  cur.download += row.download || 0;
  cur.uploadRate += row.uploadRate || 0;
  cur.downloadRate += row.downloadRate || 0;
  map.set(key, cur);
}

function rankedBuckets(map: Map<string, TrafficBucket>, limit: number): TrafficBucket[] {
  return [...map.values()]
    .sort((a, b) => b.downloadRate - a.downloadRate || b.download - a.download || b.count - a.count)
    .slice(0, limit);
}

export function summarizeConnections(rows: ConnectionView[], limit = 8): {
  live: number;
  upload: number;
  download: number;
  uploadRate: number;
  downloadRate: number;
  byOutbound: TrafficBucket[];
  bySrc: TrafficBucket[];
  byMac: TrafficBucket[];
  byDialer: TrafficBucket[];
  byNetwork: TrafficBucket[];
  byDomain: TrafficBucket[];
} {
  const liveRows = rows.filter((row) => !row.closed);
  const totals = liveSessionTraffic(liveRows);
  const byOutbound = new Map<string, TrafficBucket>();
  const bySrc = new Map<string, TrafficBucket>();
  const byMac = new Map<string, TrafficBucket>();
  const byDialer = new Map<string, TrafficBucket>();
  const byNetwork = new Map<string, TrafficBucket>();
  const byDomain = new Map<string, TrafficBucket>();
  for (const row of liveRows) {
    addBucket(byOutbound, row.outbound || "—", row);
    addBucket(bySrc, srcHost(row.src) || row.src, row);
    if (row.mac) addBucket(byMac, String(row.mac).toLowerCase(), row);
    if (row.dialer) addBucket(byDialer, row.dialer, row);
    addBucket(byNetwork, networkFamily(row.network), row);
    if (row.domain) addBucket(byDomain, row.domain, row);
  }
  return {
    live: totals.count,
    upload: totals.upload,
    download: totals.download,
    uploadRate: totals.uploadRate,
    downloadRate: totals.downloadRate,
    byOutbound: rankedBuckets(byOutbound, limit),
    bySrc: rankedBuckets(bySrc, limit),
    byMac: rankedBuckets(byMac, limit),
    byDialer: rankedBuckets(byDialer, limit),
    byNetwork: rankedBuckets(byNetwork, limit),
    byDomain: rankedBuckets(byDomain, limit),
  };
}

export function trafficForName(rows: ConnectionView[], name: string): TrafficBucket {
  const match = String(name || "");
  const bucket: TrafficBucket = { name: match, count: 0, upload: 0, download: 0, uploadRate: 0, downloadRate: 0 };
  if (!match) return bucket;
  for (const row of rows) {
    if (row.closed) continue;
    if (row.outbound === match || row.dialer === match) {
      bucket.count += 1;
      bucket.upload += row.upload || 0;
      bucket.download += row.download || 0;
      bucket.uploadRate += row.uploadRate || 0;
      bucket.downloadRate += row.downloadRate || 0;
    }
  }
  return bucket;
}

export function latencyFingerprint(group: { members?: { name: string; alive: boolean; latency_ms?: number | null }[] }): string {
  return (group.members || [])
    .map((member) => member.name + ":" + (member.alive ? "1" : "0") + ":" + String(member.latency_ms ?? ""))
    .join("|");
}

export function mergeConnectionSnapshots(prev: ConnectionView[], live: AdminConnection[], elapsedMs: number): ConnectionView[] {
  const prevById = new Map(prev.map((row) => [row.id, row]));
  const liveIds = new Set(live.map((row) => row.id));
  const rows: ConnectionView[] = live.map((item) => {
    const last = prevById.get(item.id);
    return {
      ...item,
      src: displayEndpoint(item.src),
      dst: displayEndpoint(item.dst),
      domain: displayEndpoint(item.domain || ""),
      uploadRate: last ? byteRate(last.upload, item.upload, elapsedMs) : 0,
      downloadRate: last ? byteRate(last.download, item.download, elapsedMs) : 0,
      closed: false,
    };
  });
  for (const row of prev) {
    if (!liveIds.has(row.id) && !row.closed) {
      rows.push({ ...row, uploadRate: 0, downloadRate: 0, closed: true });
    }
  }
  return rows;
}
