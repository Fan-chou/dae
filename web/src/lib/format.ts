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

export function mergeConnectionSnapshots(prev: ConnectionView[], live: AdminConnection[], elapsedMs: number): ConnectionView[] {
  const prevById = new Map(prev.map((row) => [row.id, row]));
  const liveIds = new Set(live.map((row) => row.id));
  const rows: ConnectionView[] = live.map((item) => {
    const last = prevById.get(item.id);
    return {
      ...item,
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
