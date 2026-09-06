import { computed, reactive } from "vue";
import { createClient, fetchConfig, fetchConnections, fetchGroups, fetchLogs, fetchStatus, postGroupDelay, postReload, putConfig, putGroupMember } from "@/api/client";
import { applyTheme } from "@/lib/theme";
import { loadPrefs, savePrefs, type UiPrefs } from "@/api/prefs";
import { loadSrcMacHints, saveSrcMacHints } from "@/api/srcMac";
import { loadSettings, saveSettings, type UiSettings } from "@/api/settings";
import type { AdminConfig, AdminConnection, AdminGroup, AdminStatus, ConnectionFilter } from "@/api/types";
import { latencyFingerprint, mergeConnectionSnapshots, mergeLogSnapshots, mergeSrcMacHints, type ConnectionView, type ParsedLog, type SrcMacHint, type TrafficSamplePoint } from "@/lib/format";

export const ui = reactive({
  settings: loadSettings(),
  prefs: loadPrefs(),
  status: null as AdminStatus | null,
  groups: [] as AdminGroup[],
  logs: [] as ParsedLog[],
  connections: [] as AdminConnection[],
  connectionViews: [] as ConnectionView[],
  connectionsTotal: 0,
  connectionsTruncated: false,
  connectionsLastPollAt: 0,
  connectionsScope: "",
  connectionsPending: false,
  connectionsError: "",
  connectionFilter: { outbound: "", src: "", mac: "" } as ConnectionFilter,
  srcMacHints: loadSrcMacHints() as SrcMacHint[],
  trafficSamples: [] as TrafficSamplePoint[],
  config: { config: "", routing: "" } as AdminConfig,
  error: "",
  refreshError: "",
  statusError: "",
  statusLastSuccessAt: 0,
  notice: "",
  loading: false,
  logPaused: false,
  checkingGroups: {} as Record<string, boolean>,
});

export const generation = computed(() => ui.status?.generation || "—");

export function persistSettings(next: UiSettings): void {
  ui.settings = next;
  saveSettings(next);
}

export function persistPrefs(patch: Partial<UiPrefs>): void {
  ui.prefs = { ...ui.prefs, ...patch };
  savePrefs(ui.prefs);
  if (patch.theme) applyTheme(ui.prefs.theme);
}

function client() {
  return createClient(ui.settings.baseUrl, ui.settings.secret);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export async function refresh(page?: string, opts?: { silent?: boolean }): Promise<void> {
  if (!ui.settings.secret) {
    ui.refreshError = "请先在设置里填写 admin_secret";
    ui.statusError = ui.refreshError;
    return;
  }
  if (!opts?.silent) ui.loading = true;
  let statusReceived = false;
  try {
    const api = client();
    ui.status = await fetchStatus(api);
    statusReceived = true;
    ui.statusLastSuccessAt = Date.now();
    ui.statusError = "";
    if (page === "groups" || page === "overview") {
      const body = await fetchGroups(api);
      ui.groups = body.groups || [];
    }
    if (page === "logs" && !ui.logPaused) {
      const body = await fetchLogs(api);
      ui.logs = mergeLogSnapshots(ui.logs, body.lines || []);
    }
    if (page === "config") {
      ui.config = await fetchConfig(api);
    }
    ui.refreshError = "";
  } catch (err) {
    ui.refreshError = err instanceof Error ? err.message : String(err);
    if (!statusReceived) ui.statusError = ui.refreshError;
  } finally {
    if (!opts?.silent) ui.loading = false;
  }
}

export async function selectMember(group: AdminGroup, memberName: string): Promise<void> {
  try {
    await putGroupMember(client(), group.name, memberName);
    group.selected = memberName;
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  }
}

export async function checkGroupDelay(groupName: string): Promise<void> {
  if (ui.checkingGroups[groupName]) return;
  ui.checkingGroups[groupName] = true;
  ui.error = "";
  const before = latencyFingerprint(ui.groups.find((group) => group.name === groupName) || { members: [] });
  try {
    await postGroupDelay(client(), groupName);
    const deadline = Date.now() + 15000;
    let last = before;
    let stable = 0;
    while (Date.now() < deadline) {
      await sleep(800);
      await refresh("groups", { silent: true });
      const after = latencyFingerprint(ui.groups.find((group) => group.name === groupName) || { members: [] });
      if (after !== last) {
        last = after;
        stable = 0;
      } else if (after !== before) {
        stable += 1;
        if (stable >= 2) break;
      }
    }
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  } finally {
    ui.checkingGroups[groupName] = false;
  }
}

export async function reloadPlane(): Promise<void> {
  ui.notice = "";
  ui.error = "";
  try {
    const body = await postReload(client());
    ui.notice = body.queued ? "已排队热重载" : "重载忙，稍后再试";
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  }
}

export async function saveConfig(): Promise<void> {
  ui.notice = "";
  ui.error = "";
  try {
    const body = await putConfig(client(), {
      config: ui.config.config,
      routing: ui.config.routing,
    });
    ui.notice = body.queued ? "已保存并排队热重载" : "已保存，热重载忙或未启用";
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  }
}

let connectionRequest = 0;
let connectionContext = "";

export async function refreshConnections(opts?: { silent?: boolean; outbound?: string }): Promise<void> {
  if (!ui.settings.secret) { ui.connectionsError = "请先在设置里填写访问密钥"; return; }
  const filter = opts && "outbound" in opts
    ? { outbound: String(opts.outbound || "").trim(), limit: ui.prefs.connLimit }
    : { ...ui.connectionFilter, limit: ui.prefs.connLimit };
  const context = JSON.stringify([ui.settings.baseUrl, ui.settings.secret, filter]);
  if (ui.connectionsPending && context === connectionContext) return;
  const changed = context !== connectionContext;
  connectionContext = context;
  const request = ++connectionRequest;
  if (changed) {
    ui.connectionViews = []; ui.connections = []; ui.connectionsTotal = 0;
    ui.connectionsLastPollAt = 0; ui.connectionsTruncated = false;
  }
  ui.connectionsPending = true;
  ui.connectionsError = "";
  try {
    const body = await fetchConnections(client(), filter);
    if (request !== connectionRequest) return;
    const now = Date.now();
    const scopeChanged = !!body.scope && body.scope !== ui.connectionsScope;
    const elapsed = ui.connectionsLastPollAt ? now - ui.connectionsLastPollAt : 0;
    ui.connections = body.connections || [];
    ui.connectionViews = mergeConnectionSnapshots(scopeChanged ? [] : ui.connectionViews, ui.connections, elapsed, !body.truncated);
    ui.connectionsScope = body.scope || "";
    ui.srcMacHints = mergeSrcMacHints(ui.srcMacHints, ui.connectionViews);
    saveSrcMacHints(ui.srcMacHints);
    ui.connectionsTotal = body.total ?? 0;
    ui.connectionsTruncated = !!body.truncated;
    ui.connectionsLastPollAt = now;
  } catch (err) {
    if (request === connectionRequest) ui.connectionsError = err instanceof Error ? err.message : String(err);
  } finally {
    if (request === connectionRequest) ui.connectionsPending = false;
  }
}
