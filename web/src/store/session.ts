import { computed, reactive } from "vue";
import { createClient, fetchConfig, fetchConnections, fetchGroups, fetchLogs, fetchStatus, postGroupDelay, postReload, putConfig, putGroupMember } from "@/api/client";
import { loadSettings, saveSettings, type UiSettings } from "@/api/settings";
import type { AdminConfig, AdminConnection, AdminGroup, AdminStatus, ConnectionFilter } from "@/api/types";
import { parseLogLineSafe, type ParsedLog } from "@/lib/format";

export const ui = reactive({
  settings: loadSettings(),
  status: null as AdminStatus | null,
  groups: [] as AdminGroup[],
  logs: [] as ParsedLog[],
  connections: [] as AdminConnection[],
  connectionsTotal: 0,
  connectionsTruncated: false,
  connectionFilter: { outbound: "AI", src: "", mac: "" } as ConnectionFilter,
  config: { config: "", routing: "" } as AdminConfig,
  error: "",
  notice: "",
  loading: false,
  logPaused: false,
});

export const generation = computed(() => ui.status?.generation || "—");

export function persistSettings(next: UiSettings): void {
  ui.settings = next;
  saveSettings(next);
}

function client() {
  return createClient(ui.settings.baseUrl, ui.settings.secret);
}

export async function refresh(page?: string): Promise<void> {
  if (!ui.settings.secret) {
    ui.error = "请先在设置里填写 admin_secret";
    return;
  }
  ui.loading = true;
  try {
    const api = client();
    ui.status = await fetchStatus(api);
    if (page === "groups" || page === "overview") {
      const body = await fetchGroups(api);
      ui.groups = body.groups || [];
    }
    if (page === "logs" && !ui.logPaused) {
      const body = await fetchLogs(api);
      ui.logs = (body.lines || []).map((raw, i) => parseLogLineSafe(raw, i + 1)).reverse();
    }
    if (page === "config") {
      ui.config = await fetchConfig(api);
    }
    ui.error = "";
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  } finally {
    ui.loading = false;
  }
}

export async function selectMember(group: AdminGroup, memberName: string): Promise<void> {
  ui.notice = "";
  try {
    await putGroupMember(client(), group.name, memberName);
    group.selected = memberName;
    ui.notice = "已切换 " + group.name + " → " + memberName + "（未 reload）";
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  }
}

export async function checkGroupDelay(groupName: string): Promise<void> {
  ui.notice = "";
  try {
    await postGroupDelay(client(), groupName);
    ui.notice = "已触发 " + groupName + " 延迟检测";
    void refresh("groups");
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  }
}

export async function reloadPlane(): Promise<void> {
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

export async function refreshConnections(opts?: { silent?: boolean }): Promise<void> {
  if (!ui.settings.secret) {
    ui.error = "请先在设置里填写 admin_secret";
    return;
  }
  if (!opts?.silent) ui.loading = true;
  try {
    const body = await fetchConnections(client(), {
      outbound: ui.connectionFilter.outbound?.trim(),
      src: ui.connectionFilter.src?.trim(),
      mac: ui.connectionFilter.mac?.trim(),
      limit: 256,
    });
    ui.connections = body.connections || [];
    ui.connectionsTotal = body.total || 0;
    ui.connectionsTruncated = !!body.truncated;
    ui.error = "";
  } catch (err) {
    ui.error = err instanceof Error ? err.message : String(err);
  } finally {
    if (!opts?.silent) ui.loading = false;
  }
}
