import { computed, reactive } from "vue";
import { createClient, fetchGroups, fetchLogs, fetchStatus, postGroupDelay, postReload, putGroupMember } from "@/api/client";
import { loadSettings, saveSettings, type UiSettings } from "@/api/settings";
import type { AdminGroup, AdminStatus } from "@/api/types";
import { parseLogLineSafe, type ParsedLog } from "@/lib/format";

export const ui = reactive({
  settings: loadSettings(),
  status: null as AdminStatus | null,
  groups: [] as AdminGroup[],
  logs: [] as ParsedLog[],
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
