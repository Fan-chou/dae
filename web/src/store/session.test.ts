import { beforeEach, describe, expect, it, vi } from "vitest";
const api = vi.hoisted(() => ({ fetchConnections: vi.fn(), fetchStatus: vi.fn() }));
vi.mock("@/api/client", () => ({...api,createClient:vi.fn(),fetchConfig:vi.fn(),fetchGroups:vi.fn(),fetchLogs:vi.fn(),postGroupDelay:vi.fn(),postReload:vi.fn(),putConfig:vi.fn(),putGroupMember:vi.fn()}));
const row = (id: string) => ({id,network:"tcp",src:"1.2.3.4:90",dst:"example.test:443",outbound:"A",upload:100,download:200});
beforeEach(() => { vi.resetModules(); api.fetchConnections.mockReset(); api.fetchStatus.mockReset(); });
describe("connection requests", () => {
 it("ignores old responses after a filter change and forwards server filters", async () => {
  const {ui,refreshConnections}=await import("./session"); ui.settings.secret="test";
  let resolveOld!: (value: unknown) => void;
  api.fetchConnections.mockImplementationOnce(() => new Promise(resolve => {resolveOld=resolve;}));
  const old=refreshConnections();
  ui.connectionFilter={outbound:"B",src:"1.2.3.4",mac:"aa:bb:cc:dd:ee:ff"};
  api.fetchConnections.mockResolvedValueOnce({total:1,truncated:false,connections:[row("new")]});
  await refreshConnections();
  resolveOld({total:1,truncated:false,connections:[row("old")]}); await old;
  expect(ui.connections[0].id).toBe("new");
  expect(api.fetchConnections.mock.calls[1][1]).toMatchObject({src:"1.2.3.4",mac:"aa:bb:cc:dd:ee:ff",limit:1024});
 });
 it("coalesces same-filter polls and resets history for a new server scope", async () => {
  const {ui,refreshConnections}=await import("./session");ui.settings.secret="test";
  let resolve!: (value: unknown) => void;
  api.fetchConnections.mockImplementationOnce(() => new Promise(r=>{resolve=r;}));
  const first=refreshConnections();await refreshConnections();
  expect(api.fetchConnections).toHaveBeenCalledTimes(1);
  resolve({scope:"one",total:1,truncated:false,connections:[row("old")]});await first;
  api.fetchConnections.mockResolvedValueOnce({scope:"two",total:1,truncated:false,connections:[row("new")]});
  await refreshConnections();expect(ui.connectionViews.map(r=>r.id)).toEqual(["new"]);
 });
});


describe("refresh status", () => {
 it("keeps operation errors independent and preserves the last successful status on failure", async () => {
  const {ui,refresh}=await import("./session");
  ui.settings.secret="test";
  ui.error="保存失败";
  api.fetchStatus.mockResolvedValueOnce({running:true,upload_rate:42});
  await refresh();
  const timestamp=ui.statusLastSuccessAt;
  expect(timestamp).toBeGreaterThan(0);
  expect(ui.error).toBe("保存失败");
  api.fetchStatus.mockRejectedValueOnce(new Error("离线"));
  await refresh();
  expect(ui.statusError).toBe("离线");
  expect(ui.refreshError).toBe("离线");
  expect(ui.statusLastSuccessAt).toBe(timestamp);
  expect(ui.status?.upload_rate).toBe(42);
  expect(ui.error).toBe("保存失败");
  api.fetchStatus.mockResolvedValueOnce({running:true,upload_rate:0});
  await refresh();
  expect(ui.statusError).toBe("");
  expect(ui.refreshError).toBe("");
  expect(ui.error).toBe("保存失败");
 });
});
