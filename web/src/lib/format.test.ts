import { describe, expect, it } from "vitest";
import { connectionsPath } from "../api/client";
import { defaultBaseUrl } from "../api/settings";
import { byteRate, logChips, mergeConnectionSnapshots, parseLogLine } from "./format";

describe("logChips", () => {
  it("keeps mac and outbound, drops URIs", () => {
    const chips = logChips({
      outbound: "AI",
      dialer: "US_Dmit_LAX_Hysteria",
      mac: "3e:0a:a5:de:ae:a3",
      link: "hy2://secret@example.com",
      sniffed: "api2.cursor.sh",
    });
    expect(chips.map((c) => c.k)).toEqual(["dialer", "sniffed", "mac", "outbound"]);
    expect(chips.some((c) => c.v.includes("://"))).toBe(false);
  });
});

describe("parseLogLine", () => {
  it("parses kdae connection info lines", () => {
    const line =
      'level=info msg="192.168.124.202:63630 <-> api2.cursor.sh:443" dialer="US_Dmit_LAX_Hysteria" mac="3e:0a:a5:de:ae:a3" network=tcp4 outbound=AI sniffed=api2.cursor.sh';
    const parsed = parseLogLine(line, 1);
    expect(parsed.kind).toBe("conn");
    expect(parsed.conn?.to).toBe("api2.cursor.sh:443");
    expect(parsed.match).toBe("AI");
    expect(parsed.chips.find((c) => c.k === "dialer")?.v).toBe("US_Dmit_LAX_Hysteria");
  });
});

describe("defaultBaseUrl", () => {
  it("falls back to cgi proxy without a browser location", () => {
    expect(defaultBaseUrl()).toBe("/cgi-bin/kdae-proxy");
  });
});

describe("connectionsPath", () => {
  it("puts outbound=AI on the query string", () => {
    expect(connectionsPath({ outbound: "AI", limit: 256 })).toBe("/v1/connections?limit=256&outbound=AI");
  });
});

describe("config payloads", () => {
  it("never ships a node URI in the editor seed", () => {
    const seed = { config: "global {\n  log_level: info\n  admin_secret: '***'\n}\n", routing: "routing {\n  fallback: direct\n}\n" };
    expect(JSON.stringify(seed).includes("://")).toBe(false);
    expect(seed.config.includes("keep-me")).toBe(false);
  });
});

describe("mergeConnectionSnapshots", () => {
  const live = {
    id: "1",
    network: "tcp",
    src: "192.168.124.202:44321",
    dst: "api2.cursor.sh:443",
    mac: "3e:0a:a5:de:ae:a3",
    outbound: "AI",
    dialer: "US_Dmit_LAX_Hysteria",
    upload: 100,
    download: 200,
  };

  it("computes rates from two snapshots and marks closed ids for one cycle", () => {
    expect(byteRate(100, 200, 2000)).toBe(50);
    const first = mergeConnectionSnapshots([], [live], 0);
    expect(first[0].uploadRate).toBe(0);
    const second = mergeConnectionSnapshots(first, [{ ...live, upload: 200, download: 400 }], 2000);
    expect(second[0].uploadRate).toBe(50);
    expect(second[0].downloadRate).toBe(100);
    const closed = mergeConnectionSnapshots(second, [], 2000);
    expect(closed).toHaveLength(1);
    expect(closed[0].closed).toBe(true);
    expect(mergeConnectionSnapshots(closed, [], 2000)).toHaveLength(0);
  });

  it("does not keep URIs on view rows", () => {
    const rows = mergeConnectionSnapshots([], [{ ...live, domain: "api2.cursor.sh" }], 0);
    expect(JSON.stringify(rows).includes("://")).toBe(false);
  });
});
