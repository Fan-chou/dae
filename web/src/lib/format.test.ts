import { describe, expect, it } from "vitest";
import { connectionsPath } from "../api/client";
import { defaultBaseUrl } from "../api/settings";
import { applyConnectionFilters, appendTrafficSample, byteRate, connectionAge, connectionAgeMs, connectionMacOptions, connectionSrcOptions, displayEndpoint, filterConnectionViews, logChips, lookupCachedMac, mergeConnectionSnapshots, mergeLogSnapshots, mergeSrcMacHints, parseLogLine, rateScale, srcHost, summarizeConnections, uniqueOutbounds } from "./format";
import { effectiveConnView } from "./layout";
import { lintDae } from "./dae-lint";

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

describe("connection filter options", () => {
  const rows = [
    { src: "192.168.124.202:44321", mac: "3e:0a:a5:de:ae:a3" },
    { src: "192.168.124.202:1", mac: "3e:0a:a5:de:ae:a3" },
    { src: "192.168.124.10:9", mac: "aa:bb:cc:dd:ee:ff" },
  ];

  it("lists every group even if live rows only show one outbound", () => {
    expect(uniqueOutbounds([{ name: "AI" }, { name: "proxy" }], [{ outbound: "AI" }])).toEqual(["AI", "block", "direct", "proxy"]);
  });

  it("labels src with mac and mac with matching src hosts", () => {
    expect(srcHost("192.168.124.202:44321")).toBe("192.168.124.202");
    expect(srcHost("[fd00::1]:443")).toBe("fd00::1");
    const srcs = connectionSrcOptions(rows);
    expect(srcs.find((opt) => opt.value === "192.168.124.202")?.label).toBe("192.168.124.202 (3e:0a:a5:de:ae:a3)");
    const macs = connectionMacOptions(rows);
    expect(macs.find((opt) => opt.value === "3e:0a:a5:de:ae:a3")?.label).toBe("3e:0a:a5:de:ae:a3 (192.168.124.202)");
    expect(filterConnectionViews(rows, "192.168.124.202", "").map((row) => row.src)).toEqual(["192.168.124.202:44321", "192.168.124.202:1"]);
  });

  it("keeps src/mac pairs after live rows disappear", () => {
    const cached = mergeSrcMacHints([], rows);
    const later = mergeSrcMacHints(cached, [{ src: "192.168.124.30:9", mac: "11:22:33:44:55:66" }]);
    expect(connectionSrcOptions(later).map((opt) => opt.value)).toEqual(["192.168.124.10", "192.168.124.202", "192.168.124.30"]);
    expect(connectionMacOptions(later).find((opt) => opt.value === "3e:0a:a5:de:ae:a3")?.label).toBe("3e:0a:a5:de:ae:a3 (192.168.124.202)");
    expect(mergeSrcMacHints(later, [], 1)).toEqual([{ src: "192.168.124.30", mac: "11:22:33:44:55:66" }]);
  });
});

describe("lintDae", () => {
  it("flags node URIs and unclosed braces, keeps http check urls", () => {
    const ok = lintDae("global {\n  tcp_check_url: 'http://cp.cloudflare.com'\n}\nrouting { fallback: direct }\n", "config");
    expect(ok.filter((issue) => issue.severity === "error")).toHaveLength(0);
    const bad = lintDae("routing {\n  hy2://secret@example.com\n", "routing");
    expect(bad.some((issue) => issue.message.includes("URI"))).toBe(true);
    expect(bad.some((issue) => issue.message.includes("未闭合"))).toBe(true);
    expect(JSON.stringify(bad).includes("secret@")).toBe(false);
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

describe("rateScale and connection summaries", () => {
  const row = {
    id: "1",
    network: "tcp",
    src: "192.168.124.202:44321",
    dst: "api2.cursor.sh:443",
    mac: "3e:0a:a5:de:ae:a3",
    outbound: "AI",
    dialer: "US_Dmit_LAX_Hysteria",
    upload: 10,
    download: 20,
  };

  it("picks kB/s and a nice y-max from sample rates", () => {
    const scale = rateScale([100, 1500, 800]);
    expect(scale.unit).toBe("kB/s");
    expect(scale.divisor).toBe(1000);
    expect(scale.niceMax).toBeGreaterThanOrEqual(1);
  });

  it("formats connection age from RFC3339 start", () => {
    const now = 1_700_000_005_000;
    expect(connectionAge(new Date(now - 5000).toISOString(), now)).toBe("5s");
    expect(connectionAge(new Date(now - 65_000).toISOString(), now)).toBe("1m 5s");
    expect(connectionAgeMs(new Date(now - 65_000).toISOString(), now)).toBeGreaterThan(
      connectionAgeMs(new Date(now - 5000).toISOString(), now),
    );
  });

  it("hides invalid AddrPort and fills MAC from src cache", () => {
    expect(displayEndpoint("invalid AddrPort")).toBe("");
    expect(displayEndpoint("1.2.3.4:443")).toBe("1.2.3.4:443");
    expect(srcHost("invalid AddrPort")).toBe("");
    expect(lookupCachedMac([{ src: "192.168.124.202:1", mac: "3e:0a:a5:de:ae:a3" }], "192.168.124.202:9")).toBe(
      "3e:0a:a5:de:ae:a3",
    );
  });

  it("picks card view on compact screens when connView is auto", () => {
    expect(effectiveConnView("auto", true)).toBe("card");
    expect(effectiveConnView("auto", false)).toBe("table");
    expect(effectiveConnView("table", true)).toBe("table");
    expect(effectiveConnView("card", false)).toBe("card");
  });

  it("merges newer log lines past the 300 fetch window", () => {
    const first = mergeLogSnapshots([], ["old-a", "old-b", "mid"]);
    expect(first.map((item) => item.raw)).toEqual(["mid", "old-b", "old-a"]);
    const next = mergeLogSnapshots(first, ["old-b", "mid", "new-1", "new-2"], 4);
    expect(next.map((item) => item.raw)).toEqual(["new-2", "new-1", "mid", "old-b"]);
    expect(next[0].seqLabel).toBe("004");
  });

  it("summarizes live rows by outbound and hides closed ones", () => {
    const rows = mergeConnectionSnapshots(
      [],
      [
        { ...row, id: "1", outbound: "AI" },
        { ...row, id: "2", outbound: "direct", src: "192.168.124.10:9" },
      ],
      0,
    );
    rows[0].downloadRate = 100;
    rows[1].downloadRate = 10;
    const summary = summarizeConnections(rows);
    expect(summary.live).toBe(2);
    expect(summary.byOutbound[0].name).toBe("AI");
    expect(summary.byMac[0].name).toBe("3e:0a:a5:de:ae:a3");
    expect(summary.upload).toBe(20);
    expect(summary.download).toBe(40);
    expect(applyConnectionFilters(rows, { search: "direct" }).map((item) => item.outbound)).toEqual(["direct"]);
    expect(applyConnectionFilters(rows, { excludeOn: true, exclude: "AI" })).toHaveLength(1);
    expect(appendTrafficSample([{ ts: 1, up: 1, down: 1 }], { ts: 2, up: 3, down: 4 }, 2)).toEqual([
      { ts: 1, up: 1, down: 1 },
      { ts: 2, up: 3, down: 4 },
    ]);
    expect(appendTrafficSample([{ ts: 1, up: 1, down: 1 }, { ts: 2, up: 2, down: 2 }], { ts: 3, up: 3, down: 3 }, 2)).toEqual([
      { ts: 2, up: 2, down: 2 },
      { ts: 3, up: 3, down: 3 },
    ]);
  });
});
