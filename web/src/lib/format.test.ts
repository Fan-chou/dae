import { describe, expect, it } from "vitest";
import { defaultBaseUrl } from "../api/settings";
import { logChips, parseLogLine } from "./format";

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
