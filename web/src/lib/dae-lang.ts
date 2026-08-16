import type * as monaco from "monaco-editor";

const DAE_LANGUAGE_ID = "dae";

export function registerDaeLanguage(monacoApi: typeof monaco): void {
  const languages = monacoApi.languages.getLanguages();
  if (languages.some((lang) => lang.id === DAE_LANGUAGE_ID)) return;

  monacoApi.languages.register({ id: DAE_LANGUAGE_ID, aliases: ["dae", "RoutingA"] });
  monacoApi.languages.setLanguageConfiguration(DAE_LANGUAGE_ID, {
    comments: { lineComment: "#" },
    brackets: [
      ["{", "}"],
      ["(", ")"],
    ],
    autoClosingPairs: [
      { open: "{", close: "}" },
      { open: "(", close: ")" },
      { open: "'", close: "'" },
      { open: '"', close: '"' },
    ],
    surroundingPairs: [
      { open: "{", close: "}" },
      { open: "(", close: ")" },
      { open: "'", close: "'" },
      { open: '"', close: '"' },
    ],
  });
  monacoApi.languages.setMonarchTokensProvider(DAE_LANGUAGE_ID, {
    ignoreCase: false,
    keywords: [
      "global",
      "routing",
      "dns",
      "include",
      "group",
      "node",
      "subscription",
      "upstream",
      "request",
      "response",
      "fallback",
      "must_direct",
      "must_rules",
      "direct",
      "block",
      "asis",
      "accept",
      "reject",
      "tcp",
      "udp",
    ],
    functions: [
      "sip",
      "dip",
      "l4proto",
      "dport",
      "sport",
      "domain",
      "pname",
      "mac",
      "match_mac",
      "dscp",
      "qname",
      "qtype",
      "ipversion",
      "dialer",
      "outbound",
      "geoip",
      "geosite",
      "ruleset",
    ],
    operators: ["&&", "!", "->"],
    symbols: /[=><!~?:&|+\-*/^%]+/,
    escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,
    tokenizer: {
      root: [
        [/@[A-Za-z_]\w*/, "tag"],
        [/[A-Za-z_]\w*/, { cases: { "@keywords": "keyword", "@functions": "type.identifier", "@default": "identifier" } }],
        { include: "@whitespace" },
        [/[{}()]/, "@brackets"],
        [/->/, "operator"],
        [/@symbols/, { cases: { "@operators": "operator", "@default": "" } }],
        [/\d+\.\d+\.\d+\.\d+(\/\d+)?/, "number"],
        [/\b\d+[smh]?\b/, "number"],
        [/[,:]/, "delimiter"],
        [/"([^"\\]|\\.)*$/, "string.invalid"],
        [/'([^'\\]|\\.)*$/, "string.invalid"],
        [/"/, "string", "@string_double"],
        [/'/, "string", "@string_single"],
      ],
      string_double: [
        [/[^\\"]+/, "string"],
        [/@escapes/, "string.escape"],
        [/\\./, "string.escape.invalid"],
        [/"/, "string", "@pop"],
      ],
      string_single: [
        [/[^\\']+/, "string"],
        [/@escapes/, "string.escape"],
        [/\\./, "string.escape.invalid"],
        [/'/, "string", "@pop"],
      ],
      whitespace: [
        [/[ \t\r\n]+/, "white"],
        [/#.*$/, "comment"],
        [/\/\/.*$/, "comment"],
      ],
    },
  });
}

export { DAE_LANGUAGE_ID };
