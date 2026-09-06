// Adapted from daeuniverse/daed packages/dae-editor/src/constants.ts.
// Upstream commit: 671e65d2fdcd62fe6a3ec18ecda209c5addea898.
// MIT Copyright (c) 2023 daeuniverse. See public/DAED-LICENSE.txt.
// Tokenization only: no upstream formatter, completions or diagnostics.
import type { languages } from 'monaco-editor/esm/vs/editor/editor.api'

export const FDAE_LANGUAGE: languages.IMonarchLanguage = {
  // set defaultToken as `invalid` to turn on debug mode
  // defaultToken: 'invalid',
  ignoreCase: false,

  // Rule functions (matching conditions)
  ruleFunctions: [
    'domain',
    'ip',
    'source',
    'port',
    'sourcePort',
    'inboundTag',
    'network',
    'protocol',
    'user',
    // dae-specific
    'dip',
    'dport',
    'sip',
    'sport',
    'ipversion',
    'l4proto',
    'mac',
    'pname',
    'qname',
  ],

  // Domain matching types
  domainTypes: ['domain', 'full', 'contains', 'regexp', 'geosite'],

  // IP matching types
  ipTypes: ['geoip'],

  // Declaration keywords
  declarations: ['global', 'routing', 'dns', 'group', 'node', 'subscription'],

  // Outbound/inbound types
  connectionTypes: ['http', 'socks', 'freedom'],

  // Built-in outbounds
  builtinOutbounds: ['proxy', 'block', 'direct', 'must_direct', 'must_proxy'],

  // Connection parameters
  parameters: [
    'address',
    'port',
    'user',
    'pass',
    'sniffing',
    'domainStrategy',
    'redirect',
    'userLevel',
  ],

  // dae-specific keywords
  daeKeywords: [
    'fallback',
    'must_rules',
    'request',
    'response',
    'routing',
    'upstream',
    'tcp',
    'udp',
    'true',
    'false',
  ],

  escapes:
    /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,

  symbols: /[->=&!:,]+/,

  operators: ['&&', '!', '->'],

  tokenizer: {
    root: [
      // Comments
      { include: '@whitespace' },

      [/\b[a-z_][\w-]*(?=\s*:)/i, 'variable.parameter'],

      // Declaration: inbound:name=type(...) or outbound:name=type(...)
      [
        /(inbound|outbound)(:)(\w+)(=)/,
        ['keyword', 'delimiter', 'variable', 'operator'],
      ],

      // Default declaration: default:
      [/(default)(:)/, ['keyword', 'delimiter']],

      // External file reference: ext:"file.dat:tag"
      [/(ext)(:)/, ['keyword.special', 'delimiter']],

      // Geosite/geoip prefix
      [/(geosite|geoip)(:)/, ['keyword.special', 'delimiter']],

      // Rule functions and identifiers (including process names like NetworkManager)
      [
        /[a-z][\w-]*/i,
        {
          cases: {
            '@ruleFunctions': 'keyword',
            '@domainTypes': 'type',
            '@ipTypes': 'type',
            '@declarations': 'keyword',
            '@connectionTypes': 'type.identifier',
            '@builtinOutbounds': 'constant',
            '@parameters': 'variable.parameter',
            '@daeKeywords': 'keyword',
            '@default': 'identifier',
          },
        },
      ],

      // IP addresses (IPv4)
      [/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?/, 'number.ip'],

      // IPv6 addresses (simplified pattern)
      [/[\da-f:]+::[\da-f:]+/i, 'number.ip'],
      [/[\da-f]+:[\da-f:]+/i, 'number.ip'],

      // Port ranges
      [/\d+-\d+/, 'number.range'],

      // Numbers
      [/\d+/, 'number'],

      // Brackets
      [/[{}()]/, '@brackets'],

      // Arrow operator
      [/->/, 'operator.arrow'],

      // Symbols and operators
      [
        /@symbols/,
        { cases: { '@operators': 'operator', '@default': 'delimiter' } },
      ],

      // Delimiters
      [/[,:]/, 'delimiter'],

      // Strings
      [/"([^"\\]|\\.)*$/, 'string.invalid'],
      [/'([^'\\]|\\.)*$/, 'string.invalid'],
      [/"/, 'string', '@string_double'],
      [/'/, 'string', '@string_single'],
    ],

    string_double: [
      [/[^\\"]+/, 'string'],
      [/@escapes/, 'string.escape'],
      [/\\./, 'string.escape.invalid'],
      [/"/, 'string', '@pop'],
    ],

    string_single: [
      [/[^\\']+/, 'string'],
      [/@escapes/, 'string.escape'],
      [/\\./, 'string.escape.invalid'],
      [/'/, 'string', '@pop'],
    ],

    whitespace: [
      [/[ \t\r\n]+/, 'white'],
      [/#.*$/, 'comment'],
    ],
  },
}
