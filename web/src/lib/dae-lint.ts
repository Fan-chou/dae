export type DaeLintKind = "config" | "routing";

export type DaeLintIssue = {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  message: string;
  severity: "error" | "warning";
};

const nodeURIScheme = /(hy2|hysteria2?|ssr?|vmess|vless|trojan|tuic|juicity|anytls|socks5?):\/\//i;
const allowedConfigSections = new Set(["global", "routing"]);

export function lintDae(src: string, kind: DaeLintKind): DaeLintIssue[] {
  const issues: DaeLintIssue[] = [];
  const text = String(src || "");
  const lines = text.split(/\n/);
  let depth = 0;
  let inString: "'" | '"' | "" = "";
  let section = "";
  let sectionLine = 1;

  const push = (line: number, column: number, endColumn: number, message: string, severity: DaeLintIssue["severity"] = "error"): void => {
    issues.push({ line, column, endLine: line, endColumn: Math.max(endColumn, column + 1), message, severity });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;
    let j = 0;
    while (j < line.length) {
      const ch = line[j];
      if (inString) {
        if (ch === "\\" && j + 1 < line.length) {
          j += 2;
          continue;
        }
        if (ch === inString) inString = "";
        j++;
        continue;
      }
      if (ch === "#" || (ch === "/" && line[j + 1] === "/")) break;
      if (ch === "'" || ch === '"') {
        inString = ch;
        j++;
        continue;
      }
      if (ch === "{") {
        depth++;
        j++;
        continue;
      }
      if (ch === "}") {
        depth--;
        if (depth < 0) {
          push(lineNo, j + 1, j + 2, "多余的 }");
          depth = 0;
        }
        if (depth === 0) section = "";
        j++;
        continue;
      }
      if (depth === 0 && /[A-Za-z_]/.test(ch)) {
        const start = j;
        j++;
        while (j < line.length && /[A-Za-z0-9_]/.test(line[j])) j++;
        const name = line.slice(start, j);
        let k = j;
        while (k < line.length && /[ \t]/.test(line[k])) k++;
        if (line[k] === "{") {
          section = name.toLowerCase();
          sectionLine = lineNo;
          if (kind === "config" && !allowedConfigSections.has(section)) {
            push(lineNo, start + 1, j + 1, "配置页不能编辑 " + name + " 段");
          }
          if (section === "node" || section === "subscription") {
            push(lineNo, start + 1, j + 1, name + " 不能在此编辑");
          }
        }
        continue;
      }
      j++;
    }
    if (inString) {
      push(lineNo, 1, line.length + 1, "未闭合的字符串");
      inString = "";
    }
    if (nodeURIScheme.test(line)) {
      push(lineNo, 1, line.length + 1, "节点 URI 不允许出现在配置里");
    }
    if (line.includes("nodes.dae")) {
      push(lineNo, 1, line.length + 1, "不能在此引用 nodes.dae");
    }
    if (kind === "routing" && line.includes("://") && !nodeURIScheme.test(line) && !/^\s*(#|\/\/)/.test(line)) {
      push(lineNo, 1, line.length + 1, "routing.dae 不允许出现 URI", "warning");
    }
  }
  if (depth > 0) {
    push(sectionLine, 1, 2, "有 " + String(depth) + " 个未闭合的 {");
  }
  return issues;
}
