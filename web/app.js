(() => {
  const { createApp, reactive, computed, onMounted, onUnmounted } = Vue;
  const storageKey = "kdae-ui-settings";
  const pageKey = "kdae-ui-page";
  const pages = ["groups", "status", "logs", "settings"];
  const chipKeys = ["dialer", "network", "sniffed", "ip", "policy", "pname"];
  const sensitiveKey = /password|secret|token|uri|url|auth|key$/i;

  function pageFromHash() {
    const raw = (location.hash || "").replace(/^#\/?/, "").trim();
    const name = decodeURIComponent((raw.split(/[/?#]/)[0] || "").toLowerCase());
    return pages.indexOf(name) >= 0 ? name : "";
  }

  function savedPage() {
    try {
      const name = localStorage.getItem(pageKey) || "";
      return pages.indexOf(name) >= 0 ? name : "";
    } catch {
      return "";
    }
  }

  function rememberPage(page) {
    try { localStorage.setItem(pageKey, page); } catch {}
  }

  function writeHash(page, replace) {
    const next = "#/" + page;
    if (location.hash === next) return;
    if (replace && window.history && history.replaceState) {
      history.replaceState(null, "", next);
      return;
    }
    location.hash = next;
  }

  function resolvePage() {
    return pageFromHash() || savedPage() || "groups";
  }

  function kindLabel(kind) {
    if (kind === "conn") return "连接";
    if (kind === "dns") return "DNS";
    return "系统";
  }

  function defaultBaseUrl() {
    if (location.protocol === "https:" || location.pathname.indexOf("/kdae-ui") === 0) {
      return location.origin + "/cgi-bin/kdae-proxy";
    }
    return "http://192.168.124.223:2025";
  }

  function loadSettings() {
    const defaults = { baseUrl: defaultBaseUrl(), secret: "" };
    try {
      const saved = Object.assign({}, defaults, JSON.parse(localStorage.getItem(storageKey) || "{}"));
      if (location.protocol === "https:" && /^http:\/\//.test(saved.baseUrl || "")) {
        saved.baseUrl = defaultBaseUrl();
      }
      return saved;
    } catch {
      return defaults;
    }
  }

  function latencyClass(member) {
    if (!member || !member.alive || member.latency_ms == null) return "dead";
    if (member.latency_ms < 150) return "ok";
    if (member.latency_ms < 400) return "warn";
    return "bad";
  }

  function latencyText(member) {
    if (!member || !member.alive) return "超时";
    if (member.latency_ms == null) return "—";
    return member.latency_ms + " ms";
  }

  function policyLabel(policy) {
    if (policy === "first_alive") return "first_alive（fallback，自动）";
    if (policy === "fixed") return "fixed（select）";
    if (policy === "min_avg10") return "min_avg10（url-test）";
    if (policy === "min_moving_avg") return "min_moving_avg（url-test）";
    if (policy === "min") return "min（url-test）";
    return policy || "—";
  }

  function displayedSelected(group) {
    if (group && group.selected) return group.selected;
    const members = (group && group.members) || [];
    if (group && group.policy === "first_alive") {
      const alive = members.find((m) => m.alive);
      return alive ? alive.name : "检查中";
    }
    if (group && group.policy && group.policy.indexOf("min") === 0) {
      const alive = members.filter((m) => m.alive && m.latency_ms != null);
      if (!alive.length) return "检查中";
      alive.sort((a, b) => a.latency_ms - b.latency_ms);
      return alive[0].name;
    }
    return "—";
  }

  function unescapeLogValue(raw) {
    if (raw.charAt(0) !== '"') return raw;
    try {
      return JSON.parse(raw);
    } catch {
      return raw.slice(1, -1).replace(/\\"/g, '"');
    }
  }

  function parseLogrusFields(raw) {
    const fields = {};
    const re = /([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"\\])*"|[^\s]*)/g;
    let match;
    while ((match = re.exec(raw))) {
      fields[match[1]] = unescapeLogValue(match[2]);
    }
    return fields;
  }

  function normalizeLevel(level) {
    const value = String(level || "info").toLowerCase();
    if (value === "warn") return "warning";
    return value;
  }

  function formatTimeShort(time) {
    if (!time) return "";
    const clock = String(time).match(/(\d{2}:\d{2}:\d{2})/);
    if (clock) return clock[1];
    const parsed = new Date(time);
    if (!isNaN(parsed.getTime())) {
      return parsed.toTimeString().slice(0, 8);
    }
    return String(time);
  }

  function parseConn(msg) {
    const token = " <-> ";
    const idx = String(msg).indexOf(token);
    if (idx === -1) return null;
    return { from: msg.slice(0, idx), to: msg.slice(idx + token.length) };
  }

  function classifyLog(msg, fields) {
    if (parseConn(msg) || fields.outbound || fields.dialer) return "conn";
    if (/dns/i.test(msg) || fields.upstream) return "dns";
    return "sys";
  }

  function parsePrefixedLine(raw) {
    return raw.match(/^(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|PANIC)\s*\[([^\]]*)\]\s*(.*)$/i);
  }

  function parseLogLine(raw, seq) {
    const line = String(raw).replace(/\r$/, "");
    let level = "info";
    let time = "";
    let msg = line;
    let fields = {};

    if (line.charAt(0) === "{") {
      try {
        const obj = JSON.parse(line);
        level = normalizeLevel(obj.level || obj.type || "info");
        time = obj.time || obj.timestamp || "";
        msg = obj.msg || obj.message || obj.payload || line;
        fields = obj;
      } catch {
        fields = {};
      }
    } else {
      const prefixed = parsePrefixedLine(line);
      if (prefixed) {
        level = normalizeLevel(prefixed[1]);
        time = prefixed[2];
        const rest = prefixed[3] || "";
        const split = rest.match(/\s+([A-Za-z_][A-Za-z0-9_]*)=/);
        if (split) {
          msg = rest.slice(0, split.index).trim() || msg;
          fields = parseLogrusFields(rest.slice(split.index));
          if (fields.msg) msg = fields.msg;
        } else {
          msg = rest.trim();
          fields = parseLogrusFields(rest);
        }
      } else {
        fields = parseLogrusFields(line);
        if (fields.level || fields.msg) {
          level = normalizeLevel(fields.level || "info");
          time = fields.time || fields.timestamp || "";
          msg = fields.msg || line;
        }
      }
    }

    const conn = parseConn(msg);
    const kind = classifyLog(msg, fields);
    return {
      seq,
      seqLabel: String(seq).padStart(3, "0"),
      raw: line,
      level,
      time,
      timeShort: formatTimeShort(time),
      msg,
      fields,
      conn,
      kind,
      kindLabel: kindLabel(kind),
      match: fields.outbound || "",
      chips: logChips(fields),
    };
  }

  function parseLogLineSafe(raw, seq) {
    try {
      return parseLogLine(raw, seq);
    } catch {
      return {
        seq,
        seqLabel: String(seq).padStart(3, "0"),
        raw: String(raw),
        level: "info",
        time: "",
        timeShort: "",
        msg: String(raw),
        fields: {},
        conn: null,
        kind: "sys",
        kindLabel: "系统",
        match: "",
        chips: [],
      };
    }
  }

  function logChips(fields) {
    const chips = [];
    for (let i = 0; i < chipKeys.length; i++) {
      const key = chipKeys[i];
      const value = fields[key];
      if (value == null || value === "") continue;
      if (sensitiveKey.test(key)) continue;
      if (String(value).indexOf("://") !== -1) continue;
      chips.push({ k: key, v: String(value) });
    }
    return chips;
  }

  function highlightParts(text, query) {
    const src = text == null ? "" : String(text);
    const needle = (query || "").trim();
    if (!src || !needle) return [{ t: src, h: false }];
    const lower = src.toLowerCase();
    const find = needle.toLowerCase();
    const parts = [];
    let i = 0;
    while (i < src.length) {
      const j = lower.indexOf(find, i);
      if (j < 0) {
        parts.push({ t: src.slice(i), h: false });
        break;
      }
      if (j > i) parts.push({ t: src.slice(i, j), h: false });
      parts.push({ t: src.slice(j, j + find.length), h: true });
      i = j + find.length;
    }
    return parts.length ? parts : [{ t: src, h: false }];
  }

  createApp({
    setup() {
      const state = reactive({
        page: resolvePage(),
        settings: loadSettings(),
        status: null,
        groups: [],
        logs: [],
        logFilter: "",
        logLevel: "",
        logKind: "",
        logPaused: false,
        error: "",
        notice: "",
        loading: false,
      });
      let timer = 0;

      async function api(path, options) {
        const headers = Object.assign(
          {
            Authorization: "Bearer " + state.settings.secret,
            "X-Kdae-Authorization": "Bearer " + state.settings.secret,
          },
          options && options.headers
        );
        const response = await fetch(state.settings.baseUrl.replace(/\/$/, "") + path, Object.assign({}, options, { headers }));
        const text = await response.text();
        let body = null;
        if (text) {
          try { body = JSON.parse(text); } catch { body = { error: text }; }
        }
        if (!response.ok) {
          throw new Error((body && body.error) || ("HTTP " + response.status));
        }
        return body;
      }

      async function refresh() {
        if (!state.settings.secret) {
          state.error = "请先在设置里填写 admin_secret";
          return;
        }
        state.loading = true;
        try {
          const status = await api("/v1/status");
          state.status = status;
          if (state.page === "groups") {
            const body = await api("/v1/groups");
            state.groups = body.groups || [];
          }
          if (state.page === "logs" && !state.logPaused) {
            const body = await api("/v1/logs?n=300");
            const lines = body.lines || [];
            state.logs = lines.map((raw, i) => parseLogLineSafe(raw, i + 1)).reverse();
          }
          state.error = "";
        } catch (err) {
          state.error = String(err.message || err);
        } finally {
          state.loading = false;
        }
      }

      async function selectMember(group, member) {
        state.notice = "";
        try {
          await api("/v1/groups/" + encodeURIComponent(group.name), {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ member: member.name }),
          });
          group.selected = member.name;
          state.notice = "已切换 " + group.name + " → " + member.name + "（未 reload）";
        } catch (err) {
          state.error = String(err.message || err);
        }
      }

      async function reload() {
        try {
          const body = await api("/v1/reload", { method: "POST" });
          state.notice = body.queued ? "已排队热重载" : "重载忙，稍后再试";
        } catch (err) {
          state.error = String(err.message || err);
        }
      }

      function goPage(page) {
        if (pages.indexOf(page) < 0) page = "groups";
        state.page = page;
        rememberPage(page);
        writeHash(page, false);
        refresh();
      }

      function onHashChange() {
        const page = pageFromHash() || "groups";
        if (state.page === page) return;
        state.page = page;
        rememberPage(page);
        refresh();
      }

      function saveSettings() {
        localStorage.setItem(storageKey, JSON.stringify(state.settings));
        state.notice = "已保存本地设置";
        refresh();
      }

      function toggleLogPause() {
        state.logPaused = !state.logPaused;
        if (!state.logPaused) refresh();
      }

      function clearLogs() {
        state.logs = [];
        state.logPaused = true;
      }

      function downloadLogs() {
        const lines = filteredLogs.value.map((entry) => {
          return [entry.seqLabel, entry.timeShort || "-", entry.level.padEnd(7, " "), entry.msg].join("  ");
        });
        const blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "kdae-logs.txt";
        a.click();
        URL.revokeObjectURL(url);
      }

      const filteredLogs = computed(() => {
        const q = (state.logFilter || "").trim().toLowerCase();
        return state.logs.filter((entry) => {
          if (state.logLevel && entry.level !== state.logLevel) return false;
          if (state.logKind && entry.kind !== state.logKind) return false;
          if (!q) return true;
          return entry.raw.toLowerCase().indexOf(q) !== -1;
        });
      });

      const generation = computed(() => (state.status && (state.status.generation || "—")) || "—");

      onMounted(() => {
        const page = resolvePage();
        state.page = page;
        rememberPage(page);
        if (pageFromHash() !== page) writeHash(page, true);
        window.addEventListener("hashchange", onHashChange);
        refresh();
        timer = setInterval(refresh, 5000);
      });
      onUnmounted(() => {
        window.removeEventListener("hashchange", onHashChange);
        clearInterval(timer);
      });

      return {
        state,
        generation,
        filteredLogs,
        highlightParts,
        latencyClass,
        latencyText,
        policyLabel,
        displayedSelected,
        refresh,
        goPage,
        selectMember,
        reload,
        saveSettings,
        toggleLogPause,
        clearLogs,
        downloadLogs,
      };
    },
    template: `
      <div class="shell">
        <div class="top">
          <div class="brand">kdae</div>
          <div class="nav">
            <a href="#/groups" :class="{active: state.page==='groups'}" @click.prevent="goPage('groups')">组</a>
            <a href="#/status" :class="{active: state.page==='status'}" @click.prevent="goPage('status')">状态</a>
            <a href="#/logs" :class="{active: state.page==='logs'}" @click.prevent="goPage('logs')">日志</a>
            <a href="#/settings" :class="{active: state.page==='settings'}" @click.prevent="goPage('settings')">设置</a>
            <button class="ghost" @click="reload">热重载</button>
          </div>
        </div>
        <div v-if="state.error" class="error">{{ state.error }}</div>
        <div v-if="state.notice" class="okbox">{{ state.notice }}</div>
        <div v-if="state.status && state.status.sync_warning" class="banner">{{ state.status.sync_warning }}</div>

        <div v-if="state.page==='status'" class="status-grid">
          <div class="card"><div class="muted">版本</div><div>{{ state.status && state.status.version || '—' }}</div></div>
          <div class="card"><div class="muted">运行</div><div>{{ state.status && state.status.running ? '运行中' : '未连接' }}</div></div>
          <div class="card"><div class="muted">generation</div><div>{{ generation }}</div></div>
          <div class="card"><div class="muted">LAN</div><div>{{ (state.status && state.status.lan_interface || []).join(', ') || '—' }}</div></div>
          <div class="card"><div class="muted">WAN</div><div>{{ (state.status && state.status.wan_interface || []).join(', ') || '（空，不劫持本机）' }}</div></div>
        </div>

        <div v-if="state.page==='groups'" class="group-grid">
          <div class="card" v-for="group in state.groups" :key="group.name">
            <h2>{{ group.name }}</h2>
            <div class="muted">策略 {{ policyLabel(group.policy) }} · 当前 <span class="selected">{{ displayedSelected(group) }}</span></div>
            <div
              class="member"
              :class="{current: member.name === displayedSelected(group)}"
              v-for="member in group.members"
              :key="member.name"
              @click="group.selectable && selectMember(group, member)"
            >
              <span>{{ member.name }}</span>
              <span class="latency" :class="latencyClass(member)">{{ latencyText(member) }}</span>
            </div>
          </div>
        </div>

        <div v-if="state.page==='logs'" class="logs-page">
          <div class="log-toolbar">
            <select v-model="state.logLevel">
              <option value="">级别</option>
              <option value="trace">trace</option>
              <option value="debug">debug</option>
              <option value="info">info</option>
              <option value="warning">warning</option>
              <option value="error">error</option>
            </select>
            <select v-model="state.logKind">
              <option value="">全部类型</option>
              <option value="conn">连接</option>
              <option value="dns">DNS</option>
              <option value="sys">系统</option>
            </select>
            <input class="log-search" v-model="state.logFilter" placeholder="搜索 payload / outbound / dialer" />
            <button class="ghost" :class="{on: state.logPaused}" @click="toggleLogPause">{{ state.logPaused ? '继续' : '暂停' }}</button>
            <button class="ghost" @click="clearLogs">清空</button>
            <button class="ghost" @click="downloadLogs">下载</button>
            <span class="log-count">{{ filteredLogs.length }} / {{ state.logs.length }}</span>
          </div>
          <div class="log-list">
            <div v-if="!filteredLogs.length" class="log-empty">{{ state.logPaused && !state.logs.length ? '已清空（已暂停刷新）' : '暂无日志' }}</div>
            <article class="log-card" :class="entry.level" v-for="entry in filteredLogs" :key="entry.seq">
              <div class="log-head">
                <span class="log-seq">{{ entry.seqLabel }}</span>
                <span class="log-time" v-if="entry.timeShort">{{ entry.timeShort }}</span>
                <span class="log-level" :class="entry.level">{{ entry.level }}</span>
                <span class="log-kind" :class="entry.kind">{{ entry.kindLabel }}</span>
                <span class="log-match" v-if="entry.match">{{ entry.match }}</span>
              </div>
              <div class="log-payload">
                <div v-if="entry.conn" class="log-conn">
                  <span class="log-ep from">
                    <span v-for="(part, i) in highlightParts(entry.conn.from, state.logFilter)" :key="'f'+i" :class="{mark: part.h}">{{ part.t }}</span>
                  </span>
                  <span class="log-arrow">↔</span>
                  <span class="log-ep to">
                    <span v-for="(part, i) in highlightParts(entry.conn.to, state.logFilter)" :key="'t'+i" :class="{mark: part.h}">{{ part.t }}</span>
                  </span>
                </div>
                <div v-else>
                  <span v-for="(part, i) in highlightParts(entry.msg, state.logFilter)" :key="'m'+i" :class="{mark: part.h}">{{ part.t }}</span>
                </div>
              </div>
              <div class="log-chips" v-if="entry.chips.length">
                <span class="log-chip" :class="chip.k" v-for="chip in entry.chips" :key="chip.k">
                  <b>{{ chip.k }}</b>
                  <span v-for="(part, i) in highlightParts(chip.v, state.logFilter)" :key="chip.k+i" :class="{mark: part.h}">{{ part.t }}</span>
                </span>
              </div>
            </article>
          </div>
        </div>

        <div v-if="state.page==='settings'" class="card form">
          <p class="muted">面板只打 kdae <code>/v1</code>，不是 Clash API。HTTPS 下默认走同源反代，避免被浏览器拦截。密钥只存在浏览器本地。</p>
          <label>admin_listen 地址
            <input v-model="state.settings.baseUrl" placeholder="/cgi-bin/kdae-proxy" />
          </label>
          <label>admin_secret
            <input v-model="state.settings.secret" type="password" placeholder="Bearer token" />
          </label>
          <div class="row">
            <button class="ghost" @click="saveSettings">保存</button>
            <button class="ghost" @click="refresh">测试连接</button>
          </div>
        </div>
      </div>
    `,
  }).mount("#app");
})();
