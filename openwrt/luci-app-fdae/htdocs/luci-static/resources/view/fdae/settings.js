'use strict';
'require form';
'require fs';
'require poll';
'require uci';
'require ui';
'require view';

const INIT = '/etc/init.d/dae';
const DAE = '/usr/bin/dae';
const CONFIG = '/etc/dae/config.dae';

function parseLines(text) {
	const out = {};
	String(text || '').split('\n').forEach(function (line) {
		const i = line.indexOf('=');
		if (i > 0)
			out[line.slice(0, i)] = line.slice(i + 1);
	});
	return out;
}

function runInit(args) {
	return L.resolveDefault(fs.exec(INIT, args), { code: 1, stdout: '', stderr: '' });
}

function loadPending() {
	return runInit(['pending']).then(function (res) { return parseLines(res.stdout); });
}

// What dae knows about its Mihomo source; null while dae is down.
function loadMihomo() {
	return L.resolveDefault(fs.exec(DAE, ['mihomo', 'status', '-c', CONFIG]), null).then(function (res) {
		if (!res || res.code || !res.stdout)
			return null;
		try {
			return JSON.parse(res.stdout);
		} catch (e) {
			return null;
		}
	});
}

// The inbounds dae knows, with where each comes from and whether it listens;
// null while dae is down.
function loadInbounds() {
	return L.resolveDefault(fs.exec(DAE, ['inbound', 'status', '-c', CONFIG]), null).then(function (res) {
		if (!res || res.code || !res.stdout)
			return null;
		try {
			return JSON.parse(res.stdout);
		} catch (e) {
			return null;
		}
	});
}

function notify(res, okMsg) {
	const text = [res.stdout, res.stderr].filter(Boolean).join('\n').trim();
	// A failed call that printed nothing is almost always a dropped connection
	// (the service restarting under the page); say so instead of showing an
	// empty red box.
	ui.addNotification(null, E('pre', {}, text || (res.code ? _('命令没有返回内容，连接可能被中断，请刷新页面确认状态。') : okMsg)),
		res.code ? 'error' : 'info');
}

function button(style, label, handler) {
	const b = E('button', { type: 'button', class: 'cbi-button cbi-button-' + style }, label);
	b.addEventListener('click', function (ev) {
		ev.preventDefault();
		if (b.disabled)
			return;
		b.disabled = true;
		Promise.resolve(handler()).catch(function (e) {
			ui.addNotification(null, E('p', {}, (e && e.message) || String(e || _('操作失败'))), 'error');
		}).finally(function () {
			b.disabled = false;
		});
	});
	return b;
}

function ago(iso) {
	const t = Date.parse(iso);
	if (!t)
		return '—';
	const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
	if (sec < 90)
		return _('%d 秒前').format(sec);
	if (sec < 5400)
		return _('%d 分钟前').format(Math.round(sec / 60));
	return _('%d 小时前').format(Math.round(sec / 3600));
}

function row(key, value) {
	return E('tr', { class: 'tr' }, [
		E('td', { class: 'td', style: 'width:9em;opacity:.7' }, key),
		E('td', { class: 'td' }, value)
	]);
}

function sourceBlock(st) {
	if (!st)
		return E('em', {}, _('dae 未运行，或管理接口不可用。运行后这里显示路由源状态。'));
	const m = st.mihomo || {};
	if (!m.enabled)
		return E('span', {}, _('未配置路由源'));

	let status;
	if (m.degraded)
		status = E('strong', { style: 'color:red' }, _('不可用，已不带路由源启动，正在重试'));
	else if (m.error)
		status = E('strong', { style: 'color:red' }, _('读取失败'));
	else if (m.used_last_good)
		status = E('strong', { style: 'color:#c80' }, _('使用上一份有效副本'));
	else
		status = E('strong', { style: 'color:green' }, _('正常'));

	const kids = [E('table', { class: 'table' }, [
		row(_('状态'), status),
		row(_('来源'), m.source || '—'),
		row(_('最近检查'), ago(m.checked_at)),
		row(_('内容'), _('%d 节点 · %d 分组 · %d 规则 · %d 规则集').format(m.nodes || 0, m.groups || 0, m.rules || 0, m.providers || 0))
	])];
	if (m.error)
		kids.push(E('pre', { style: 'white-space:pre-wrap;word-break:break-all;color:red' }, m.error));
	const skipped = m.skipped_rules || [];
	if (skipped.length)
		kids.push(E('details', {}, [
			E('summary', {}, _('被跳过或忽略的规则 (%d)').format(skipped.length)),
			E('pre', { style: 'white-space:pre-wrap;word-break:break-all' },
				skipped.map(function (r) {
					return '[' + r.kind + '] ' + (r.line ? 'L' + r.line + ' ' : '') + r.rule + ' — ' + r.reason;
				}).join('\n'))
		]));
	return E('div', {}, kids);
}

const LISTEN_RE = /^(?:(\d{1,3}(?:\.\d{1,3}){3})|\[([0-9A-Fa-f:.]+)\]):(\d{1,5})$/;

function validListen(v) {
	const m = LISTEN_RE.exec(String(v || '').trim());
	if (!m)
		return _('写成 IP:端口，IPv6 写成 [地址]:端口');
	const port = parseInt(m[3], 10);
	if (port < 1 || port > 65535)
		return _('端口范围 1–65535');
	if (m[1] && m[1].split('.').some(function (o) { return parseInt(o, 10) > 255; }))
		return _('不是有效的 IPv4 地址');
	return true;
}

// Names of the inbounds that this page owns (the UCI sections).
function uciInboundNames() {
	const names = {};
	(uci.sections('dae', 'inbound') || []).forEach(function (sec) {
		if (sec.name)
			names[sec.name] = true;
	});
	return names;
}

function inboundBlock(st) {
	if (!st)
		return E('em', {}, _('dae 未运行，或管理接口不可用。运行后这里显示各入站的状态。'));
	const list = st.inbounds || [];
	if (!list.length)
		return E('em', {}, _('没有入站。'));
	const mine = uciInboundNames();
	const origins = { config: 'config.dae', routing: 'routing.dae', managed: _('其它文件') };
	const state = {
		listening: [ _('监听中'), 'green' ],
		pending: [ _('已保存，等待重载'), '#c80' ],
		failed: [ _('启动失败'), 'red' ]
	};
	const rows = list.map(function (ib) {
		const s = state[ib.state] || [ ib.state, '' ];
		const auth = ib.username ? ib.username + (ib.has_password ? ' / ••••' : '') : _('无');
		const origin = mine[ib.name] ? _('本页') : (origins[ib.origin] || ib.origin);
		const cells = [
			E('td', { class: 'td' }, E('strong', {}, ib.name)),
			E('td', { class: 'td' }, E('code', {}, ib.listen)),
			E('td', { class: 'td' }, auth),
			E('td', { class: 'td' }, [ ib.udp ? 'TCP+UDP' : 'TCP', ' · ', ib.sniff, ' · ', ib.resolve ]),
			E('td', { class: 'td' }, E('strong', { style: 'color:' + s[1] }, s[0])),
			E('td', { class: 'td' }, _('%d 连接 / %d UDP').format(ib.conns || 0, ib.udp_sessions || 0)),
			E('td', { class: 'td' }, origin)
		];
		const tr = E('tr', { class: 'tr' }, cells);
		if (ib.error)
			return [ tr, E('tr', { class: 'tr' }, E('td', { class: 'td', colspan: 7, style: 'color:red;word-break:break-all' }, ib.error)) ];
		return [ tr ];
	}).reduce(function (a, b) { return a.concat(b); }, []);
	return E('table', { class: 'table' }, [
		E('tr', { class: 'tr table-titles' }, [ _('名称'), _('监听'), _('认证'), _('协议 · 嗅探 · 解析'), _('状态'), _('当前'), _('来源') ].map(function (t) {
			return E('th', { class: 'th' }, t);
		}))
	].concat(rows));
}

return view.extend({
	load() {
		return Promise.all([uci.load('dae'), loadMihomo(), loadInbounds()]);
	},

	render(data) {
		const nodeNames = (data[1] && data[1].node_names) || {};
		const names = Object.keys(nodeNames).sort();
		const listen = uci.get('dae', 'config', 'admin_listen');
		const m = new form.Map('dae', _('fdae'));

		let s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			const head = E('div', { style: 'display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:8px' });
			const banner = E('div', { style: 'display:none;margin-bottom:8px;padding:8px 12px;border:1px solid #c80;border-radius:4px' });
			const progress = E('div', { style: 'margin-bottom:8px' });
			const source = E('div', {});

			function paint(p) {
				const running = p.running === '1';
				head.replaceChildren(
					E('strong', { style: 'color:' + (running ? 'green' : 'red') }, running ? _('运行中') : _('未运行')),
					E('span', { style: 'opacity:.7' }, p.running_version || p.installed_version || ''),
					listen
						? E('a', { class: 'cbi-button', href: 'http://' + listen + '/fdae-ui/', target: '_blank', rel: 'noreferrer' }, _('打开面板'))
						: E('em', { style: 'opacity:.7' }, _('设置 API 地址后可打开面板'))
				);
				if (p.pending === '1') {
					banner.style.display = '';
					banner.replaceChildren(
						E('div', { style: 'margin-bottom:6px' },
							p.installed_version === p.running_version
								? _('已安装新的构建（版本号相同），运行中的还是旧构建。')
								: _('已安装新版本（%s），运行中的仍是 %s。').format(p.installed_version || '?', p.running_version || '?')),
						button('apply', _('切换到新版本'), startSwitch),
						E('span', { style: 'margin-left:8px;opacity:.7' },
							_('会短暂重启；新版本没起来时自动换回旧版本。'))
					);
				} else {
					banner.style.display = 'none';
				}
			}

			function refresh() {
				return Promise.all([loadPending(), loadMihomo()]).then(function (r) {
					paint(r[0]);
					source.replaceChildren(sourceBlock(r[1]));
				});
			}

			// While dae restarts the router may not answer for a moment; an
			// empty reply then means "still going", not "nothing to show".
			function showSwitch(waiting) {
				return runInit(['switch_state']).then(function (res) {
					if (waiting && res.code && !res.stdout) {
						progress.replaceChildren(E('strong', { style: 'color:#c80' }, _('正在切换，连接可能短暂中断…')));
						return true;
					}
					const st = parseLines(res.stdout);
					if (!st.state || st.state === 'idle')
						return false;
					const color = st.state === 'ok' ? 'green' : st.state === 'failed' ? 'red' : '#c80';
					progress.replaceChildren(E('strong', { style: 'color:' + color }, st.message || st.state));
					return st.state === 'running';
				});
			}

			function followSwitch(since) {
				since = since || Date.now();
				return showSwitch(true).then(function (busy) {
					if (busy && Date.now() - since < 180000)
						return new Promise(function (ok) { setTimeout(ok, 2000); }).then(function () { return followSwitch(since); });
					return refresh();
				});
			}

			function startSwitch() {
				return runInit(['switch']).then(function (res) {
					// Failed without a word: the connection dropped, but the
					// switch may well have started; follow it instead of failing.
					if (res.code && (res.stdout || res.stderr))
						return notify(res, '');
					return followSwitch();
				});
			}

			function act(args, okMsg) {
				return runInit(args).then(function (res) {
					notify(res, okMsg);
					return refresh();
				});
			}

			poll.add(refresh);
			showSwitch();

			return E('div', { class: 'cbi-section' }, [
				head, banner, progress,
				E('div', { style: 'display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px' }, [
					button('apply', _('启动'), function () { return act(['start'], _('已启动')); }),
					button('reset', _('停止'), function () { return act(['stop'], _('已停止')); }),
					button('reload', _('应用设置'), function () { return act(['apply'], _('已应用')); }),
					button('remove', _('清除残留'), function () {
						if (!window.confirm(_('将停止 fdae 并清除 eBPF/TC 残留。继续？')))
							return Promise.resolve();
						return act(['recover'], _('残留已清除'));
					})
				]),
				source
			]);
		};

		s = m.section(form.NamedSection, 'config', 'dae', _('接口'));
		let o = s.option(form.Flag, 'enabled', _('启用'));
		o = s.option(form.Value, 'lan_interface', _('LAN'), _('逗号分隔的接口名'));
		o.placeholder = 'br-lan';
		o = s.option(form.Value, 'wan_interface', _('WAN'), _('留空则不代理本机'));
		o = s.option(form.Value, 'admin_listen', _('API 地址'), _('LAN 上的 ip:port，面板也在这个地址。不要用 0.0.0.0'));
		o.placeholder = '192.168.1.1:2025';
		o = s.option(form.Value, 'admin_secret', _('API 密钥'));
		o.password = true;

		s = m.section(form.NamedSection, 'config', 'dae', _('路由源'),
			_('完整的 Mihomo 配置由 dae 自己读取、转换并合并，保留上一份有效副本。'));
		o = s.option(form.Value, 'mihomo_config', _('本地 YAML'), _('填写则覆盖下面的“完整配置”订阅'));
		o.placeholder = '/etc/dae/mihomo.yaml';
		o = s.option(form.Value, 'mihomo_interval', _('刷新间隔'), _('留空为 1h'));
		o.placeholder = '1h';
		o = s.option(form.Value, 'isolate_transport_groups', _('独立传输的分组'), _('逗号分隔；这些分组的每个节点各用一条独立连接'));

		s = m.section(form.TypedSection, 'subscription', _('订阅'));
		s.anonymous = true;
		s.addremove = true;
		s.addbtntitle = _('添加');
		o = s.option(form.Value, 'tag', _('标签'));
		o.placeholder = 'main';
		o = s.option(form.Value, 'url', _('链接'));
		o.password = true;
		o.rmempty = false;
		o = s.option(form.ListValue, 'role', _('用途'));
		o.value('routing', _('完整配置'));
		o.value('nodes', _('仅节点'));
		o.default = 'routing';

		s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			const box = E('div', { id: 'fdae-inbound-status' }, inboundBlock(data[2]));
			poll.add(function () {
				return loadInbounds().then(function (st) {
					box.replaceChildren(inboundBlock(st));
				});
			});
			return E('div', { class: 'cbi-section' }, [
				E('h3', {}, _('入站状态')),
				E('div', { class: 'cbi-section-descr' },
					_('包含所有来源的入站（本页、config.dae、routing.dae）。要让流量走某个入站的规则，在“配置”页写 inbound(名称)。')),
				box
			]);
		};

		s = m.section(form.GridSection, 'inbound', _('入站'),
			_('SOCKS5 监听（TCP CONNECT 与 UDP ASSOCIATE）。保存并应用后生效。监听 0.0.0.0、[::] 或公网地址时必须设置用户名和密码。'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;
		s.addbtntitle = _('添加入站');
		s.modaltitle = _('入站');

		o = s.option(form.Flag, 'enabled', _('启用'));
		o.default = o.enabled;
		o.editable = true;
		o.rmempty = false;

		o = s.option(form.Value, 'name', _('名称'), _('规则里写 inbound(名称)；1–32 位字母、数字、_ 或 -'));
		o.rmempty = false;
		o.placeholder = 's1';
		o.validate = function (section_id, value) {
			if (!/^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$/.test(value || ''))
				return _('1–32 位字母、数字、_ 或 -');
			let dup = false;
			(uci.sections('dae', 'inbound') || []).forEach(function (sec) {
				if (sec['.name'] !== section_id && sec.name === value)
					dup = true;
			});
			return dup ? _('名称已被使用') : true;
		};

		o = s.option(form.Value, 'listen', _('监听地址'), _('IP:端口，IPv6 写成 [地址]:端口'));
		o.rmempty = false;
		o.placeholder = '127.0.0.1:1080';
		o.validate = function (section_id, value) { return validListen(value); };

		o = s.option(form.Value, 'username', _('用户名'), _('与密码同时填写才启用认证'));
		o.modalonly = false;
		o.rmempty = true;

		o = s.option(form.Value, 'password', _('密码'));
		o.password = true;
		o.modalonly = true;
		o.rmempty = true;
		o.validate = function (section_id, value) {
			const user = this.section.formvalue(section_id, 'username');
			if ((user ? true : false) !== (value ? true : false))
				return _('用户名和密码要同时填写');
			return true;
		};

		o = s.option(form.Flag, 'udp', _('UDP'), _('允许 UDP ASSOCIATE'));
		o.default = o.enabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.ListValue, 'sniff', _('嗅探'), _('自动：对 IP 目标先应答再嗅探 TLS SNI / HTTP Host；关闭：先拨号，SOCKS5 错误码更精确'));
		o.value('auto', _('自动'));
		o.value('off', _('关闭'));
		o.default = 'auto';
		o.modalonly = true;

		o = s.option(form.ListValue, 'resolve', _('域名解析'), _('本地：先解析再路由；延后：先按域名路由，走代理的域名由节点解析，dae 不查询'));
		o.value('local', _('本地'));
		o.value('deferred', _('延后'));
		o.default = 'local';
		o.modalonly = true;

		o = s.option(form.Value, 'udp_advertise', _('UDP 中继地址'), _('dae 在 NAT 或端口转发之后时，告诉客户端的 UDP 地址；留空自动'));
		o.datatype = 'ipaddr';
		o.modalonly = true;
		o.rmempty = true;

		s = m.section(form.NamedSection, 'config', 'dae', _('地理数据'),
			_('geoip() 与 geosite 规则用的数据文件。填写链接后由 dae 自己下载、校验并定期更新，失败时保留旧文件。'));
		o = s.option(form.Value, 'geoip_url', _('geoip.dat'));
		o.placeholder = 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat';
		o = s.option(form.Value, 'geosite_url', _('geosite.dat'));
		o.placeholder = 'https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat';
		o = s.option(form.Value, 'geodata_interval', _('更新间隔'), _('留空为 168h'));
		o.placeholder = '168h';

		s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			const current = {};
			(uci.sections('dae', 'mixin') || []).forEach(function (sec) {
				if (sec.name)
					current[sec.name] = sec.resolve_dns || '';
			});
			const rows = names.length ? names.map(function (name) {
				return E('tr', { class: 'tr', 'data-node': name }, [
					E('td', { class: 'td' }, name),
					E('td', { class: 'td' }, E('input', {
						class: 'fdae-dns', type: 'text', value: current[name] || '',
						placeholder: _('不覆盖'), style: 'width:12em'
					}))
				]);
			}) : [E('tr', { class: 'tr' }, E('td', { class: 'td', colspan: 2 },
				_('dae 运行并读取到路由源后，这里列出节点。')))];
			return E('div', { class: 'cbi-section' }, [
				E('h3', {}, _('节点解析 DNS')),
				E('div', { class: 'cbi-section-descr' }, _('为指定节点的服务器名改用这个 DNS 解析；留空则不覆盖。')),
				E('table', { class: 'table', id: 'fdae-dns-table' }, rows)
			]);
		};

		s = m.section(form.NamedSection, 'config', 'dae', _('高级'));
		o = s.option(form.Flag, 'tcp_sockmap', _('TCP sockmap'), _('内核 6.12.34+ / 6.6.94+；改后需重启服务'));
		o = s.option(form.Value, 'log_maxbackups', _('日志备份数'));
		o.datatype = 'uinteger';
		o.placeholder = '1';
		o = s.option(form.Value, 'log_maxsize', _('日志大小 (MB)'));
		o.datatype = 'uinteger';
		o.placeholder = '1';
		o = s.option(form.DynamicList, 'env', _('环境变量'), _('KEY=VALUE，例如 GOMEMLIMIT=256MiB；改后需重启服务'));

		return m.render();
	},

	handleSave(ev) {
		const table = document.getElementById('fdae-dns-table');
		const rows = table ? table.querySelectorAll('tr[data-node]') : [];
		// No rows means the node list was not available, not "clear everything".
		if (rows.length) {
			(uci.sections('dae', 'mixin') || []).slice().forEach(function (sec) {
				uci.remove('dae', sec['.name']);
			});
			rows.forEach(function (tr) {
				const dns = (tr.querySelector('.fdae-dns').value || '').trim();
				if (!dns)
					return;
				const id = uci.add('dae', 'mixin');
				uci.set('dae', id, 'name', tr.getAttribute('data-node'));
				uci.set('dae', id, 'resolve_dns', dns);
			});
		}
		return this.super('handleSave', ev);
	},

	// Commit the settings, then have dae take them: the init script writes
	// local.dae, checks it, and reloads, and its complaints are shown here.
	handleSaveApply(ev, mode) {
		return this.handleSave(ev).then(function () {
			return ui.changes.apply(mode == '0');
		}).then(function () {
			return runInit(['apply']).then(function (res) {
				notify(res, _('已应用'));
			});
		});
	}
});
