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

function notify(res, okMsg) {
	const text = [res.stdout, res.stderr].filter(Boolean).join('\n').trim();
	ui.addNotification(null, E('pre', {}, text || okMsg), res.code ? 'error' : 'info');
}

function button(style, label, handler) {
	const b = E('button', { type: 'button', class: 'cbi-button cbi-button-' + style }, label);
	b.addEventListener('click', function (ev) {
		ev.preventDefault();
		if (b.disabled)
			return;
		b.disabled = true;
		Promise.resolve(handler()).catch(function (e) {
			ui.addNotification(null, E('p', {}, e.message), 'error');
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

return view.extend({
	load() {
		return Promise.all([uci.load('dae'), loadMihomo()]);
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
							_('已安装新版本（%s），运行中的仍是 %s。').format(p.installed_version || '?', p.running_version || '?')),
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

			function showSwitch() {
				return runInit(['switch_state']).then(function (res) {
					const st = parseLines(res.stdout);
					if (!st.state || st.state === 'idle')
						return false;
					const color = st.state === 'ok' ? 'green' : st.state === 'failed' ? 'red' : '#c80';
					progress.replaceChildren(E('strong', { style: 'color:' + color }, st.message || st.state));
					return st.state === 'running';
				});
			}

			function followSwitch() {
				return showSwitch().then(function (busy) {
					if (busy)
						return new Promise(function (ok) { setTimeout(ok, 2000); }).then(followSwitch);
					return refresh();
				});
			}

			function startSwitch() {
				return runInit(['switch']).then(function (res) {
					if (res.code)
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
