'use strict';
'require form';
'require fs';
'require poll';
'require uci';
'require ui';
'require view';

function loadStatus() {
	return L.resolveDefault(fs.exec('/usr/libexec/dae/kdae-status.sh'), null).then(function (res) {
		if (!res || res.code || !res.stdout)
			return null;
		try {
			return JSON.parse(res.stdout);
		} catch (e) {
			return null;
		}
	});
}

function parseNodeMap(data) {
	const list = Array.isArray(data) ? data : [data];
	for (let i = 0; i < list.length; i++) {
		let text = list[i];
		if (text && typeof text === 'object' && text.stdout != null)
			text = text.stdout;
		if (!text || typeof text !== 'string')
			continue;
		try {
			const parsed = JSON.parse(text);
			if (parsed && parsed.mihomo && parsed.mihomo.node_name_map)
				return parsed.mihomo.node_name_map;
			if (parsed && parsed.node_name_map)
				return parsed.node_name_map;
			if (parsed && typeof parsed === 'object' && parsed.generation == null && parsed.schema_version == null)
				return parsed;
		} catch (e) {
			/* ignore malformed metadata */
		}
	}
	return {};
}

function notifyResult(res, okMsg) {
	const text = [res.stdout, res.stderr].filter(Boolean).join('\n');
	if (res.code)
		ui.addNotification(null, E('pre', {}, text || 'failed'), 'error');
	else
		ui.addNotification(null, E('pre', {}, text || okMsg), 'info');
}

function validateConfig() {
	return fs.exec('/usr/bin/dae', ['validate', '-c', '/etc/dae/config.dae']);
}

function actionBtn(style, label, handler) {
	const b = E('button', { type: 'button', class: 'cbi-button cbi-button-' + style }, label);
	b.addEventListener('click', function (ev) {
		ev.preventDefault();
		if (b.disabled)
			return;
		b.disabled = true;
		Promise.resolve(handler(b)).catch(function (e) {
			ui.addNotification(null, E('p', {}, e.message), 'error');
		}).finally(function () {
			b.disabled = false;
		});
	});
	return b;
}

function kvRow(key, value) {
	return E('tr', { class: 'tr' }, [
		E('td', { class: 'td', style: 'width:9em;opacity:.7' }, key),
		E('td', { class: 'td' }, value)
	]);
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

function renderSyncState(box, st) {
	let kids;
	if (!st) {
		kids = [E('em', {}, _('dae 未运行，或管理接口 (admin_listen) 不可用。启动后这里显示路由源状态。'))];
	} else {
		const m = st.mihomo || {};
		let status;
		if (!m.enabled)
			status = E('span', {}, _('未配置路由源'));
		else if (m.degraded)
			status = E('strong', { style: 'color:red' }, _('不可用，已不带路由源启动，正在重试'));
		else if (m.error)
			status = E('strong', { style: 'color:red' }, _('读取失败'));
		else if (m.used_last_good)
			status = E('strong', { style: 'color:#c80' }, _('使用上一份有效副本'));
		else
			status = E('strong', { style: 'color:green' }, _('正常'));

		const rows = [kvRow(_('状态'), status)];
		if (m.enabled) {
			rows.push(kvRow(_('来源'), m.source || '—'));
			rows.push(kvRow(_('最近检查'), ago(m.checked_at)));
			rows.push(kvRow(_('内容'), _('%d 节点 · %d 分组 · %d 规则 · %d 规则集').format(m.nodes || 0, m.groups || 0, m.rules || 0, m.providers || 0)));
		}
		rows.push(kvRow(_('运行代次'), st.generation || '—'));
		kids = [E('table', { class: 'table' }, rows)];
		if (m.error)
			kids.push(E('pre', { style: 'white-space:pre-wrap;word-break:break-all;color:red;margin-top:8px' }, m.error));
		const skipped = m.skipped_rules || [];
		if (skipped.length)
			kids.push(E('details', { style: 'margin-top:8px' }, [
				E('summary', {}, _('被跳过或忽略的规则 (%d)').format(skipped.length)),
				E('pre', { style: 'white-space:pre-wrap;word-break:break-all' },
					skipped.map(function (r) { return '[' + r.kind + '] ' + (r.line ? 'L' + r.line + ' ' : '') + r.rule + ' — ' + r.reason; }).join('\n'))
			]));
	}
	while (box.firstChild)
		box.removeChild(box.firstChild);
	kids.forEach(function (el) { box.appendChild(el); });
}

return view.extend({
	load() {
		return Promise.all([
			uci.load('dae'),
			L.resolveDefault(fs.exec('/usr/libexec/dae/kdae-list-nodes.sh'), { code: 1, stdout: '' })
		]);
	},

	render(data) {
		const nodeMap = parseNodeMap(data);
		const nodeNames = Object.keys(nodeMap).sort();
		const m = new form.Map('dae', _('Mihomo 路由源'));

		let s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			const stateBox = E('div', { id: 'kdae-sync-state' }, _('Collecting data…'));

			function refreshState() {
				return loadStatus().then(function (st) {
					renderSyncState(stateBox, st);
				});
			}

			poll.add(refreshState);

			const syncBtn = actionBtn('action', _('应用并重新读取'), function () {
				return fs.exec('/usr/libexec/dae/kdae-sync.sh').then(function (res) {
					notifyResult(res, _('已应用'));
					return refreshState();
				});
			});
			const reloadBtn = actionBtn('reload', _('热重载'), function () {
				return validateConfig().then(function (res) {
					if (res.code) {
						notifyResult(res, '');
						return;
					}
					return fs.exec('/etc/init.d/dae', ['hot_reload']).then(function (reloadRes) {
						notifyResult(reloadRes, _('已热重载'));
					});
				});
			});

			return E('div', { class: 'cbi-section' }, [
				E('div', { style: 'display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px' }, [
					syncBtn, reloadBtn
				]),
				stateBox
			]);
		};

		s = m.section(form.NamedSection, 'config', 'dae', _('生成来源'));
		let o = s.option(form.Value, 'mihomo_config', _('本地 YAML'), _('填写则覆盖完整配置订阅'));
		o.placeholder = '/etc/dae/mihomo.yaml';

		o = s.option(form.Value, 'mihomo_interval', _('刷新间隔'), _('留空为 1h'));
		o.placeholder = '1h';

		o = s.option(form.Value, 'isolate_transport_groups', _('独立传输的分组'), _('逗号分隔的分组名；这些分组的每个节点各用一条独立连接'));

		s = m.section(form.TypedSection, 'subscription', _('订阅'));
		s.anonymous = true;
		s.addremove = true;
		s.addbtntitle = _('添加');

		o = s.option(form.Value, 'tag', _('标签'));
		o.placeholder = 'main';

		o = s.option(form.Value, 'url', _('链接'));
		o.password = true;
		o.rmempty = false;
		o.placeholder = 'https://example.com/clash';

		o = s.option(form.ListValue, 'role', _('用途'));
		o.value('routing', _('完整配置'));
		o.value('nodes', _('仅节点'));
		o.default = 'routing';

		o = s.option(form.Flag, 'persist', _('落盘'));
		o.default = '1';

		s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			const byName = {};
			[]
				.concat(uci.sections('dae', 'mixin') || [])
				.concat(uci.sections('dae', 'node_dns') || [])
				.forEach(function (sec) {
					if (sec.name)
						byName[sec.name] = sec;
				});
			const head = E('tr', { class: 'tr table-titles' }, [
				E('th', { class: 'th' }, _('启用')),
				E('th', { class: 'th' }, _('节点')),
				E('th', { class: 'th' }, _('resolve_dns'))
			]);
			const rows = nodeNames.length
				? nodeNames.map(function (name) {
					const cur = byName[name] || {};
					const on = !!cur.resolve_dns;
					return E('tr', { class: 'tr', 'data-node': name }, [
						E('td', { class: 'td' }, E('input', {
							class: 'kdae-mixin-on',
							type: 'checkbox',
							checked: on ? 'checked' : null
						})),
						E('td', { class: 'td' }, [
							name,
							E('span', { style: 'opacity:.6;margin-left:8px' }, nodeMap[name] || '')
						]),
						E('td', { class: 'td' }, E('input', {
							class: 'kdae-mixin-dns',
							type: 'text',
							value: cur.resolve_dns || '',
							placeholder: '8.8.8.8',
							style: 'width:12em'
						}))
					]);
				})
				: [E('tr', { class: 'tr' }, [
					E('td', { class: 'td', colspan: 3 }, _('dae 运行并读取到路由源后显示节点'))
				])];
			return E('div', { class: 'cbi-section' }, [
				E('h3', {}, _('混入')),
				E('div', { class: 'cbi-section-descr' }, _('为指定节点覆盖解析用的 DNS，保存并应用后生效')),
				E('table', { class: 'table', id: 'kdae-mixin-table' }, [head].concat(rows))
			]);
		};

		return m.render();
	},

	handleSave(ev) {
		const table = document.getElementById('kdae-mixin-table');
		if (table) {
			const rows = table.querySelectorAll('tr[data-node]');
			// An empty node list means metadata is missing, not "clear all
			// mixins". Rebuilding from zero rows would wipe saved resolve_dns.
			if (rows.length) {
				[]
					.concat(uci.sections('dae', 'mixin') || [])
					.concat(uci.sections('dae', 'node_dns') || [])
					.slice()
					.forEach(function (sec) {
						uci.remove('dae', sec['.name']);
					});
				rows.forEach(function (tr) {
					const name = tr.getAttribute('data-node');
					const on = tr.querySelector('.kdae-mixin-on').checked;
					let dns = (tr.querySelector('.kdae-mixin-dns').value || '').trim();
					if (!on)
						return;
					if (!dns)
						dns = '8.8.8.8';
					const id = uci.add('dae', 'mixin');
					uci.set('dae', id, 'name', name);
					uci.set('dae', id, 'resolve_dns', dns);
				});
			}
		}
		return this.super('handleSave', ev);
	},

	handleSaveApply(ev, mode) {
		return this.handleSave(ev).then(function () {
			return fs.exec('/usr/libexec/dae/kdae-write-local.sh').then(function (res) {
				if (res && res.code)
					ui.addNotification(null, E('pre', {}, res.stderr || res.stdout || 'write local.dae failed'), 'warning');
			}).catch(function (e) {
				ui.addNotification(null, E('p', {}, e.message));
			});
		}).then(function () {
			return validateConfig().then(function (res) {
				if (res.code) {
					ui.addNotification(null, E('pre', {}, res.stderr || res.stdout || 'validate failed'), 'error');
					return Promise.reject(new Error('validate failed'));
				}
			});
		}).then(function () {
			return ui.changes.apply(mode == '0');
		});
	}
});
