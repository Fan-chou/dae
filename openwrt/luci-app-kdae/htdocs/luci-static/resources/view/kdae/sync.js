'use strict';
'require form';
'require fs';
'require poll';
'require uci';
'require ui';
'require view';

function loadJSON(path) {
	return fs.read_direct(path, 'text').then(function (content) {
		try {
			return JSON.parse(content);
		} catch (e) {
			return { raw: content };
		}
	}).catch(function () {
		return null;
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

function renderSyncState(box, sync, meta) {
	sync = sync || {};
	meta = meta || {};
	const ok = sync.ok;
	let status;
	if (ok === false)
		status = E('strong', { style: 'color:red' }, _('失败'));
	else if (ok === true)
		status = E('strong', { style: 'color:green' }, _('成功'));
	else
		status = E('span', {}, _('尚未同步'));

	const rows = [
		kvRow(_('状态'), status),
		kvRow(_('generation'), sync.generation || meta.generation || '—')
	];
	if (meta.previous_generation)
		rows.push(kvRow(_('上一份'), meta.previous_generation));

	const kids = [E('table', { class: 'table' }, rows)];
	if (sync.error)
		kids.push(E('pre', { style: 'white-space:pre-wrap;word-break:break-all;color:red;margin-top:8px' }, sync.error));
	if (sync.warning)
		kids.push(E('pre', { style: 'white-space:pre-wrap;word-break:break-all;margin-top:8px' }, sync.warning));

	while (box.firstChild)
		box.removeChild(box.firstChild);
	kids.forEach(function (el) { box.appendChild(el); });
}

return view.extend({
	load() {
		return Promise.all([
			uci.load('dae'),
			L.resolveDefault(fs.exec('/usr/libexec/dae/kdae-list-nodes.sh'), { code: 1, stdout: '' }),
			L.resolveDefault(fs.read_direct('/etc/dae/current/metadata.json', 'text'), ''),
			L.resolveDefault(fs.read_direct('/etc/dae/metadata.json', 'text'), '')
		]);
	},

	render(data) {
		const nodeMap = parseNodeMap(data);
		const nodeNames = Object.keys(nodeMap).sort();
		const m = new form.Map('dae', _('规则同步'));

		let s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			const stateBox = E('div', { id: 'kdae-sync-state' }, _('Collecting data…'));

			function refreshState() {
				return Promise.all([
					loadJSON('/var/run/kdae-last-sync.json'),
					loadJSON('/etc/dae/current/metadata.json'),
					loadJSON('/etc/dae/metadata.json')
				]).then(function (pair) {
					renderSyncState(stateBox, pair[0], pair[1] || pair[2] || {});
				});
			}

			poll.add(refreshState);

			const syncBtn = actionBtn('action', _('同步'), function () {
				return fs.exec('/usr/libexec/dae/kdae-sync.sh').then(function (res) {
					notifyResult(res, _('已同步'));
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

		o = s.option(form.Value, 'generation_dir', _('generation 目录'));
		o.default = '/etc/dae';

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
					E('td', { class: 'td', colspan: 3 }, _('同步后显示节点'))
				])];
			return E('div', { class: 'cbi-section' }, [
				E('h3', {}, _('混入')),
				E('div', { class: 'cbi-section-descr' }, _('覆盖 resolve_dns，保存后再同步')),
				E('table', { class: 'table', id: 'kdae-mixin-table' }, [head].concat(rows))
			]);
		};

		return m.render();
	},

	handleSave(ev) {
		const table = document.getElementById('kdae-mixin-table');
		if (table) {
			[]
				.concat(uci.sections('dae', 'mixin') || [])
				.concat(uci.sections('dae', 'node_dns') || [])
				.slice()
				.forEach(function (sec) {
					uci.remove('dae', sec['.name']);
				});
			table.querySelectorAll('tr[data-node]').forEach(function (tr) {
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
