'use strict';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

function getServiceStatus() {
	return L.resolveDefault(callServiceList('dae'), {}).then(function (res) {
		try {
			return res['dae']['instances']['dae']['running'];
		} catch (e) {
			return false;
		}
	});
}

function renderStatus(isRunning) {
	const color = isRunning ? 'green' : 'red';
	const text = isRunning ? _('运行中') : _('未运行');
	return '<span style="color:%s"><strong>kdae %s</strong></span>'.format(color, text);
}

function refreshStatus() {
	return L.resolveDefault(getServiceStatus()).then(function (res) {
		const view = document.getElementById('service_status');
		if (view)
			view.innerHTML = renderStatus(res);
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

function execInit(args, okMsg) {
	return fs.exec('/etc/init.d/dae', args).then(function (res) {
		const text = [res.stdout, res.stderr].filter(Boolean).join('\n');
		if (res.code)
			ui.addNotification(null, E('pre', {}, text || args.join(' ') + ' failed'), 'error');
		else
			ui.addNotification(null, E('pre', {}, text || okMsg), 'info');
		return refreshStatus();
	}).catch(function (e) {
		ui.addNotification(null, E('p', {}, e.message), 'error');
	});
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
		const m = new form.Map('dae', _('kdae'),
			_('eBPF 透明代理。选组、连接表、分流编辑请打开面板；本页管启停、接口、订阅和热重载。'));

		let s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			poll.add(function () {
				return L.resolveDefault(refreshStatus());
			});
			const sockmapOn = uci.get('dae', 'config', 'tcp_sockmap') === '1';
			return E('div', { class: 'cbi-section', id: 'status_bar' }, [
				E('p', { id: 'service_status' }, _('Collecting data…')),
				E('p', {}, sockmapOn
					? E('strong', { style: 'color:green' }, _('TCP sockmap 卸载：已开启（改此项后必须点下面的「重启」）'))
					: E('strong', {}, _('TCP sockmap 卸载：已关闭')))
			]);
		};

		s = m.section(form.NamedSection, 'config', 'dae');

		let o = s.option(form.Flag, 'enabled', _('启用'));

		o = s.option(form.Flag, 'tcp_sockmap', _('TCP sockmap 卸载'),
			_('只加速已经进用户态的代理 TCP。直连 / UDP / 加密出站剥不到真 TCP 的不走这条路。热重载无效，改完必须点下面的「重启」。内核需 6.12.34+ 或 6.6.94+。'));
		o.default = '0';

		o = s.option(form.Value, 'config_file', _('配置文件'));
		o.default = '/etc/dae/config.dae';
		o.readonly = true;

		o = s.option(form.Value, 'lan_interface', _('LAN 接口'),
			_('逗号分隔，例如 br-lan,Home,IEPL。会写入 /etc/dae/local.dae，请在 config.dae 中 include { local.dae }。'));
		o.placeholder = 'br-lan,Home,IEPL';

		o = s.option(form.Value, 'wan_interface', _('WAN 接口'),
			_('默认留空，对齐 Nikki router_proxy=0，不劫持路由器本机流量。'));
		o.placeholder = '';

		o = s.option(form.Value, 'admin_listen', _('管理 API 监听'),
			_('仅绑 LAN，例如 192.168.124.223:2025。不要用 0.0.0.0，不要用 9090。'));
		o.placeholder = '192.168.124.223:2025';

		o = s.option(form.Value, 'admin_secret', _('管理 API 密钥'));
		o.password = true;

		o = s.option(form.Value, 'mihomo_config', _('Mihomo 路由配置（本地覆盖）'),
			_('可选。若填写本地 YAML，同步时优先用它，不再拉取「完整配置」订阅。一般留空，让订阅自己生成分流。'));

		o = s.option(form.Value, 'generation_dir', _('generation 目录'));
		o.default = '/etc/dae';

		o = s.option(form.Value, 'log_maxbackups', _('日志备份数'));
		o.datatype = 'uinteger';
		o.placeholder = '1';

		o = s.option(form.Value, 'log_maxsize', _('日志大小 (MB)'));
		o.datatype = 'uinteger';
		o.placeholder = '1';

		o = s.option(form.Button, '_start', _('启动'));
		o.inputtitle = _('启动');
		o.inputstyle = 'apply';
		o.description = _('直接调用 /etc/init.d/dae start。需已勾选「启用」。');
		o.onclick = function () {
			return execInit(['start'], _('已发送启动'));
		};

		o = s.option(form.Button, '_stop', _('关闭'));
		o.inputtitle = _('关闭');
		o.inputstyle = 'reset';
		o.onclick = function () {
			return execInit(['stop'], _('已关闭'));
		};

		o = s.option(form.Button, '_restart', _('重启'));
		o.inputtitle = _('重启');
		o.inputstyle = 'reload';
		o.description = _('先停再启。启动前仍会 validate，配置有问题则起不来。');
		o.onclick = function () {
			return execInit(['restart'], _('已发送重启'));
		};

		o = s.option(form.Button, '_validate', _('校验配置'));
		o.inputtitle = _('dae validate');
		o.inputstyle = 'apply';
		o.onclick = function () {
			return fs.exec('/usr/bin/dae', ['validate', '-c', '/etc/dae/config.dae']).then(function (res) {
				if (res.code)
					ui.addNotification(null, E('pre', {}, res.stderr || res.stdout || 'validate failed'), 'error');
				else
					ui.addNotification(null, E('p', {}, _('配置校验通过')), 'info');
			});
		};

		o = s.option(form.Button, '_reload', _('热重载'));
		o.inputtitle = _('dae reload');
		o.inputstyle = 'reload';
		o.onclick = function () {
			return fs.exec('/usr/bin/dae', ['validate', '-c', '/etc/dae/config.dae']).then(function (res) {
				if (res.code) {
					ui.addNotification(null, E('pre', {}, res.stderr || res.stdout || 'validate failed'), 'error');
					return;
				}
				return fs.exec('/etc/init.d/dae', ['hot_reload']).then(function (reloadRes) {
					if (reloadRes.code)
						ui.addNotification(null, E('pre', {}, reloadRes.stderr || reloadRes.stdout || 'reload failed'), 'error');
					else
						ui.addNotification(null, E('p', {}, _('已发送热重载')), 'info');
				});
			});
		};

		o = s.option(form.Button, '_recover', _('清除残留'));
		o.inputtitle = _('清除残留');
		o.inputstyle = 'remove';
		o.description = _('崩溃后网络不通时用：停止 kdae，卸 TC hook、删 dae0/daens、清 /sys/fs/bpf/dae。正常运行时不要点。');
		o.onclick = function () {
			if (!window.confirm(_('将停止 kdae 并清除残留 eBPF/TC/dae0/daens。确认继续？')))
				return Promise.resolve();
			return execInit(['recover'], _('残留已清除'));
		};

		o = s.option(form.Button, '_panel', _('打开面板'));
		o.inputtitle = _('kdae-ui');
		o.inputstyle = 'action';
		o.onclick = function () {
			window.open('/kdae-ui/', '_blank');
		};

		s = m.section(form.TypedSection, 'subscription', _('Mihomo 订阅'),
			_('默认当作完整 Mihomo YAML（节点 + 分流）。同步时拉取并生成 groups/routes。仅节点列表的订阅请把用途改成「仅节点」。请在 config.dae 中 include { local.dae }。'));
		s.anonymous = true;
		s.addremove = true;
		s.addbtntitle = _('添加订阅');

		o = s.option(form.Value, 'tag', _('标签'));
		o.placeholder = 'main';

		o = s.option(form.Value, 'url', _('订阅链接'));
		o.password = true;
		o.rmempty = false;
		o.placeholder = 'https://example.com/clash';

		o = s.option(form.ListValue, 'role', _('用途'));
		o.value('routing', _('完整配置（节点 + 分流）'));
		o.value('nodes', _('仅节点列表（写入 kdae subscription {}）'));
		o.default = 'routing';

		o = s.option(form.Flag, 'persist', _('落盘兜底'),
			_('仅节点列表：https 写成 https-file://。完整配置：同步时缓存 YAML 到 generation/cache。'));
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
						E('td', { class: 'td' }, name + ' → ' + nodeMap[name]),
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
					E('td', { class: 'td', colspan: 3 },
						_('还没有节点名单。请先到「规则同步」跑一次。'))
				])];
			return E('div', { class: 'cbi-section' }, [
				E('h3', {}, _('混入配置')),
				E('div', { class: 'cbi-section-descr' },
					_('覆盖订阅生成的节点参数，不改机场 YAML。每个节点单独勾选、单独填 resolve_dns。保存后再跑一次规则同步。')),
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
			return fs.exec('/usr/bin/dae', ['validate', '-c', '/etc/dae/config.dae']).then(function (res) {
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
