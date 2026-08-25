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

function refreshStatus() {
	return L.resolveDefault(getServiceStatus()).then(function (running) {
		const el = document.getElementById('service_status');
		if (!el)
			return;
		el.textContent = running ? _('运行中') : _('未运行');
		el.style.color = running ? 'green' : 'red';
	});
}

function notifyResult(res, okMsg) {
	const text = [res.stdout, res.stderr].filter(Boolean).join('\n');
	if (res.code)
		ui.addNotification(null, E('pre', {}, text || 'failed'), 'error');
	else
		ui.addNotification(null, E('pre', {}, text || okMsg), 'info');
}

function execInit(args, okMsg) {
	return fs.exec('/etc/init.d/dae', args).then(function (res) {
		notifyResult(res, okMsg);
		return refreshStatus();
	}).catch(function (e) {
		ui.addNotification(null, E('p', {}, e.message), 'error');
	});
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

function toolbarRow(children) {
	return E('div', { style: 'display:flex;flex-wrap:wrap;gap:8px;align-items:center' }, children);
}

return view.extend({
	load() {
		return uci.load('dae');
	},

	render() {
		const m = new form.Map('dae', _('kdae'));
		const sockmapOn = uci.get('dae', 'config', 'tcp_sockmap') === '1';

		let s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			poll.add(function () {
				return L.resolveDefault(refreshStatus());
			});

			const status = E('strong', { id: 'service_status', style: 'font-size:15px' }, _('Collecting data…'));
			const panel = actionBtn('action', _('打开面板'), function () {
				window.open('/kdae-ui/', '_blank');
				return Promise.resolve();
			});
			const statusLine = [status];
			if (sockmapOn)
				statusLine.push(E('span', { style: 'margin-left:12px;color:green' }, _('sockmap 开 · 须重启')));

			return E('div', { class: 'cbi-section', id: 'status_bar' }, [
				E('div', {
					style: 'display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px'
				}, [
					E('div', {}, statusLine),
					panel
				]),
				toolbarRow([
					actionBtn('apply', _('启动'), function () {
						return execInit(['start'], _('已启动'));
					}),
					actionBtn('reset', _('停止'), function () {
						return execInit(['stop'], _('已停止'));
					}),
					actionBtn('reload', _('重启'), function () {
						return execInit(['restart'], _('已重启'));
					}),
					actionBtn('reload', _('热重载'), function () {
						return validateConfig().then(function (res) {
							if (res.code) {
								notifyResult(res, '');
								return;
							}
							return fs.exec('/etc/init.d/dae', ['hot_reload']).then(function (reloadRes) {
								notifyResult(reloadRes, _('已热重载'));
							});
						});
					}),
					actionBtn('apply', _('校验'), function () {
						return validateConfig().then(function (res) {
							if (res.code)
								notifyResult(res, '');
							else
								ui.addNotification(null, E('p', {}, _('校验通过')), 'info');
						});
					})
				]),
				E('div', { style: 'margin-top:8px' }, [
					actionBtn('remove', _('清除残留'), function () {
						if (!window.confirm(_('将停止 kdae 并清除 eBPF/TC/dae0/daens。继续？')))
							return Promise.resolve();
						return execInit(['recover'], _('残留已清除'));
					})
				])
			]);
		};

		s = m.section(form.NamedSection, 'config', 'dae', _('接口'));
		let o = s.option(form.Flag, 'enabled', _('启用'));

		o = s.option(form.Value, 'lan_interface', _('LAN'));
		o.placeholder = 'br-lan,Home,IEPL';

		o = s.option(form.Value, 'wan_interface', _('WAN'), _('留空则不代理本机'));
		o.placeholder = '';

		o = s.option(form.Value, 'admin_listen', _('API 地址'), _('LAN 上的 ip:port，勿用 0.0.0.0 / 9090'));
		o.placeholder = '192.168.124.223:2025';

		o = s.option(form.Value, 'admin_secret', _('API 密钥'));
		o.password = true;

		s = m.section(form.NamedSection, 'config', 'dae', _('高级'));

		o = s.option(form.Flag, 'tcp_sockmap', _('TCP sockmap'),
			_('仅加速已进用户态的代理 TCP。改完须重启。内核 6.12.34+ / 6.6.94+'));
		o.default = '0';

		o = s.option(form.Value, 'log_maxbackups', _('日志备份'));
		o.datatype = 'uinteger';
		o.placeholder = '1';

		o = s.option(form.Value, 'log_maxsize', _('日志大小 (MB)'));
		o.datatype = 'uinteger';
		o.placeholder = '1';

		o = s.option(form.Value, 'config_file', _('配置文件'));
		o.default = '/etc/dae/config.dae';
		o.readonly = true;

		return m.render();
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
