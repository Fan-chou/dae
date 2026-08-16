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

return view.extend({
	render() {
		const m = new form.Map('dae', _('kdae'),
			_('eBPF 透明代理。选组、连接表、分流编辑请打开面板；本页管启停、接口、订阅和热重载。'));

		let s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			poll.add(function () {
				return L.resolveDefault(getServiceStatus()).then(function (res) {
					const view = document.getElementById('service_status');
					if (view)
						view.innerHTML = renderStatus(res);
				});
			});
			return E('div', { class: 'cbi-section', id: 'status_bar' }, [
				E('p', { id: 'service_status' }, _('Collecting data…'))
			]);
		};

		s = m.section(form.NamedSection, 'config', 'dae');

		let o = s.option(form.Flag, 'enabled', _('启用'));

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
			return fs.exec('/etc/init.d/dae', ['hot_reload']).then(function (res) {
				if (res.code)
					ui.addNotification(null, E('pre', {}, res.stderr || res.stdout || 'reload failed'), 'error');
				else
					ui.addNotification(null, E('p', {}, _('已发送热重载')), 'info');
			});
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
			return ui.changes.apply(mode == '0');
		});
	}
});
