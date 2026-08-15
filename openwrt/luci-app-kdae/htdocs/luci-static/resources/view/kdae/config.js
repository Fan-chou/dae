'use strict';
'require form';
'require fs';
'require ui';
'require view';

return view.extend({
	render() {
		const m = new form.Map('dae', _('配置'),
			_('编辑 /etc/dae/config.dae。节点 URI 请放在 nodes.dae（0600），不要贴到这里。保存后请先校验再热重载。'));

		m.section(form.TypedSection).anonymous = true;

		const s = m.section(form.NamedSection, 'config', 'dae');
		const o = s.option(form.TextValue, '_configuration');
		o.rows = 30;
		o.monospace = true;
		o.load = function () {
			return fs.read_direct('/etc/dae/config.dae', 'text').then(function (content) {
				return content ?? '';
			}).catch(function (e) {
				if (e.toString().includes('NotFoundError')) {
					return fs.read_direct('/etc/dae/example.dae', 'text').then(function (content) {
						return content ?? '';
					}).catch(function () { return ''; });
				}
				ui.addNotification(null, E('p', e.message));
				return '';
			});
		};
		o.write = function (section_id, value) {
			return fs.write('/etc/dae/config.dae', value, 384).catch(function (e) {
				ui.addNotification(null, E('p', e.message));
			});
		};
		o.remove = function () {
			return fs.write('/etc/dae/config.dae', '').catch(function (e) {
				ui.addNotification(null, E('p', e.message));
			});
		};

		return m.render();
	},

	handleSaveApply(ev, mode) {
		return this.handleSave(ev).then(function () {
			return fs.exec('/usr/bin/dae', ['validate', '-c', '/etc/dae/config.dae']).then(function (res) {
				if (res.code) {
					ui.addNotification(null, E('pre', {}, res.stderr || res.stdout || 'validate failed'), 'error');
					return Promise.reject(new Error('validate failed'));
				}
				return L.resolveDefault(fs.exec('/etc/init.d/dae', ['hot_reload']), null);
			});
		});
	}
});
