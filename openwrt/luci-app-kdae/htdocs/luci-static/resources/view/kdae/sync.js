'use strict';
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

return view.extend({
	load() {
		return uci.load('dae');
	},

	render() {
		const mihomo = uci.get('dae', 'config', 'mihomo_config') || '';
		const gendir = uci.get('dae', 'config', 'generation_dir') || '/etc/dae';
		const subs = uci.sections('dae', 'subscription') || [];
		const routing = subs.filter(function (item) {
			return (item.role || 'routing') !== 'nodes';
		}).map(function (item, i) {
			return item.tag || ('sub' + (i + 1));
		});
		const nodeSubs = subs.filter(function (item) {
			return item.role === 'nodes';
		}).map(function (item, i) {
			return item.tag || ('nodes' + (i + 1));
		});

		const resultBox = E('pre', { style: 'white-space:pre-wrap;word-break:break-all;min-height:8em;' }, _('尚未同步'));

		function refreshState() {
			return Promise.all([
				loadJSON('/var/run/kdae-last-sync.json'),
				loadJSON('/etc/dae/metadata.json')
			]).then(function (pair) {
				const sync = pair[0] || {};
				const meta = pair[1] || {};
				const lines = [];
				lines.push('generation: ' + (sync.generation || meta.generation || '—'));
				if (meta.previous_generation)
					lines.push('previous: ' + meta.previous_generation);
				if (sync.ok === false)
					lines.push('status: failed');
				else if (sync.ok === true)
					lines.push('status: ok');
				if (sync.warning)
					lines.push('warning:\n' + sync.warning);
				if (sync.error)
					lines.push('error:\n' + sync.error);
				resultBox.textContent = lines.join('\n') || _('尚无 metadata');
			});
		}

		poll.add(refreshState);

		const syncBtn = E('button', { class: 'cbi-button cbi-button-action' }, _('运行 dae-rule-sync'));
		syncBtn.addEventListener('click', function () {
			syncBtn.disabled = true;
			fs.exec('/usr/libexec/dae/kdae-sync.sh').then(function (res) {
				const text = [res.stdout, res.stderr].filter(Boolean).join('\n') || 'done';
				if (res.code)
					ui.addNotification(null, E('pre', {}, text), 'error');
				else
					ui.addNotification(null, E('pre', {}, text), 'info');
				return refreshState();
			}).catch(function (e) {
				ui.addNotification(null, E('p', {}, e.message), 'error');
			}).finally(function () {
				syncBtn.disabled = false;
			});
		});

		const reloadBtn = E('button', { class: 'cbi-button cbi-button-reload' }, _('校验并热重载'));
		reloadBtn.addEventListener('click', function () {
			return fs.exec('/usr/bin/dae', ['validate', '-c', '/etc/dae/config.dae']).then(function (res) {
				if (res.code) {
					ui.addNotification(null, E('pre', {}, res.stderr || res.stdout || 'validate failed'), 'error');
					return;
				}
				return fs.exec('/etc/init.d/dae', ['hot_reload']).then(function (reloadRes) {
					if (reloadRes.code)
						ui.addNotification(null, E('pre', {}, reloadRes.stderr || reloadRes.stdout || 'reload failed'), 'error');
					else
						ui.addNotification(null, E('p', {}, _('已热重载')), 'info');
				});
			});
		});

		return E([], [
			E('h2', {}, _('规则同步')),
			E('p', {}, _('完整配置订阅会在同步时拉取 Mihomo YAML，生成 nodes/groups/routes。仅节点订阅写入 kdae subscription {}，启动时再拉。失败时保留上一份 generation。')),
			E('p', { class: 'cbi-value-description' }, [
				_('完整配置订阅: '), E('code', {}, routing.length ? routing.join(', ') : _('（无）')),
				E('br'),
				_('仅节点订阅: '), E('code', {}, nodeSubs.length ? nodeSubs.join(', ') : _('（无）')),
				E('br'),
				_('本地路由覆盖: '), E('code', {}, mihomo || _('（无，使用订阅）')),
				E('br'),
				_('generation 目录: '), E('code', {}, gendir)
			]),
			E('div', { class: 'cbi-section' }, [
				E('div', { style: 'margin-bottom:12px' }, [syncBtn, ' ', reloadBtn]),
				resultBox
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
