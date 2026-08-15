'use strict';
'require dom';
'require fs';
'require poll';
'require view';

return view.extend({
	render() {
		const log_textarea = E('div', { id: 'log_textarea' },
			E('img', { src: L.resource('icons/loading.svg'), alt: _('Loading...'), style: 'vertical-align:middle' }, _('Collecting data…')));

		poll.add(function () {
			return fs.read_direct('/var/log/dae/dae.log', 'text').then(function (content) {
				dom.content(log_textarea, E('pre', { wrap: 'pre' }, [content.trim() || _('日志为空。')]));
			}).catch(function (e) {
				const msg = e.toString().includes('NotFoundError') ? _('日志文件不存在。') : _('Unknown error: %s').format(e);
				dom.content(log_textarea, E('pre', { wrap: 'pre' }, [msg]));
			});
		});

		return E([], [
			E('h2', {}, [_('日志')]),
			E('p', {}, _('读取 /var/log/dae/dae.log')),
			E('div', { class: 'cbi-section' }, [log_textarea])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
