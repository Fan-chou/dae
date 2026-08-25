'use strict';
'require fs';
'require poll';
'require view';

const LINE_CHOICES = [100, 300, 1000];
const DEFAULT_LINES = 300;

function tailReverse(text, n) {
	const trimmed = (text || '').replace(/\s+$/, '');
	if (!trimmed)
		return [];
	const lines = trimmed.split('\n');
	const tail = lines.length > n ? lines.slice(-n) : lines;
	return tail.reverse();
}

return view.extend({
	render() {
		let maxLines = DEFAULT_LINES;
		let follow = true;
		let refreshing = true;

		const pre = E('pre', {
			wrap: 'pre',
			style: 'max-height:70vh;overflow:auto;margin:0;white-space:pre-wrap;word-break:break-all'
		}, _('Collecting data…'));

		const meta = E('span', { style: 'opacity:.7' }, '');

		function paint(lines, note) {
			const keep = follow ? 0 : pre.scrollTop;
			pre.textContent = lines.length ? lines.join('\n') : (note || _('日志为空。'));
			if (follow)
				pre.scrollTop = 0;
			else
				pre.scrollTop = keep;
			meta.textContent = lines.length
				? _('最近 %d 行，新→旧').format(lines.length)
				: '';
		}

		function loadLog() {
			return fs.read_direct('/var/log/dae/dae.log', 'text').then(function (content) {
				paint(tailReverse(content, maxLines));
			}).catch(function (e) {
				const msg = e.toString().includes('NotFoundError')
					? _('日志文件不存在。')
					: _('Unknown error: %s').format(e);
				paint([], msg);
			});
		}

		poll.add(loadLog);

		const followBox = E('input', { type: 'checkbox', checked: 'checked' });
		followBox.addEventListener('change', function () {
			follow = followBox.checked;
			if (follow)
				pre.scrollTop = 0;
		});

		const refreshBox = E('input', { type: 'checkbox', checked: 'checked' });
		refreshBox.addEventListener('change', function () {
			refreshing = refreshBox.checked;
			if (refreshing)
				poll.add(loadLog);
			else
				poll.remove(loadLog);
		});

		pre.addEventListener('scroll', function () {
			if (!follow || !refreshing)
				return;
			if (pre.scrollTop > 24)
				followBox.checked = follow = false;
		});

		const lineSel = E('select');
		LINE_CHOICES.forEach(function (n) {
			lineSel.appendChild(E('option', {
				value: String(n),
				selected: n === DEFAULT_LINES ? 'selected' : null
			}, String(n)));
		});
		lineSel.addEventListener('change', function () {
			maxLines = parseInt(lineSel.value, 10) || DEFAULT_LINES;
			loadLog();
		});

		return E([], [
			E('h2', {}, [_('日志')]),
			E('div', { class: 'cbi-section' }, [
				E('div', {
					style: 'display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:8px'
				}, [
					E('label', {}, [refreshBox, ' ', _('自动刷新')]),
					E('label', {}, [followBox, ' ', _('跟随最新')]),
					E('label', {}, [_('行数'), ' ', lineSel]),
					meta
				]),
				pre
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
