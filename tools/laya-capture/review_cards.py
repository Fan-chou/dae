#!/usr/bin/env python3
"""Build evidence-only review cards; never infer gold labels or incident IDs."""
import argparse
import hashlib
import json
from pathlib import Path


def build(folder):
    report = json.loads((folder / 'screening.json').read_text())
    name = 'selected-events.jsonl'
    raw = (folder / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['artifacts'][name]['sha256']:
        raise ValueError('selected event hash mismatch')
    events = {}
    for line in raw.splitlines():
        e = json.loads(line)
        key = (e['generation'], e['id'])
        if key in events:
            raise ValueError('duplicate evidence ID')
        events[key] = e
    cards = []
    for c in report['candidates']:
        inputs = [events[(r['generation'], r['id'])] for r in c['input_refs']]
        anchor = events[(c['anchor']['generation'], c['anchor']['id'])]
        if anchor not in inputs or any(e['start_ms'] + e['duration_ms'] > c['decision_ms'] for e in inputs):
            raise ValueError('missing anchor or future input')
        if any(e['flow_id'] != c['flow_id'] or e['generation'] != c['anchor']['generation'] for e in inputs):
            raise ValueError('unlinked input')
        gaps = ['缺少独立人工复核和根因事件归并']
        category = c['category']
        if 'dial' in category:
            gaps += ['缺少同时间、同目标、同协议的独立路径对照', '缺少具体错误码及失败阶段；不能从拨号结果归因节点']
        elif category.startswith('dns_') or category == 'later_dns_answer':
            gaps += ['缺少查询级依赖关联及权威预期结果', '缺少应用失败与此 DNS 查询的直接关联']
        else:
            gaps += ['应用需求和接收端背压未观测', '缺少独立容量基准，流量差异不等于拥塞']
        if category == 'relay_error_reason_missing':
            gaps.append('缺少 relay 终止错误分类及错误发生方向')
        if c['followup_refs_not_model_input']:
            gaps.append('后续结果只能用于回溯，不能输入此前的判定')
        cards.append(dict(candidate_id=c['candidate_id'], category=category,
            anchor=c['anchor'], decision_ms=c['decision_ms'], scope=anchor['scope'],
            facts=inputs, followup_refs_not_model_input=c['followup_refs_not_model_input'],
            missing_evidence=gaps, gold=None, incident_id=None,
            review_status='assistant_evidence_inventory_not_human_gold',
            training_ready=False))
    return cards


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder', type=Path)
    a = p.parse_args()
    cards = build(a.folder)
    (a.folder / 'review-cards.json').write_text(json.dumps(cards, ensure_ascii=False, indent=2) + '\n')
    lines = ['# 逐条证据复核卡', '', '以下是事实与缺口清单，不是模型判断或人工金标准。所有条目禁止直接进入训练。', '']
    for c in cards:
        lines += [f"## {c['candidate_id']} · {c['category']}", '',
                  f"路径：{c['scope']['path']}；协议：{c['scope']['network']}；判定时刻：{c['decision_ms']} ms。", '',
                  '| 证据 ID | 类型 | 结果 | 持续 ms |', '|---|---|---|---:|']
        for e in c['facts']:
            lines.append(f"| {e['id']} | {e['kind']} | {e['outcome']} | {e['duration_ms']} |")
        lines += ['', *['- ' + gap for gap in c['missing_evidence']], '']
    (a.folder / 'REVIEW-CARDS.zh.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'cards': len(cards), 'training_ready': 0}))


if __name__ == '__main__':
    main()
