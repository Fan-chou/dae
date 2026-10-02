#!/usr/bin/env python3
"""Freeze and triage real evidence for human review. Never produces training gold."""
import argparse
import bisect
import collections
import datetime
import hashlib
import json
from pathlib import Path
from evidence import load, end


def reference(e):
    return {'generation':e['generation'],'id':e['id']}


def screen(events, limit=8):
    dials=[e for e in events if e['kind']=='dial']
    flows=collections.defaultdict(list)
    for e in events:
        flows[(e['generation'],e['flow_id'])].append(e)
    for rs in flows.values():rs.sort(key=lambda e:(end(e),e['sequence']))
    categories=collections.defaultdict(list)
    def add(category, anchor, followups=(), caveat=''):
        rs=flows[(anchor['generation'],anchor['flow_id'])]
        before=[e for e in rs if end(e)<=end(anchor)]
        # Stable review unit only; deliberately not a root-cause incident ID.
        seed=category+'|'+anchor['generation']+'|'+anchor['id']
        categories[category].append({'candidate_id':hashlib.sha256(seed.encode()).hexdigest()[:24],
          'category':category,'anchor':reference(anchor),'flow_id':anchor['flow_id'],
          'decision_ms':end(anchor),'input_refs':[reference(e) for e in before],
          'followup_refs_not_model_input':[reference(e) for e in followups],
          'site_id':anchor['scope']['site_id'],'node_id':anchor['scope']['node_id'],
          'caveat':caveat,'incident_id':None,'gold':None,'review':'pending','split':'development'})
    for e in dials:
        if e['outcome'] in {'timeout','error'}:
            add('dial_'+e['outcome'],e,caveat='Dial outcome alone cannot attribute failure to the node; target/dependency/control evidence required.')
        elif e['outcome']=='canceled':
            add('canceled_not_failure',e,caveat='Cancellation is not a failed-node label.')
    for rs in flows.values():
        streak=[]
        for e in rs:
            if e['kind']!='load_window':continue
            l=e['load'];down=l['own_down_bytes'];dt=e['duration_ms']
            # Screening threshold only, not production policy or a fault label.
            slow=dt>=15000 and e['outcome']=='open' and down is not None and 0<down*1000/dt<16384
            contiguous=not streak or abs(e['start_ms']-end(streak[-1]))<=1000
            if not slow:streak=[];continue
            if not contiguous:streak=[]
            streak.append(e)
            if len(streak)==3:
                add('three_low_transfer_windows',e,caveat='Three measured windows below 16 KiB/s with nonzero bytes; application demand remains unobserved. Not a degradation label.')
                break
        ended=[e for e in rs if e['kind']=='relay_end' and e['outcome'] in {'relay_error','offload_error'}]
        if ended:add('relay_error_reason_missing',ended[0],caveat='Captured terminal category does not distinguish peer reset, cancellation or network fault; obtain error provenance before labeling.')
        measured=[e for e in rs if e['kind']=='load_window' and e['load']['own_down_bytes'] is not None]
        if measured:
            if all(e['load']['own_down_bytes']==0 for e in measured):
                add('zero_bytes_demand_unknown',measured[0],caveat='Zero downstream bytes do not establish unmet demand or a slow node.')
            for e in measured:
                l=e['load'];dt=e['duration_ms']
                if dt>=15000 and l['other_down_bytes'] is not None and l['other_down_bytes']*1000/dt>=65536 and l['other_down_bytes']>=10*max(1,l['own_down_bytes']):
                    add('other_traffic_dominates',e,caveat='Other traffic exceeds this flow by >=10x and >=64 KiB/s; screening contrast only, not proof of contention or capacity.')
                    break
        successes=[e for e in rs if e['kind']=='dial' and e['outcome']=='success']
        normals=[e for e in rs if e['kind']=='relay_end' and e['outcome']=='relay_ended']
        if successes and normals:
            add('normal_completion_comparison',normals[0],caveat='Normal observed completion is a comparison candidate, not proof of adequate speed or application success.')
    dns=[e for e in events if e['dns'] is not None]
    for e in dns:
        f=e['dns']
        if f['rcode']==2:
            add('dns_servfail',e,caveat='Resolver SERVFAIL; root cause and impact need dependency evidence.')
        elif f['rcode']==3:
            add('dns_nxdomain_review',e,caveat='NXDOMAIN may be legitimate; check whether the requested name should exist.')
        elif f['qtype']==1 and f['answer_ips']==0 and f['rcode'] in (None,0):
            add('dns_empty_A_review',e,caveat='Empty A may be legitimate. SmartDNS audit has no RCODE/filter provenance; do not assume FakeIP filtering.')
    # Later success is follow-up only, never a control at the failure time.
    successes=collections.defaultdict(list)
    for e in sorted(dials,key=end):
        if e['outcome']=='success':
            s=e['scope'];successes[(e['generation'],e['target_id'],s['node_id'],s['network'],s['policy_epoch'])].append(e)
    for e in dials:
        if e['outcome'] not in {'error','timeout'} or not e['target_id']:continue
        s=e['scope'];ls=successes[(e['generation'],e['target_id'],s['node_id'],s['network'],s['policy_epoch'])]
        later=next((r for r in ls if end(e)<r['start_ms'] and end(r)-end(e)<=1800000),None)
        if later:add('later_dial_success',e,[later],caveat='Same target/node later dial success within 30 min; not simultaneous control or confirmed node recovery. Future evidence excluded from failure-time input.')
    dns_success=collections.defaultdict(list)
    def dns_key(e):
        f=e['dns'];return (e['kind'],e['scope']['site_id'],f['qtype'],f['upstream_id'])
    for e in sorted(dns,key=end):
        f=e['dns']
        if f['rcode'] in (None,0) and f['answer_ips']>f['fake_ips']:
            dns_success[dns_key(e)].append(e)
    for e in dns:
        f=e['dns']
        if f['qtype']!=1 or f['answer_ips']!=0:continue
        later=next((r for r in dns_success[dns_key(e)] if end(e)<r['start_ms'] and end(r)-end(e)<=1800000),None)
        if later:add('later_dns_answer',e,[later],caveat='A later real-address answer is not evidence available at the earlier decision; same site/type/observer, not proven common root cause.')
    # Audit the lack of simultaneous cross-node controls without loosening it.
    groups=collections.defaultdict(list)
    for e in dials:
        if e['target_id']:groups[(e['generation'],e['target_id'])].append(e)
    pairs=[];multi=0
    for rs in groups.values():
        if len({e['scope']['node_id'] for e in rs if e['scope']['node_id']})<2:continue
        multi+=1
        for i,a in enumerate(rs):
            for b in rs[i+1:]:
                if not a['scope']['node_id'] or not b['scope']['node_id'] or a['scope']['node_id']==b['scope']['node_id']:continue
                gap=abs(end(a)-end(b))
                pairs.append({'a':reference(a),'b':reference(b),'gap_ms':gap,
                    'same_network':a['scope']['network']==b['scope']['network'],
                    'same_policy_epoch':a['scope']['policy_epoch']==b['scope']['policy_epoch']})
    chosen=[]
    for category,rs in sorted(categories.items()):
        # Diverse site/node selections first. Do not inflate identical incidents.
        ordered=sorted(rs,key=lambda r:r['candidate_id']);seen=set();first=[];rest=[]
        for r in ordered:
            key=(r['site_id'],r['node_id'])
            (rest if key in seen else first).append(r);seen.add(key)
        chosen.extend((first+rest)[:limit])
    return {'schema':'kdae-screening-v1','status':'development_review_only','gold_count':0,
       'events':len(events),'provisional_flows':sum(any(e['dns'] is None for e in rs) for rs in flows.values()),
       'dial_outcomes':dict(collections.Counter(e['outcome'] for e in dials)),
       'category_counts':{k:len(v) for k,v in sorted(categories.items())},
       'selected_counts':dict(collections.Counter(r['category'] for r in chosen)),
       'selection_limit_per_category':limit,'root_cause_independence':'unreviewed',
       'controls_audit':{'nodes':len({e['scope']['node_id'] for e in dials if e['scope']['node_id']}),
          'targets_observed_on_multiple_nodes':multi,'cross_node_pairs':len(pairs),
          'minimum_gap_ms':min((r['gap_ms'] for r in pairs),default=None),
          'pairs_within_10s':sum(r['gap_ms']<=10000 for r in pairs),
          'nearest_pairs':sorted(pairs,key=lambda r:r['gap_ms'])[:10]},'candidates':chosen}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False,mode=0o700)
    events_paths=[];capture_paths=[];sources=[];gaps=[]
    for f in sorted(a.archive.glob('*.manifest.json')):
        m=json.loads(f.read_text());data=f.with_suffix('').with_suffix('.jsonl')
        if hashlib.sha256(data.read_bytes()).hexdigest()!=m['sha256']:raise ValueError('hash mismatch: '+str(data))
        if m['endpoint'] not in {'capture','evidence','smartdns_audit'}:raise ValueError('unknown endpoint')
        (capture_paths if m['endpoint']=='capture' else events_paths).append(data)
        sources.append({'file':data.name,'sha256':m['sha256'],'endpoint':m['endpoint']})
        if m.get('gap'):gaps.append(m['gap'])
    events=load(events_paths);captures=load(capture_paths,True);report=screen(events)
    report.update(sources=sources,archive_gaps=gaps,capture_records=len(captures),frozen_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    refs={(r['generation'],r['id']) for c in report['candidates'] for r in c['input_refs']+c['followup_refs_not_model_input']}
    refs.update((r[k]['generation'],r[k]['id']) for r in report['controls_audit']['nearest_pairs'] for k in ('a','b'))
    selected=[e for e in events if (e['generation'],e['id']) in refs]
    capture_ids={(e['generation'],e['capture_episode_id']) for e in selected if e['capture_episode_id']}
    selected_captures=[e for e in captures if (e['generation'],e['episode_id']) in capture_ids]
    # Include full raw flow windows as review attachments, not as implicit inputs.
    for name,rs in [('selected-events.jsonl',selected),('selected-captures-review-only.jsonl',selected_captures)]:
        data=b''.join((json.dumps(r,separators=(',',':'))+'\n').encode() for r in rs)
        (a.output/name).write_bytes(data)
        report.setdefault('artifacts',{})[name]={'sha256':hashlib.sha256(data).hexdigest(),'records':len(rs)}
    (a.output/'screening.json').write_text(json.dumps(report,indent=2)+'\n')
    rows=['# 真实证据首轮筛查','', '状态：开发复核候选；无人工金标准，不可直接训练。','', '| 候选类型 | 全部候选数 | 本批选取 |','|---|---:|---:|']
    for k,n in report['category_counts'].items():rows.append(f'| {k} | {n} | {report["selected_counts"].get(k,0)} |')
    rows+=['', '同一事件可能进入多个类别；候选数不能相加作为独立根因数。','', '控制对照审计：'+json.dumps(report['controls_audit'],ensure_ascii=False),'', '每项 input_refs 仅含判定时刻已结束的同流事实；followup_refs_not_model_input 和原始完整字节窗口附件不得直接混入训练输入。','', '下一步：人工核对目标是否有效、错误原因、同窗口外部负载和 DNS 依赖，合并 incident，再进行双人盲审；不可用当前筛查规则生成 gold。']
    (a.output/'README.md').write_text('\n'.join(rows)+'\n')
    for f in a.output.iterdir():f.chmod(0o600)
    print(json.dumps({k:v for k,v in report.items() if k not in {'sources','candidates','controls_audit'}},ensure_ascii=False))
    print(json.dumps(report['controls_audit']))
if __name__=='__main__':main()
