#!/usr/bin/env python3
"""Verify archive hashes, deduplicate, and build one UTC day's review bundle."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
from evidence import load, bundle


def review(archive, day):
    evidence_paths, capture_paths, sources = [], [], []
    for manifest in sorted(archive.glob(day+'-*.manifest.json')):
        meta=json.loads(manifest.read_text())
        data=manifest.with_suffix('').with_suffix('.jsonl')
        if hashlib.sha256(data.read_bytes()).hexdigest()!=meta['sha256']:
            raise ValueError('archive hash mismatch: '+str(data))
        if meta['endpoint'] not in {'capture','evidence','smartdns_audit'}:
            raise ValueError('unknown archive endpoint')
        (capture_paths if meta['endpoint']=='capture' else evidence_paths).append(data)
        sources.append({'file':data.name,'sha256':meta['sha256'],'manifest':manifest.name})
    result=bundle(load(evidence_paths),load(capture_paths,True))
    result.update(sources=sources,archive_day_utc=day,review_scope='development_only')
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--day',default=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d'))
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--annotation-template',type=Path)
    a=p.parse_args();result=review(a.archive,a.day)
    a.output.write_text(json.dumps(result,indent=2)+'\n');a.output.chmod(0o600)
    if a.annotation_template:
        template=[{'generation':e['generation'],'flow_id':e['flow_id'],'incident_id':'','split':'development','reviews':[{'reviewer':'','model_blind':True,'tasks':{t:{'label':None,'evidence_ids':[],'rationale':''} for t in ('node_fault','demand_shortfall','recovery')}} for _ in range(2)]} for e in result['episodes']]
        a.annotation_template.write_text(json.dumps(template,indent=2)+'\n');a.annotation_template.chmod(0o600)
    print(json.dumps({'events':result['events'],'flows':result['provisional_flows'],'with_dns_candidates':sum(bool(e['dns_candidates']) for e in result['episodes']),'with_dns_upstream_candidates':sum(bool(e['dns_upstream_candidates']) for e in result['episodes']),'with_control_candidates':sum(bool(e['control_candidates']) for e in result['episodes']),'capture_links':sum(bool(e['capture_record_ids']) for e in result['episodes']),'v4_accepted':0}))
