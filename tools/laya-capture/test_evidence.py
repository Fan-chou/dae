import copy
import json
from pathlib import Path
import tempfile
import unittest
from evidence import bundle, validate, SCHEMA
from smartdns_evidence import parse
from collect_evidence import archive


def event(kind="dial", **kwargs):
    e=dict(schema=SCHEMA,generation="generation-a",sequence=1,id="event-1",flow_id="flow-1",capture_episode_id="",kind=kind,
       scope=dict(site_id="a"*32,node_id="b"*32,group_id="c"*32,network="tcp4",path="proxy",policy_epoch=1),
       target_id="d"*32,target_kind="ip",client_id="e"*32,start_ms=100000,duration_ms=100,outcome="success",dns=None,load=None,
       inclusion_probability=.025,source="kdae",sampling_frame="uniform_trace")
    e.update(kwargs);return e

class EvidenceTests(unittest.TestCase):
    def test_error_facts_are_bounded_and_stage_linked(self):
        validate(event())  # Old archives remain readable.
        a = event(outcome="error", error_facts={"class": "connection_reset", "stage": "dial"})
        validate(a)
        a["error_facts"]["class"] = "dial secret.example:443"
        with self.assertRaises(ValueError): validate(a)
        a["error_facts"] = {"class": "unknown", "stage": "relay"}
        with self.assertRaises(ValueError): validate(a)

    def test_future_and_same_node_not_control(self):
        a=event()
        future=event(id="future",flow_id="flow-2",start_ms=100101)
        future["scope"]["node_id"]="f"*32
        same=event(id="same",flow_id="flow-3",start_ms=99999)
        valid=event(id="valid",flow_id="flow-4",start_ms=99999)
        valid["scope"]["node_id"]="f"*32
        late=event("relay_end",id="later",start_ms=101000,outcome="relay_error")
        ep=next(e for e in bundle([a,future,same,valid,late])["episodes"] if e["flow_id"]=="flow-1")
        self.assertEqual(ep["control_candidates"],[dict(event_id="valid",strength="same_ip_candidate",outcome="success")])
        self.assertEqual(ep["followup_event_ids_not_model_input"],["later"])
        self.assertIsNone(ep["gold"])
        self.assertNotIn("future",ep["input_event_ids"])

    def test_protocol_epoch_and_names(self):
        a=event(target_kind="name")
        b=event(id="other",flow_id="flow-2",start_ms=99999,target_kind="name")
        b["scope"]["node_id"]="f"*32
        self.assertEqual(bundle([a,b])["episodes"][0]["control_candidates"][0]["strength"],"same_name_candidate")
        b["scope"]["network"]="tcp6"
        self.assertTrue(all(not r["control_candidates"] for r in bundle([a,b])["episodes"]))
        b["scope"]["network"]="tcp4";b["scope"]["policy_epoch"]=2
        self.assertTrue(all(not r["control_candidates"] for r in bundle([a,b])["episodes"]))

    def test_smartdns_does_not_invent_dns_rcode_cache_or_cause(self):
        line="[2026-09-26 09:00:00,123] 192.168.124.223 query secret.example, type 1, time 5ms, speed: -0.1ms, group domestic, result "
        e=parse(line,bytes(32));validate(e)
        self.assertEqual(e["outcome"],"empty_result")
        self.assertIsNone(e["dns"]["rcode"])
        self.assertIsNone(e["dns"]["truncated"])
        self.assertEqual(e["dns"]["cache_status"],"unknown")
        self.assertIsNone(e["inclusion_probability"])
        self.assertNotIn("secret.example",json.dumps(e))
        self.assertNotIn("192.168.124.223",json.dumps(e))
        self.assertEqual(e,parse(line,bytes(32)))

    def test_unknown_fields_and_raw_addresses_rejected(self):
        a=event();a["raw_host"]="secret"
        with self.assertRaises(ValueError):validate(a)
        a=event(target_id="1.2.3.4")
        with self.assertRaises(ValueError):validate(a)

    def test_budget_and_interrupted_manifest_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            with self.assertRaises(ValueError):archive([event()],p,{},1)
            path=archive([event()],p,{},10000)
            path.with_suffix(".manifest.json").unlink()
            self.assertEqual(archive([event()],p,{},10000),path)
            self.assertTrue(path.with_suffix(".manifest.json").exists())


class AnnotationTests(unittest.TestCase):
    def test_future_citations_and_split_leakage_rejected(self):
        from annotations import validate as check
        report=bundle([event(),event("relay_end",id="future",start_ms=102000,outcome="relay_error")])
        tasks={t:dict(label="unknown",evidence_ids=[],rationale="Evidence unavailable") for t in ("node_fault","demand_shortfall","recovery")}
        a=dict(generation="generation-a",flow_id="flow-1",incident_id="incident-1",split="development",reviews=[dict(reviewer=r,model_blind=True,tasks=copy.deepcopy(tasks)) for r in ("reviewer-a","reviewer-b")])
        self.assertEqual(check(report,[a])["reviewed_flows"],1)
        a["reviews"][0]["tasks"]["node_fault"]["evidence_ids"]=["future"]
        with self.assertRaises(ValueError):check(report,[a])
        a["reviews"][0]["tasks"]["node_fault"]["evidence_ids"]=[]
        a["reviews"][1]["reviewer"]="reviewer-a"
        with self.assertRaises(ValueError):check(report,[a])

class ReviewArchiveTests(unittest.TestCase):
    def test_provenance_hash_checked(self):
        import datetime
        from review_archive import review
        with tempfile.TemporaryDirectory() as d:
            path=archive([event()],Path(d),{'endpoint':'evidence'},10000)
            day=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')
            r=review(Path(d),day)
            self.assertEqual(r['provisional_flows'],1)
            self.assertEqual(len(r['sources']),1)
            path.write_text(path.read_text().replace('success','timeout'))
            with self.assertRaises(ValueError):review(Path(d),day)

class CollectorTests(unittest.TestCase):
    def test_overlapping_audit_tail_not_rearchived(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import datetime
        from collect_evidence import run
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);key=root/'key';key.write_bytes(bytes(32));key.chmod(0o600)
            ts=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
            line=f'[{ts}] 192.168.124.223 query example.test, type 1, time 1ms, speed: 1.0ms, group domestic, result 192.0.2.1'
            dns=parse(line,bytes(32));e=event(start_ms=dns['start_ms']+dns['duration_ms']+1,duration_ms=1)
            e['scope']['site_id']=dns['scope']['site_id']
            def fake_ssh(host,command):
                if command.startswith('sha256sum'):return 'a'*64+'  /proc/1/exe\n'
                if command.startswith('tail'):return line
                records=[e] if ' evidence 0' in command else []
                return json.dumps(dict(enabled=True,generation='generation-a',records=records,oldest_sequence=1 if records else 0,next_sequence=1 if records else int(command.split()[-1])))
            args=SimpleNamespace(output=root/'archive',router='router',smartdns='dns',key_file=key,max_pages=2,daily_budget=100000)
            with patch('collect_evidence.ssh',fake_ssh):
                run(args);first=json.loads((args.output/'latest-status.json').read_text())
                run(args);second=json.loads((args.output/'latest-status.json').read_text())
            self.assertEqual(first['smartdns_records'],1)
            self.assertEqual(second['smartdns_records'],0)
            self.assertEqual(json.loads((args.output/'cursor.json').read_text())['evidence']['after'],1)

class ArchiveDurabilityTests(unittest.TestCase):
    def test_interrupted_data_publication_can_be_retried(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with patch('archive_io.os.fsync', side_effect=OSError('interrupted write')):
                with self.assertRaises(OSError):
                    archive([event()], root, {}, 10000)
            self.assertEqual(list(root.iterdir()), [])
            path = archive([event()], root, {}, 10000)
            self.assertEqual(json.loads(path.read_text()), event())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_manifest_retry_does_not_double_count_data_budget(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = archive([event()], root, {}, 10000)
            meta = path.with_suffix('.manifest.json')
            budget = path.stat().st_size + meta.stat().st_size
            meta.unlink()
            self.assertEqual(archive([event()], root, {}, budget), path)

class DNSAnchorTests(unittest.TestCase):
    def test_dns_links_to_setup_when_first_load_window_closes(self):
        dns = event('dns_client_reply', id='dns-before', flow_id='dns-flow', start_ms=94900, duration_ms=50,
                    sampling_frame='uniform_dns_event',
                    dns=dict(qtype=1, rcode=0, answer_ips=0, fake_ips=0, truncated=False,
                             cache_status='unknown', filter_reason='unobserved', upstream_id='', answer_ids=[]))
        window = event('load_window', id='load', start_ms=100100, duration_ms=15000,
                       load=dict(own_up_bytes=0, own_down_bytes=100, other_up_bytes=0, other_down_bytes=0,
                                 active_connections_at_snapshot=1, starts_total_at_snapshot=1,
                                 alignment='best_effort_non_atomic_snapshots', missing_reason=''))
        future = copy.deepcopy(dns)
        future.update(id='dns-after', start_ms=100050)
        resolution = event('selection_resolution', id='resolution', start_ms=95000, duration_ms=5100)
        during = copy.deepcopy(dns)
        during.update(id='dns-during', start_ms=99900)
        upstream = copy.deepcopy(during)
        upstream.update(id='upstream', kind='dns_upstream')
        upstream['dns']['cache_status'] = 'not_applicable'
        ep = bundle([resolution, event(), window, dns, future, during, upstream])['episodes'][0]
        self.assertEqual(ep['decision_ms'],115100)
        self.assertEqual([c['event_id'] for c in ep['dns_candidates']], ['dns-before'])
        self.assertEqual([c['event_id'] for c in ep['dns_upstream_candidates']], ['upstream'])

class CollectorRecoveryTests(unittest.TestCase):
    def test_audit_anchors_survive_smartdns_failure_after_cursor_commit(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import datetime
        import subprocess
        from collect_evidence import run
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            key=root/'key';key.write_bytes(bytes(32));key.chmod(0o600)
            ts=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
            line=f'[{ts}] 192.168.124.223 query example.test, type 1, time 1ms, speed: 1.0ms, group domestic, result 192.0.2.1'
            dns=parse(line,bytes(32))
            e=event(start_ms=dns['start_ms']+dns['duration_ms']+1)
            e['scope']['site_id']=dns['scope']['site_id']
            failed=True
            def fake_ssh(host, command):
                if command.startswith('sha256sum'):return 'a'*64+' /proc/1/exe\n'
                if command.startswith('tail'):
                    if failed:raise subprocess.CalledProcessError(1, 'ssh')
                    return line
                after=int(command.split()[-1])
                records=[e] if ' evidence 0' in command else []
                return json.dumps(dict(enabled=True,generation='generation-a',records=records,
                                       oldest_sequence=1 if records else 0,next_sequence=1 if records else after))
            args=SimpleNamespace(output=root/'archive',router='router',smartdns='dns',key_file=key,max_pages=2,daily_budget=100000)
            with patch('collect_evidence.ssh',fake_ssh):
                with self.assertRaises(subprocess.CalledProcessError):run(args)
                state=json.loads((args.output/'cursor.json').read_text())
                self.assertEqual(state['evidence']['after'],1)
                self.assertEqual(state['audit_anchors'],[[e['scope']['site_id'],e['start_ms']]])
                failed=False
                run(args)
            status=json.loads((args.output/'latest-status.json').read_text())
            self.assertEqual(status['smartdns_records'],1)

class ReviewIdentityTests(unittest.TestCase):
    def test_reviewer_normalization_and_incident_split_validation_across_batches(self):
        from annotations import validate as check
        report=bundle([event(),event(id='event-2',flow_id='flow-2')])
        tasks={t:dict(label='unknown',evidence_ids=[],rationale='Evidence unavailable') for t in ('node_fault','demand_shortfall','recovery')}
        a=dict(generation='generation-a',flow_id='flow-1',incident_id='incident',split='train',
               reviews=[dict(reviewer=r,model_blind=True,tasks=copy.deepcopy(tasks)) for r in ('Alice',' alice ')])
        with self.assertRaises(ValueError):check(report,[a])
        a['reviews'][1]['reviewer']='Bob'
        b=copy.deepcopy(a);b.update(flow_id='flow-2',split='final_test')
        with self.assertRaises(ValueError):check(report,[a,b])

class IdentityKeyTests(unittest.TestCase):
    def test_hex_key_and_private_permissions(self):
        from smartdns_evidence import read_key
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'key'
            path.write_text('ab'*32+'\n');path.chmod(0o600)
            self.assertEqual(read_key(path),bytes.fromhex('ab'*32))
            path.chmod(0o644)
            with self.assertRaises(ValueError):read_key(path)

class AdditionalValidationTests(unittest.TestCase):
    def test_source_kind_and_timestamp(self):
        for changes in (dict(kind='smartdns_audit'), dict(start_ms=253402300800000), dict(scope=[])):
            with self.subTest(changes=changes), self.assertRaises(ValueError):validate(event(**changes))

    def test_fifo_key_is_rejected_without_open(self):
        import os
        from smartdns_evidence import read_key
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'fifo'
            os.mkfifo(path,0o600)
            with self.assertRaises(ValueError):read_key(path)
            link=Path(d)/'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):read_key(link)

    def test_empty_new_generation_commits_zero_cursor(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from collect_evidence import run
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'cursor.json').write_text(json.dumps({e:dict(after=12,generation='old') for e in ('capture','evidence')}))
            calls=[]
            def fake_ssh(host,command):
                if command.startswith('sha256sum'):return 'a'*64+' /proc/1/exe'
                calls.append(command)
                return json.dumps(dict(enabled=True,generation='new',oldest_sequence=0,next_sequence=int(command.split()[-1]),records=[]))
            args=SimpleNamespace(output=root,router='router',smartdns='',max_pages=2,daily_budget=100000)
            with patch('collect_evidence.ssh',fake_ssh):run(args)
            state=json.loads((root/'cursor.json').read_text())
            self.assertEqual(state['capture'],dict(after=0,generation='new'))
            self.assertEqual(state['evidence'],dict(after=0,generation='new'))
            self.assertEqual(len(calls),4)

class CollectorAnchorTests(unittest.TestCase):
    def test_later_dial_preserves_earliest_anchor_across_runs(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import time
        from collect_evidence import run
        start=int(time.time()*1000)-5000
        resolution=event('selection_resolution',id='resolution',start_ms=start,duration_ms=4000)
        dial=event(id='dial',sequence=2,start_ms=start+4000,duration_ms=100)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            def fake_ssh(host,command):
                if command.startswith('sha256sum'):return 'a'*64+' /proc/1/exe'
                after=int(command.split()[-1])
                records=([resolution] if after==0 else [dial] if after==1 else []) if ' evidence ' in command else []
                return json.dumps(dict(enabled=True,generation='generation-a',oldest_sequence=1 if records else 0,next_sequence=records[-1]['sequence'] if records else after,records=records))
            args=SimpleNamespace(output=root,router='router',smartdns='',max_pages=2,daily_budget=100000)
            with patch('collect_evidence.ssh',fake_ssh):
                run(args);run(args)
            state=json.loads((root/'cursor.json').read_text())
            self.assertEqual(state['evidence']['after'],2)
            self.assertEqual(state['audit_anchors'],[[resolution['scope']['site_id'],start]])


    def test_legacy_anchors_survive_capture_commit_and_evidence_failure(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import time
        import subprocess
        from collect_evidence import run
        from test_validate import sample
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            anchors=[['a'*32,int(time.time()*1000)-1000]]
            (root/'cursor.json').write_text(json.dumps(dict(audit_anchors=anchors)))
            record=sample()
            def fake_ssh(host,command):
                if command.startswith('sha256sum'):return 'a'*64+' /proc/1/exe'
                if ' evidence ' in command:raise subprocess.CalledProcessError(1,'ssh')
                return json.dumps(dict(enabled=True,generation=record['generation'],oldest_sequence=1,next_sequence=1,records=[record]))
            args=SimpleNamespace(output=root,router='router',smartdns='',max_pages=2,daily_budget=100000)
            with patch('collect_evidence.ssh',fake_ssh), self.assertRaises(subprocess.CalledProcessError):run(args)
            state=json.loads((root/'cursor.json').read_text())
            self.assertEqual(state['audit_anchors'],anchors)
            self.assertEqual(state['capture']['after'],1)


class ObservationReaderTests(unittest.TestCase):
    def test_comments_after_quoted_and_unquoted_secrets(self):
        import os
        import subprocess
        script=Path(__file__).with_name('read-observation.sh').read_text()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            config=root/'local.dae'
            reader=root/'read.sh'
            reader.write_text(script.replace('/etc/dae/local.dae',str(config)))
            curl=root/'curl'
            curl.write_text('#!/bin/sh\ncat\n');curl.chmod(0o700)
            env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ['PATH'])
            for value,expected in [('token # comment','token'), ("'token' # comment",'token'), ('"token" # comment','token'), ("'token#part' # comment",'token#part')]:
                config.write_text('global {\n admin_secret: '+value+'\n}\n')
                output=subprocess.check_output(['sh',str(reader),'evidence','0'],env=env,text=True)
                self.assertEqual(output,'header = "Authorization: Bearer '+expected+'"\n')

if __name__ == "__main__":
    unittest.main()
