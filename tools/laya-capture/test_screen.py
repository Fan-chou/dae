import unittest
from test_evidence import event
from screen import screen

class ScreeningTests(unittest.TestCase):
    def test_later_success_is_followup_not_control_or_input(self):
        a=event(outcome='timeout')
        b=event(id='later',flow_id='flow-2',start_ms=164000)
        report=screen([a,b])
        recovery=next(c for c in report['candidates'] if c['category']=='later_dial_success')
        self.assertEqual(recovery['input_refs'],[{'generation':a['generation'],'id':a['id']}])
        self.assertEqual(recovery['followup_refs_not_model_input'],[{'generation':b['generation'],'id':b['id']}])
        self.assertIsNone(recovery['gold'])
        b['scope']['node_id']='f'*32
        report=screen([a,b])
        self.assertEqual(report['controls_audit']['minimum_gap_ms'],64000)
        self.assertEqual(report['controls_audit']['pairs_within_10s'],0)
        self.assertNotIn('later_dial_success',report['category_counts'])

    def test_low_transfer_requires_three_contiguous_measured_nonzero_windows(self):
        rs=[]
        for i in range(3):
            rs.append(event('load_window',id=f'window-{i}',sequence=i+1,start_ms=100000+i*15000,duration_ms=15000,outcome='open',load={'own_down_bytes':1000,'other_down_bytes':None}))
        self.assertEqual(screen(rs)['category_counts'].get('three_low_transfer_windows'),1)
        rs[1]['load']['own_down_bytes']=None
        self.assertNotIn('three_low_transfer_windows',screen(rs)['category_counts'])
        rs[1]['load']['own_down_bytes']=1000;rs[2]['start_ms']+=2000
        self.assertNotIn('three_low_transfer_windows',screen(rs)['category_counts'])

    def test_empty_aaaa_not_a_failure_candidate(self):
        a=event('dns_client_reply',dns={'qtype':28,'answer_ips':0,'rcode':0,'fake_ips':0,'upstream_id':''})
        report=screen([a])
        self.assertNotIn('dns_empty_A_review',report['category_counts'])
        a['dns']['qtype']=1
        self.assertEqual(screen([a])['category_counts']['dns_empty_A_review'],1)

if __name__=='__main__':unittest.main()
