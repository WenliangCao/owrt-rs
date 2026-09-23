#!/usr/bin/env python3
"""Pure arithmetic, ordering and original-caller CLI checks; no workloads."""
from decimal import Decimal
from fractions import Fraction as F
from pathlib import Path
import unittest
import caller_screen as s


class Rules(unittest.TestCase):
    def setUp(self): self.policy = s.read(s.POLICY)
    def data(self, new=F(98, 100)):
        return {(b, d, c, lane): {m: (new if c == 'new' else F(1)) for m in s.METRICS}
                for b in range(6) for d in ('c', 'r136') for c in ('old', 'new') for lane in self.policy['lanes']}
    def test_primary_and_both_daemons_required(self):
        data = self.data(); self.assertTrue(s.decisions(data, self.policy)['screen_passed'])
        for k, v in data.items():
            if k[1:3] == ('c', 'new'): v['mean_us'] = F(1)
        result = s.decisions(data, self.policy)
        self.assertFalse(result['screen_passed']); self.assertTrue(result['primary'][1]['passed'])
    def test_primary_threshold_is_strict_and_gm_not_arithmetic(self):
        self.assertFalse(s.decisions(self.data(F(99, 100)), self.policy)['screen_passed'])
        data = self.data()
        for b in range(6):
            for d in ('c', 'r136'):
                for lane, value in zip(self.policy['lanes'], (F(1, 2), F(1), F(2))): data[b,d,'new',lane]['mean_us'] = value
        result = s.decisions(data, self.policy)
        self.assertEqual([r['median_geometric_ratio'] for r in result['primary']], ['1.000000000000000000000000000000'] * 2)
    def test_five_of_six_required(self):
        data = self.data(F(9, 10))
        for b in (4, 5):
            for lane in self.policy['lanes']: data[b,'c','new',lane]['mean_us'] = F(1001,1000)
        result = s.decisions(data, self.policy); self.assertFalse(result['primary'][0]['passed'])
    def test_all_eighteen_veto_dimensions(self):
        for d in ('c', 'r136'):
            for lane in self.policy['lanes']:
                for metric in ('mean_us', 'p95_us', 'p99_us'):
                    data = self.data()
                    for b in range(6): data[b,d,'new',lane][metric] = F(104,100)
                    result = s.decisions(data,self.policy)
                    self.assertEqual(len(result['vetoes']),1)
                    self.assertFalse(result['screen_passed'])
    def test_veto_strict_threshold_all_six_and_cpu_not_gate(self):
        data = self.data()
        for b in range(6):
            data[b,'c','new','register_1']['p99_us'] = F(103,100)
            data[b,'c','new','register_1']['caller_cpu_us_per_op'] = F(2)
        self.assertTrue(s.decisions(data,self.policy)['screen_passed'])
        for b in range(6): data[b,'c','new','register_1']['p99_us'] = F(104,100)
        data[0,'c','new','register_1']['p99_us'] = F(1)
        self.assertTrue(s.decisions(data,self.policy)['screen_passed'])
    def test_unresolved_inclusive_and_missing_case(self):
        result=s.decisions(self.data(F(101,100)),self.policy)
        self.assertTrue(all(r['direction']=='unresolved_within_1pct' for r in result['comparisons']))
        data=self.data();del data[0,'c','old','register_1']
        with self.assertRaises(RuntimeError):s.decisions(data,self.policy)
    def test_schedule_and_pair_order_balance(self):
        manifest={'phase':'screen','policy':self.policy}; rows=s.schedule(manifest)
        self.assertEqual(len(rows),len(set(rows))); self.assertEqual(len(rows),72)
        labels=[tuple(x) for x in self.policy['orders'][0]]
        for a in labels:
            for b in labels:
                if a!=b:self.assertEqual(sum(list(map(tuple,o)).index(a)<list(map(tuple,o)).index(b) for o in self.policy['orders']),3)
        self.assertEqual(len(s.schedule({'phase':'smoke','policy':self.policy})),12)
    def test_original_cli_and_quantiles(self):
        self.assertEqual(s.caller_args('lookup_1',Path('/s'),Path('/o'),10,3),['lookup','/s','bench.target','10','20','3'])
        self.assertEqual(s.caller_args('invoke_1',Path('/s'),Path('/o'),10000,3),['rpc','/s','bench.target','ping','/o/input.json','/o/expect.json','10000','20','3'])
        data={'latency_ns':list(range(1,10001)),'wall_s':1,'daemon_cpu':[{'cpu_clock_ns':10000000}],'client_cpu_clock_ns':20000000}
        m=s.metrics(data,10000);self.assertEqual(m['p50_us'],F(5001,1000));self.assertEqual(m['p95_us'],F(19,2));self.assertEqual(m['p99_us'],F(99,10));self.assertEqual(m['mean_us'],F(10001,2000))


if __name__=='__main__':unittest.main()
