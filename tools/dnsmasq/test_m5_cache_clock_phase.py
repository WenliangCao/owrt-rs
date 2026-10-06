import copy
import unittest

import m5_dns_cache as family


class ImmediatePtrClockTests(unittest.TestCase):
    def fixture(self):
        rr={'section':'answer','type':12,'ttl':600,'data':'target.cache.test'}
        seed={'label':'query-0','reply':{'records':[rr]},'sent_monotonic_ns':1000000000,
              'completed_monotonic_ns':1010000000,'sent_realtime_ns':1000900000000,
              'completed_realtime_ns':1000910000000}
        replay={'label':'query-1','reply':{'records':[dict(rr,ttl=599)]},
                'sent_monotonic_ns':1150000000,'completed_monotonic_ns':1160000000,
                'sent_realtime_ns':1001050000000,'completed_realtime_ns':1001060000000}
        return {'case':'ptr-tcp-child-import','observations':[seed,replay]},replay

    def test_integer_boundary_admission_is_specific_and_clock_derived(self):
        row,replay=self.fixture();self.assertTrue(family.immediate_ptr_phase(row,replay))
        for mode in ['other-case','missing-clock','ttl598','same-second599','wall-jump','late-replay']:
            bad=copy.deepcopy(row);current=bad['observations'][1]
            if mode=='other-case':bad['case']='ttl-max-then-min'
            elif mode=='missing-clock':current.pop('sent_realtime_ns')
            elif mode=='ttl598':current['reply']['records'][0]['ttl']=598
            elif mode=='same-second599':
                for observation in bad['observations']:
                    observation['sent_realtime_ns']-=500000000;observation['completed_realtime_ns']-=500000000
            elif mode=='wall-jump':current['sent_realtime_ns']+=10000000;current['completed_realtime_ns']+=10000000
            else:
                current['sent_realtime_ns']+=1000000000;current['completed_realtime_ns']+=1000000000
                current['sent_monotonic_ns']+=1000000000;current['completed_monotonic_ns']+=1000000000
            self.assertFalse(family.immediate_ptr_phase(bad,current),mode)


if __name__=='__main__':unittest.main()
