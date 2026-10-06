import copy
import unittest

import m5_pxe as pxe


class PXEKernelWitnessTests(unittest.TestCase):
    def fixture(self):
        profile = {'name': 'fixture', 'mode': 'proxy', 'options': ['pxe-service=0,Menu,boot'],
                   'cases': [{'name': 'request', 'request': '01', 'reply': True, 'copies': 2, 'upstream': 0}]}
        rows = []
        for side, epoch in [('c', 100), ('rust', 200)]:
            packets = [{'packet': payload, 'source': [pxe.SERVER, 67], 'destination': [pxe.CLIENT, 68],
                        'flags': 0, 'received_ns': int((epoch + delay) * 1_000_000_000)}
                       for payload, delay in [('aa', .1), ('bb', .2)]]
            case = {'name': 'request', 'request': '01', 'replies': copy.deepcopy(packets), 'upstream': [],
                    'peer_echo': [], 'leases': None, 'alive': True, 'heartbeat': True,
                    'observation': {'sent_epoch': epoch, 'collected_epoch': epoch + .4,
                                    'raw_kernel_receives': {'client': list(reversed(packets)), 'upstream': []}}}
            rows.append({'profile': 'fixture', 'side': side, 'started': True, 'cases': [case],
                         'test': {'exit': 0, 'stdout': '', 'stderr': ''}, 'listening4011': True, 'threads': 1,
                         'fd_start': {'floor': 3}, 'fd_end': {'floor': 3}, 'pid_removed': True,
                         'cleanup': {'forced': False, 'returncode': 0}})
        return rows, [profile]

    def test_independent_clocks_and_readiness_order_preserve_kernel_order(self):
        rows, corpus = self.fixture()
        self.assertEqual(pxe.evaluate(rows, corpus, ['c', 'rust']), [])
        for row in rows: self.assertEqual(pxe.kernel_receive_errors(row['cases'][0]), [])

    def test_missing_or_invalid_witness_cannot_pass(self):
        for mutation in ['missing-both', 'missing-time', 'zero-time', 'future-time', 'before-send', 'bad-bounds']:
            with self.subTest(mutation=mutation):
                rows, corpus = self.fixture(); case = rows[1]['cases'][0]
                witness = case['observation']['raw_kernel_receives']['client']
                if mutation == 'missing-both':
                    for row in rows: row['cases'][0].pop('observation')
                elif mutation == 'missing-time': witness[0].pop('received_ns')
                elif mutation == 'zero-time': witness[0]['received_ns'] = 0
                elif mutation == 'future-time': witness[0]['received_ns'] = 201_000_000_000
                elif mutation == 'before-send': witness[0]['received_ns'] = 199_000_000_000
                else: case['observation']['sent_epoch'] = float('nan')
                self.assertTrue(pxe.evaluate(rows, corpus, ['c', 'rust']))

    def test_consistent_witness_still_rejects_protocol_mutations(self):
        for mutation in ['packet', 'source', 'destination', 'flags', 'missing', 'extra', 'order']:
            with self.subTest(mutation=mutation):
                rows, corpus = self.fixture(); case = rows[1]['cases'][0]
                if mutation == 'missing': case['replies'].pop()
                elif mutation == 'extra':
                    frame = copy.deepcopy(case['replies'][-1]); frame['received_ns'] += 1
                    case['replies'].append(frame)
                elif mutation == 'order':
                    case['replies'].reverse()
                    for index, frame in enumerate(case['replies']): frame['received_ns'] = 200_100_000_000 + index
                else:
                    value = {'packet': 'ff', 'source': ['192.0.2.1', 67],
                             'destination': [pxe.CLIENT, 9999], 'flags': 32}[mutation]
                    case['replies'][0][mutation] = value
                case['observation']['raw_kernel_receives']['client'] = copy.deepcopy(case['replies'])
                self.assertEqual(pxe.kernel_receive_errors(case), [])
                self.assertTrue(pxe.evaluate(rows, corpus, ['c', 'rust']))

    def test_tampered_projection_and_echo_are_rejected(self):
        rows, corpus = self.fixture(); case = rows[1]['cases'][0]
        case['replies'].reverse()
        self.assertTrue(pxe.kernel_receive_errors(case))
        rows, corpus = self.fixture(); case = rows[1]['cases'][0]
        echo = {'packet': '01', 'source': [pxe.CLIENT, 68], 'destination': [pxe.SERVER, 67],
                'flags': 0, 'received_ns': 200_050_000_000}
        case['observation']['raw_kernel_receives']['client'].append(echo)
        case['peer_echo'] = [copy.deepcopy(echo)]
        self.assertEqual(pxe.kernel_receive_errors(case), [])
        case['peer_echo'].clear()
        self.assertTrue(pxe.kernel_receive_errors(case))


if __name__ == '__main__': unittest.main()
