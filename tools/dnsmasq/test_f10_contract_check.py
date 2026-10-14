#!/usr/bin/env python3
"""Negative controls for state-scoped F10 PTR order qualifications."""
import copy
import unittest

from f10_contract_check import STOCK_SHA256, build_manifest, check, digest, fixture_input, source_bound_spec


def fixture(kind=12, case='six-addn'):
    name = '1.2.0.192.in-addr.arpa' if kind == 12 else 'y.test'
    records = [{'section': 'answer', 'name': name, 'type': kind, 'class': 1,
                'ttl': 37, 'data': value} for value in ('x.test', 'y.test')]
    observations = []
    for phase in ('before', 'after'):
        for index in range(2):
            observations.append({'label': f'udp-ptr-{phase}-192.0.2.1-{index}',
                'transport': 'udp', 'name': name, 'type': kind,
                'semantics': {'id': 13330, 'flags': 34176, 'questions': [[name, kind, 1]],
                              'records': copy.deepcopy(records)}})
    return {'binary_sha256': STOCK_SHA256, 'errors': [], 'cases': [
        {'case': case, 'completed': True, 'exit': 0, 'observations': observations}]}


def reverse(report, indices=None):
    result = copy.deepcopy(report)
    rows = result['cases'][0]['observations']
    for index in range(len(rows)) if indices is None else indices:
        rows[index]['semantics']['records'].reverse()
    return result


class ContractCheck(unittest.TestCase):
    def setUp(self):
        self.reference = fixture()
        self.alternative = reverse(self.reference)
        self.manifest = build_manifest(self.reference, [self.alternative])

    def test_observed_complete_track_qualifies_and_preserves_order(self):
        original = copy.deepcopy(self.alternative)
        result = check(self.reference, self.alternative, self.manifest)
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['qualified_ptr_order']), 4)
        self.assertEqual(self.alternative, original)

    def test_c_stable_case_reversal_is_not_allowed(self):
        manifest = build_manifest(self.reference, [copy.deepcopy(self.reference)])
        result = check(self.reference, self.alternative, manifest)
        self.assertFalse(result['passed'])
        self.assertTrue(all(row['reason'] == 'no-corresponding-c-c-state' for row in result['failures']))

    def test_absent_allow_manifest_is_default_deny(self):
        self.assertFalse(check(self.reference, self.alternative)['passed'])

    def test_absent_state_cannot_borrow_another_phase(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['entries'][0]['allowed_states'] = [state for state in manifest['entries'][0]['allowed_states']
                                                  if 'before' in state]
        result = check(self.reference, self.alternative, manifest)
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['failures']), 2)
        self.assertTrue(all('after' in row['label'] for row in result['failures']))

    def test_changed_case_name_type_or_transport_cannot_borrow_allow(self):
        for field, replacement in (('case', 'new-five-line'), ('name', '2.2.0.192.in-addr.arpa'),
                                   ('type', 1), ('transport', 'tcp')):
            with self.subTest(field=field):
                reference, actual = copy.deepcopy(self.reference), copy.deepcopy(self.alternative)
                if field == 'case':
                    reference['cases'][0]['case'] = actual['cases'][0]['case'] = replacement
                else:
                    for report in (reference, actual):
                        for row in report['cases'][0]['observations']:
                            row[field] = replacement
                # Re-anchor only the document identity; allow entries still
                # identify the original exact question and source state.
                from f10_contract_check import digest
                manifest = copy.deepcopy(self.manifest)
                manifest['reference_document_sha256'] = digest(reference)
                self.assertFalse(check(reference, actual, manifest)['passed'])

    def test_same_state_repeat_flip_is_not_an_observed_track(self):
        result = check(self.reference, reverse(self.reference, [1]), self.manifest)
        self.assertFalse(result['passed'])
        self.assertTrue(any(row['kind'] == 'same-state-ptr-repeat-instability' for row in result['failures']))
        self.assertTrue(any(row.get('reason') == 'complete-query-sequence-not-observed-in-c'
                            for row in result['failures']))

    def test_forward_query_induced_ptr_flip_cannot_mix_control_tracks(self):
        # Both per-phase orders occur in C, but C keeps one relative order
        # across before/A/after. A candidate must not splice the two C runs.
        result = check(self.reference, reverse(self.reference, [2, 3]), self.manifest)
        self.assertFalse(result['passed'])
        self.assertTrue(all(row['reason'] == 'complete-query-sequence-not-observed-in-c'
                            for row in result['failures']))

    def test_unmanifested_five_line_stateful_ptr_bug_fails(self):
        reference = fixture(case='five-line-a-mutates-ptr')
        actual = reverse(reference, [2, 3])
        result = check(reference, actual)
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['failures']), 2)

    def test_forward_order_never_qualifies(self):
        for kind in (1, 28):
            with self.subTest(kind=kind):
                reference = fixture(kind)
                manifest = build_manifest(reference, [copy.deepcopy(reference)])
                result = check(reference, reverse(reference), manifest)
                self.assertFalse(result['passed'])
                self.assertTrue(all(row['kind'] == 'forward-order' for row in result['failures']))

    def test_header_ttl_count_tc_and_rrset_never_qualify(self):
        mutations = {
            'flags': lambda row: row['semantics'].__setitem__('flags', 34177),
            'tc': lambda row: row['semantics'].__setitem__('flags', 34176 | 0x200),
            'ttl': lambda row: row['semantics']['records'][0].__setitem__('ttl', 90),
            'count': lambda row: row['semantics']['records'].pop(),
            'rrset': lambda row: row['semantics']['records'][0].__setitem__('data', 'wrong.test'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                actual = copy.deepcopy(self.alternative)
                mutate(actual['cases'][0]['observations'][0])
                result = check(self.reference, actual, self.manifest)
                self.assertFalse(result['passed'])
                self.assertTrue(any(row['kind'] == 'rrset-ttl-count-or-header' for row in result['failures']))

    def test_three_owner_unobserved_permutation_is_not_generalized(self):
        reference = fixture()
        for row in reference['cases'][0]['observations']:
            third = copy.deepcopy(row['semantics']['records'][0])
            third['data'] = 'z.test'
            row['semantics']['records'].append(third)
        manifest = build_manifest(reference, [reverse(reference)])
        actual = copy.deepcopy(reference)
        for row in actual['cases'][0]['observations']:
            rr = row['semantics']['records']
            row['semantics']['records'] = rr[1:] + rr[:1]
        self.assertFalse(check(reference, actual, manifest)['passed'])

    def test_wrong_reference_manifest_fails_closed(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['reference_document_sha256'] = '0' * 64
        self.assertFalse(check(self.reference, self.alternative, manifest)['passed'])

    def test_control_rrset_change_cannot_create_allow(self):
        invalid = copy.deepcopy(self.alternative)
        invalid['cases'][0]['observations'][0]['semantics']['records'][0]['ttl'] = 90
        with self.assertRaises(AssertionError):
            build_manifest(self.reference, [invalid])

    def test_missing_case_fails_unless_explicit_subset_requested(self):
        reference = copy.deepcopy(self.reference)
        reference['cases'] += fixture(case='second-case')['cases']
        actual = copy.deepcopy(self.reference)
        self.assertFalse(check(reference, actual)['passed'])
        self.assertTrue(check(reference, actual, expected_cases=['six-addn'])['passed'])

    def test_missing_track_observation_fails(self):
        actual = copy.deepcopy(self.reference)
        actual['cases'][0]['observations'].pop()
        result = check(self.reference, actual, self.manifest)
        self.assertFalse(result['passed'])
        self.assertTrue(any(row['kind'] == 'observation-count' for row in result['failures']))


class SourceBoundCheck(unittest.TestCase):
    def setUp(self):
        self.reference = fixture(case='six-host-record')
        case = self.reference['cases'][0]
        udp = case['observations']
        tcp = copy.deepcopy(udp)
        for row in tcp:
            row['transport'] = 'tcp'
            row['label'] = row['label'].replace('udp-', 'tcp-')
        forward = copy.deepcopy(fixture(kind=1)['cases'][0]['observations'][0])
        forward['label'] = 'udp-forward-0'
        forward['semantics']['records'][0]['data'] = '192.0.2.1'
        forward['semantics']['records'][1]['data'] = '192.0.2.2'
        case['observations'] = udp[:2] + [forward] + udp[2:] + tcp
        for row in case['observations']:
            row['request_wire'] = 'fixed-' + row['label']
        case.update(argv=['chroot', '/private/root', '/usr/sbin/dnsmasq', '-k', '--no-hosts'],
                    initial_files={}, mutations=[], process_sha256=STOCK_SHA256)
        states = [f'{transport}-ptr-{phase}-192.0.2.1'
                  for transport in ('udp', 'tcp') for phase in ('before', 'after')]
        self.entry = {'entry_basis': 'source-bound', 'review_status': 'approved',
            'contract_id': 'six-host-record-ptr-initial-order-v1',
            'reference_document_sha256': digest(self.reference),
            'reference_case_sha256': digest(case),
            'fixture_input_sha256': digest(fixture_input(case)), 'states': states,
            'target_labels': [f'{phase}-{repeat}' for phase in states for repeat in range(2)],
            'permutations': [[0, 1], [1, 0]],
            'reference_records': copy.deepcopy(udp[0]['semantics']['records'])}
        self.manifest = build_manifest(self.reference, [copy.deepcopy(self.reference)])
        self.manifest['source_bound_entries'] = [self.entry]
        self.alternative = copy.deepcopy(self.reference)
        for row in self.alternative['cases'][0]['observations']:
            if row['type'] == 12:
                row['semantics']['records'].reverse()

    def test_uniform_cross_transport_initial_order_qualifies(self):
        result = check(self.reference, self.alternative, self.manifest)
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['qualified_ptr_order']), 8)
        self.assertTrue(all(row['kind'] == 'qualified-source-bound-ptr-order'
                            for row in result['qualified_ptr_order']))

    def test_proposed_entry_is_not_activated(self):
        self.entry['review_status'] = 'proposed'
        result = check(self.reference, self.alternative, self.manifest)
        self.assertFalse(result['passed'])
        self.assertEqual(result['failures'][0]['kind'], 'source-bound-entry-not-approved')

    def test_transport_phase_or_repeat_splicing_fails(self):
        for mode in ('transport', 'phase', 'repeat'):
            with self.subTest(mode=mode):
                actual = copy.deepcopy(self.reference)
                for row in actual['cases'][0]['observations']:
                    selected = (row['transport'] == 'tcp' if mode == 'transport' else
                                '-after-' in row['label'] if mode == 'phase' else
                                row['label'] == 'udp-ptr-before-192.0.2.1-1')
                    if selected:
                        row['semantics']['records'].reverse()
                self.assertFalse(check(self.reference, actual, self.manifest)['passed'])

    def test_changed_input_or_case_is_not_the_declared_contract(self):
        for mode in ('argv', 'files', 'case'):
            with self.subTest(mode=mode):
                actual = copy.deepcopy(self.alternative)
                case = actual['cases'][0]
                if mode == 'argv':
                    case['argv'].append('--no-round-robin')
                elif mode == 'files':
                    case['initial_files']['etc/hosts'] = '192.0.2.1 x.test\n'
                else:
                    case['case'] = 'unknown-source-state'
                self.assertFalse(check(self.reference, actual, self.manifest)['passed'])

    def test_content_and_forward_mutations_cannot_borrow_source_contract(self):
        for mode in ('ttl', 'header', 'tc', 'count', 'rrset', 'forward'):
            with self.subTest(mode=mode):
                actual = copy.deepcopy(self.alternative)
                observations = actual['cases'][0]['observations']
                row = observations[0]['semantics']
                if mode == 'ttl':
                    row['records'][0]['ttl'] += 1
                elif mode in ('header', 'tc'):
                    row['flags'] ^= 1 if mode == 'header' else 0x200
                elif mode == 'count':
                    row['records'].pop()
                elif mode == 'rrset':
                    row['records'][0]['data'] = 'wrong.test'
                else:
                    next(row for row in observations if row['type'] == 1)['semantics']['records'].reverse()
                self.assertFalse(check(self.reference, actual, self.manifest)['passed'])

    def exact_case(self, name):
        reference = copy.deepcopy(self.reference)
        case = reference['cases'][0]
        case['case'] = name
        contract = name + ('-initial-order-v1' if name == 'ipv6-repeated-ptr' else '-ptr-initial-order-v1')
        spec = source_bound_spec(contract)
        if name == 'ipv6-repeated-ptr':
            for row in case['observations']:
                if row['type'] == 12:
                    row['name'] = spec['name']
                    row['label'] = row['label'].replace('-ptr-', '-v6-ptr-').replace('192.0.2.1', '2001:db8::1')
                    row['semantics']['questions'][0][0] = spec['name']
                    for rr in row['semantics']['records']:
                        rr['name'] = spec['name']
                        rr['data'] = rr['data'].replace('.test', '6.test')
        if name == 'leases-dhcp':
            after = [copy.deepcopy(row) for row in case['observations'] if row['transport'] == 'udp' and row['type'] == 12]
            for row in after:
                row['label'] = row['label'].replace('udp-', 'after-dhcp-')
            case['observations'] += after
            case['dhcp'] = {'request_wire': 'fixed-dhcp-request', 'decoded': {'message_type': 5}}
        records = next(row['semantics']['records'] for row in case['observations'] if row['type'] == 12)
        entry = copy.deepcopy(self.entry)
        entry.update(contract_id=contract, reference_document_sha256=digest(reference),
            reference_case_sha256=digest(case), fixture_input_sha256=digest(fixture_input(case)),
            states=spec['states'], target_labels=spec['target_labels'], reference_records=records)
        manifest = build_manifest(reference, [copy.deepcopy(reference)])
        manifest['source_bound_entries'] = [entry]
        actual = copy.deepcopy(reference)
        for row in actual['cases'][0]['observations']:
            if row['type'] == 12:
                row['semantics']['records'].reverse()
        return reference, actual, manifest

    def test_three_cases_reject_unknown_case_same_input(self):
        for name in ('six-hostsdir-initial', 'leases-dhcp', 'ipv6-repeated-ptr'):
            with self.subTest(case=name):
                reference, actual, manifest = self.exact_case(name)
                self.assertTrue(check(reference, actual, manifest)['passed'])
                actual['cases'][0]['case'] = 'five-line-stateful-ptr'
                self.assertFalse(check(reference, actual, manifest)['passed'])

    def test_three_cases_reject_phase_splice_and_same_state_flip(self):
        for name in ('six-hostsdir-initial', 'leases-dhcp', 'ipv6-repeated-ptr'):
            for mode in ('phase', 'repeat'):
                with self.subTest(case=name, mode=mode):
                    reference, actual, manifest = self.exact_case(name)
                    for row in actual['cases'][0]['observations']:
                        if row['type'] == 12 and (('-after-' in row['label']) if mode == 'phase' else row['label'].endswith('-1')):
                            row['semantics']['records'].reverse()
                    self.assertFalse(check(reference, actual, manifest)['passed'])

    def test_dhcp_request_and_after_dhcp_track_are_bound(self):
        reference, actual, manifest = self.exact_case('leases-dhcp')
        actual['cases'][0]['dhcp']['request_wire'] = 'different-dhcp-name'
        self.assertFalse(check(reference, actual, manifest)['passed'])
        reference, actual, manifest = self.exact_case('leases-dhcp')
        for row in actual['cases'][0]['observations']:
            if row['label'].startswith('after-dhcp-'):
                row['semantics']['records'].reverse()
        self.assertFalse(check(reference, actual, manifest)['passed'])


if __name__ == '__main__':
    unittest.main()
