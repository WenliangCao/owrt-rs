"""Frozen reverse child/parent transfer primitive matrix, separate from 307."""

X = 'c0000201'
Y = 'c0000202'
Z = 'c0000203'
V6 = '20010db8000000000000000000000001'


def cases():
    rows = []
    def add(label, child, after, *, pre=(), between=(), now=103, capacity=8, config='', ordering=False):
        rows.append(dict(label=label, child=list(child), after=list(after), pre=list(pre),
                         between=list(between), now=now, capacity=capacity, config=config, ordering=ordering))
    def tx(*records): return ['B', *records, 'C']
    old = tx(f'V Old.test 4 {X} 60 100')
    add('replace-v4-preserves-forward', tx(f'V New.test 4 {X} 60 100') + ['T'],
        ['T', f'A 4 {X} 103', 'Q New.test 4 103', 'Q Old.test 4 103'],
        pre=old + tx(f'I New.test 4 {Y} 60 100', f'I Old.test 4 {Z} 60 100'),
        between=tx(f'V Parent.test 4 {X} 60 101'))
    add('replace-v6', tx(f'V New6.test 6 {V6} 60 100'), ['T', f'A 6 {V6} 103', 'Q New6.test 6 103'],
        pre=tx(f'V Old6.test 6 {V6} 60 100', f'I New6.test 6 {V6} 60 100'))
    add('same-target-different-address', tx(f'V Same.test 4 {Y} 60 100'),
        ['T', f'A 4 {X} 103', f'A 4 {Y} 103'], pre=tx(f'V Same.test 4 {X} 60 100'))
    add('parent-local-reverse-coexist', tx(f'V Dynamic.test 4 {X} 60 100'),
        ['T', f'A 4 {X} 103', 'Q Local.test 4 103', 'Q Dynamic.test 4 103'],
        between=[f'H Local.test 4 {X} 200'])
    add('parent-same-target-local-forward', tx(f'V Local.test 4 {X} 60 100'),
        ['T', f'A 4 {X} 103', 'Q Local.test 4 103'], between=[f'H Local.test 4 {Y} 200'])
    add('parent-configured-cname-target', tx(f'V Alias.test 4 {X} 60 100'),
        ['T', f'A 4 {X} 103'], config='host-record=Local.test,192.0.2.2\ncname=Alias.test,Local.test\n')
    add('parent-mixed-shared-pressure', tx(f'V New.test 4 {X} 60 100'),
        ['T', 'Q First.test 4 103', f'A 4 {Y} 103', 'Q Last.test 4 103', f'A 4 {X} 103'], capacity=3,
        between=tx(f'I First.test 4 {X} 60 101') + tx(f'V Middle.test 4 {Y} 60 101') + tx(f'I Last.test 4 {Z} 60 101'))
    add('reverse-victim-removes-rrset', tx(f'I New.test 4 {Z} 60 100'),
        ['T', f'A 4 {X} 103', 'Q New.test 4 103'], capacity=3,
        between=tx(f'V First.test 4 {X} 60 101', f'V Second.test 4 {X} 60 101') + tx(f'I Last.test 4 {Y} 60 101'))
    add('empty-clears-parent-pending', ['B', 'C'], ['T', f'A 4 {X} 103'], pre=old,
        between=['B', f'V Pending.test 4 {X} 60 101'])
    add('uncommitted-child-removal', ['B', f'V New.test 4 {X} 60 100', f'A 4 {X} 100'],
        ['T', f'A 4 {X} 103'], pre=old)
    add('failed-child-no-transfer', ['B', f'V New.test 4 {X} 60 100', f'V Zero.test 4 {Y} 0 100', 'C'],
        ['T', f'A 4 {X} 103'], pre=old)
    add('parent-abort-retains-removal', tx(f'V Expired.test 4 {X} 10 100', f'V Replace.test 4 {Y} 60 100'),
        ['T', f'A 4 {X} 110', f'A 4 {Y} 110', 'B', 'T'], now=110,
        pre=tx(f'V OldX.test 4 {X} 60 100', f'V OldY.test 4 {Y} 60 100'))
    for stale, now in [(None,103),(None,110),(None,111),(5,110),(5,111),(0,116)]:
        add(f'expiry-{stale}-{now}', tx(f'V Clock.test 4 {X} 10 100'), ['T', f'A 4 {X} {now}'], now=now,
            config='' if stale is None else f'use-stale-cache={stale}\n')
    add('min-ttl-not-reclamped', tx(f'V Min.test 4 {X} 1 100'), ['T', f'A 4 {X} 103'], config='min-cache-ttl=10\n')
    add('max-ttl-not-reclamped', tx(f'V Max.test 4 {X} 120 100'), ['T', f'A 4 {X} 103'], config='max-cache-ttl=20\n')
    add('multiple-ptr-export-order', tx(f'V First.test 4 {X} 60 100', f'V Second.test 4 {X} 60 100', f'V Third.test 4 {X} 60 100') + ['T', f'A 4 {X} 100', 'T'],
        ['T', f'A 4 {X} 103', 'T'], ordering=True)
    return rows
