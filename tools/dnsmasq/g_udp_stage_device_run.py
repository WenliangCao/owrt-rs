#!/usr/bin/env python3
"""Original fifty-window cumulative UDP cuts on accepted G; diagnostic only."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-g-stage'
    runner.ARTIFACT_ROLES = {'exact-c', 'e', 'f', 'g', 'stage'}
    runner.EXPERIMENT_ROLE = 'stage'
    runner.GROUPS = (
        ('exact-c-vs-g', ('exact-c', None), ('g', None)),
        ('g-vs-stage-full', ('g', None), ('stage', 'full')),
        ('stage-full-vs-receive', ('stage', 'full'), ('stage', 'receive')),
        ('stage-full-vs-before-answer', ('stage', 'full'), ('stage', 'before-answer')),
        ('stage-full-vs-skip-local', ('stage', 'full'), ('stage', 'skip-local')),
    )


if __name__ == '__main__':
    configure()
    runner.main()
