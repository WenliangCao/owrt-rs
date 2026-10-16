#!/usr/bin/env python3
"""One fixed G/9e cached-hit UDP group; not full qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-cached-hit-9e'
    runner.ARTIFACT_ROLES = {'e', 'f', 'g', 'cached-hit-9e'}
    runner.EXPERIMENT_ROLE = 'cached-hit-9e'
    runner.GROUPS = (('g-vs-cached-hit-9e', ('g', None), ('cached-hit-9e', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
