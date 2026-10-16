#!/usr/bin/env python3
"""One fixed G/c95 per-method hot-section UDP group; not full qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-hot-text-group'
    runner.ARTIFACT_ROLES = {'e', 'f', 'g', 'hot-text-group'}
    runner.EXPERIMENT_ROLE = 'hot-text-group'
    runner.GROUPS = (('g-vs-hot-text-group', ('g', None), ('hot-text-group', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
