#!/usr/bin/env python3
"""One fixed accepted-E/cached-zero-frame group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-cached-zero-frame'
    runner.ARTIFACT_ROLES = {'e', 'f', 'cached-zero-frame'}
    runner.EXPERIMENT_ROLE = 'cached-zero-frame'
    runner.GROUPS = (('e-vs-cached-zero-frame', ('e', None), ('cached-zero-frame', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
