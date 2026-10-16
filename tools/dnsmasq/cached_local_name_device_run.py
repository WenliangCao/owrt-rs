#!/usr/bin/env python3
"""One fixed accepted-E/cached-local-name group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-cached-local-name'
    runner.ARTIFACT_ROLES = {'e', 'f', 'cached-local-name'}
    runner.EXPERIMENT_ROLE = 'cached-local-name'
    runner.GROUPS = (('e-vs-cached-local-name', ('e', None), ('cached-local-name', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
