#!/usr/bin/env python3
"""One fixed F/fresh-address group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-fresh-address'
    runner.ARTIFACT_ROLES = {'e', 'f', 'fresh-address'}
    runner.EXPERIMENT_ROLE = 'fresh-address'
    runner.GROUPS = (('f-vs-fresh-address', ('f', None), ('fresh-address', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
