#!/usr/bin/env python3
"""One fixed F/fresh-address-frame group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-fresh-address-frame'
    runner.ARTIFACT_ROLES = {'e', 'f', 'fresh-address-frame'}
    runner.EXPERIMENT_ROLE = 'fresh-address-frame'
    runner.GROUPS = (('f-vs-fresh-address-frame', ('f', None), ('fresh-address-frame', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
