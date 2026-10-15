#!/usr/bin/env python3
"""One fixed F/host-miss-index group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-host-miss-index'
    runner.ARTIFACT_ROLES = {'e', 'f', 'host-miss-index'}
    runner.EXPERIMENT_ROLE = 'host-miss-index'
    runner.GROUPS = (('f-vs-host-miss-index', ('f', None), ('host-miss-index', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
