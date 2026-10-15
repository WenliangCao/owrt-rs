#!/usr/bin/env python3
"""One fixed F/local-address-miss-stack group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-local-address-miss-stack'
    runner.ARTIFACT_ROLES = {'e', 'f', 'local-address-miss-stack'}
    runner.EXPERIMENT_ROLE = 'local-address-miss-stack'
    runner.GROUPS = (('f-vs-local-address-miss-stack', ('f', None), ('local-address-miss-stack', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
