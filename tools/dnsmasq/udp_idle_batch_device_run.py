#!/usr/bin/env python3
"""One fixed F/adaptive-UDP-idle-batch group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-udp-idle-batch'
    runner.ARTIFACT_ROLES = {'e', 'f', 'udp-idle-batch'}
    runner.EXPERIMENT_ROLE = 'udp-idle-batch'
    runner.GROUPS = (('f-vs-udp-idle-batch', ('f', None), ('udp-idle-batch', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
