#!/usr/bin/env python3
"""One fixed F/local-cache-integration group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-local-cache-integration'
    runner.ARTIFACT_ROLES = {'e', 'f', 'local-cache-integration'}
    runner.EXPERIMENT_ROLE = 'local-cache-integration'
    runner.GROUPS = (('f-vs-local-cache-integration', ('f', None), ('local-cache-integration', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
