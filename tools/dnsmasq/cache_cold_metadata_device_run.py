#!/usr/bin/env python3
"""One fixed F/cache-cold-metadata group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-cache-cold-metadata'
    runner.ARTIFACT_ROLES = {'e', 'f', 'cache-cold-metadata'}
    runner.EXPERIMENT_ROLE = 'cache-cold-metadata'
    runner.GROUPS = (('f-vs-cache-cold-metadata', ('f', None), ('cache-cold-metadata', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
