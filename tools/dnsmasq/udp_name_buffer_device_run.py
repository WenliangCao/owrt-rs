#!/usr/bin/env python3
"""One fixed F/UDP-name-buffer group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    # Static identities/order only; all execution and evidence gates are shared.
    runner.PREFIX = 'a53-udp-name-buffer'
    runner.ARTIFACT_ROLES = {'e', 'f', 'udp-name-buffer'}
    runner.EXPERIMENT_ROLE = 'udp-name-buffer'
    runner.GROUPS = (('f-vs-udp-name-buffer', ('f', None), ('udp-name-buffer', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
