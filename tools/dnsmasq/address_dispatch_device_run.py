#!/usr/bin/env python3
"""One fixed F/address-dispatch UDP-hit group; exploratory, not qualification."""
import udp_stage_device_run as runner


def configure():
    # Static identities/order only. Use the reviewed stage runner's unchanged
    # workload, guard, output gates, statistics, archive retention and recovery.
    runner.PREFIX = 'a53-address-dispatch'
    runner.ARTIFACT_ROLES = {'e', 'f', 'address-dispatch'}
    runner.EXPERIMENT_ROLE = 'address-dispatch'
    runner.GROUPS = (('f-vs-address-dispatch', ('f', None), ('address-dispatch', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
