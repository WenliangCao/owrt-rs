#!/usr/bin/env python3
"""One fixed G/bare1df inline-address UDP-hit group; not full qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-inline-address-details'
    runner.ARTIFACT_ROLES = {'e', 'f', 'g', 'inline-address-details'}
    runner.EXPERIMENT_ROLE = 'inline-address-details'
    runner.GROUPS = (('g-vs-inline-address-details', ('g', None), ('inline-address-details', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
