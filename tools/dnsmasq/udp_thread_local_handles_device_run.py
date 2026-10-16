#!/usr/bin/env python3
"""One fixed G/6ab thread-local UDP handles group; not full qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-udp-thread-local-handles'
    runner.ARTIFACT_ROLES = {'e', 'f', 'g', 'udp-thread-local-handles'}
    runner.EXPERIMENT_ROLE = 'udp-thread-local-handles'
    runner.GROUPS = (('g-vs-udp-thread-local-handles', ('g', None), ('udp-thread-local-handles', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
