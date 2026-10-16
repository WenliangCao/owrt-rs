#!/usr/bin/env python3
"""One fixed G/803 opt-level2 UDP-hit group; not full qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-opt2-codegen'
    runner.ARTIFACT_ROLES = {'e', 'f', 'g', 'opt2-codegen'}
    runner.EXPERIMENT_ROLE = 'opt2-codegen'
    runner.GROUPS = (('g-vs-opt2-codegen', ('g', None), ('opt2-codegen', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
