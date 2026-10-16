#!/usr/bin/env python3
"""One fixed G/5c owner-ready-frames UDP-hit group; not full qualification."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-owner-ready-frames'
    runner.ARTIFACT_ROLES = {'e', 'f', 'g', 'owner-ready-frames'}
    runner.EXPERIMENT_ROLE = 'owner-ready-frames'
    runner.GROUPS = (('g-vs-owner-ready-frames', ('g', None), ('owner-ready-frames', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
