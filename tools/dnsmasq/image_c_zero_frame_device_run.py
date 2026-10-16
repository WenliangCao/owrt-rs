#!/usr/bin/env python3
"""One fixed exact-image-C/185 UDP-hit group; direct diagnostic only."""
import udp_stage_device_run as runner


def configure():
    runner.PREFIX = 'a53-image-c-zero-frame'
    runner.ARTIFACT_ROLES = {'exact-c', 'e', 'f', 'cached-zero-frame'}
    runner.EXPERIMENT_ROLE = 'cached-zero-frame'
    runner.GROUPS = (('exact-c-vs-cached-zero-frame', ('exact-c', None), ('cached-zero-frame', None)),)


if __name__ == '__main__':
    configure()
    runner.main()
