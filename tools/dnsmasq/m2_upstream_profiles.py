#!/usr/bin/env python3
"""Run upstream profiles with the same exact-image DNS fixture and checks.

This compatibility entry point delegates to m2_dns_diff so strict-order and
all-servers select their actual configuration, not SoakProduct's fixed policy.
"""
from m2_dns_diff import main


if __name__ == '__main__':
    raise SystemExit(main())
