#!/usr/bin/env python3
"""Regression for the RR-filter fixture's UDP/TCP listener port selection."""
import socket
import unittest
from unittest.mock import patch

import m5_rr_filter


class ListenerPortTests(unittest.TestCase):
    def test_udp_free_port_with_tcp_owner_is_not_selected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner:
            owner.bind((m5_rr_filter.LISTEN_HOST, 0))
            owner.listen()
            occupied = owner.getsockname()[1]

            # Reproduce the old precondition: UDP bind succeeds even though
            # the daemon's TCP bind at that same port must fail.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind((m5_rr_filter.LISTEN_HOST, occupied))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                with self.assertRaises(OSError):
                    tcp.bind((m5_rr_filter.LISTEN_HOST, occupied))

            class FixtureSocket(socket.socket):
                def bind(self, address):
                    # Force a UDP-only port=0 selector to hit this concrete
                    # collision; no process-seeded chance is needed to fail.
                    if self.type == socket.SOCK_DGRAM and address[1] == 0:
                        address = (address[0], occupied)
                    return super().bind(address)

            with patch.object(m5_rr_filter.socket, "socket", FixtureSocket):
                selected = m5_rr_filter.free_dns_port()
            self.assertNotEqual(selected, occupied)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                tcp.bind((m5_rr_filter.LISTEN_HOST, selected))
                udp.bind((m5_rr_filter.LISTEN_HOST, selected))


if __name__ == "__main__":
    unittest.main()
