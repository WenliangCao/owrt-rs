#!/usr/bin/env python3
"""Pure parsers and mocked identity checks; never accesses a network device."""
import datetime as dt
import json
import unittest
from unittest.mock import patch

import odhcpd_client_health as health


class Parsers(unittest.TestCase):
    def test_realistic_mac_addresses_exclude_unusable(self):
        rows = health.parse_addresses("""en0: flags=8863<UP,RUNNING>
 inet6 fe80::1%en0 prefixlen 64 secured scopeid 0xc
 inet6 2001:db8:1::2 prefixlen 64 autoconf temporary
 inet6 fd12:34::2 prefixlen 64 autoconf secured
 inet6 2001:db8:1::3 prefixlen 64 dynamic deprecated
 inet6 2001:db8:1::4 prefixlen 64 tentative
""")
        self.assertEqual([row["address"] for row in rows if row["usable"]], ["2001:db8:1::2", "fd12:34::2"])

    def test_scoped_default_does_not_accept_vpn_default(self):
        text = "default fe80::1%en0 UGcg en0\ndefault fe80::%utun3 UGcIg utun3\n"
        self.assertEqual(health.parse_defaults(text, "en0"), [{"gateway": "fe80::1", "flags": "UGcg", "interface": "en0"}])
        self.assertFalse(health.parse_defaults(text, "en4"))

    def test_local_proxy_is_recorded_not_rejected(self):
        dns = health.parse_dns("""DNS configuration
resolver #1
 nameserver[0] : 127.0.0.1
DNS configuration (for scoped queries)
resolver #1
 nameserver[0] : 127.0.0.1
 if_index : 12 (en0)
""")
        self.assertEqual(dns, [{"servers": ["127.0.0.1"], "interface": None, "local_proxy": True},
                               {"servers": ["127.0.0.1"], "interface": "en0", "local_proxy": True}])

    def test_ra_timezone_and_expired_rdnss(self):
        text = """RA Received 10/18/2026 10:10:40 from fe80::1, length 152, hop limit 64, lifetime 1800s, reachable 0ms
 rdnss option (25), length 24 (3): lifetime 5400s, addr: fd12:3456::1
 rdnss option (25), length 24 (3): lifetime 0s, addr: fd12:dead::1
"""
        ra = health.parse_ra(text, "Europe/Berlin")
        self.assertEqual(ra["received_utc"], "2026-10-18T08:10:40+00:00")
        self.assertEqual(ra["router_lifetime"], 1800)
        self.assertEqual(ra["rdnss"], ["fd12:3456::1"])
        self.assertGreater(ra["received_epoch"], health.parse_activation("2026-10-18T08:10:39Z"))
        self.assertEqual(ra["received_epoch"], health.parse_activation("2026-10-18T10:10:40+02:00"))
        with self.assertRaises(RuntimeError):
            health.parse_activation("2026-10-18T10:10:40")
        with self.assertRaises(RuntimeError):
            health.parse_ra("No RA received", "Europe/Berlin")

    def test_process_stat_uses_final_parenthesis(self):
        line = "42 (odd ) process) " + " ".join(["S", "1"] + ["0"] * 17 + ["321", "0"])
        self.assertEqual(health.parse_stat(line), {"parent_pid": 1, "start_ticks": 321})


class Identity(unittest.TestCase):
    def fixture(self, fault=None):
        calls = 0
        instance = {"running": True, "pid": 42, "command": ["/usr/sbin/odhcpd"]}
        def stat(start):
            return "42 (odhcpd) " + " ".join(["S", "1"] + ["0"] * 17 + [str(start)])
        def remote(host, command, **kwargs):
            nonlocal calls
            self.assertEqual(host, "fixture")
            self.assertNotIn("restart", command)
            self.assertNotIn("kill", command)
            if "call service list" in command:
                calls += 1
                value = {**instance}
                if fault == "supervisor_changed" and calls == 2:
                    value["pid"] = 43
                return json.dumps({"odhcpd": {"instances": {"cfg": value}}})
            if "cat /proc/42/stat" in command:
                digest = "b" * 64 if fault == "wrong_elf" else health.SDK_SHA
                return "\n".join([stat(321), digest + "  /proc/42/exe", stat(322 if fault == "reused_pid" else 321), digest + "  /proc/42/exe"])
            if "dhcp ipv6ra" in command:
                return '{"interfaces":{"br-lan":[{"prefix":"fd12::1","length":60,"stale":false}]}}'
            if "dhcp ipv6leases" in command:
                return '{"device":{"br-lan":{"leases":[]}}}'
            self.fail("unexpected command: " + command)
        return remote

    def test_supervised_exact_candidate(self):
        with patch.object(health.base, "ssh", side_effect=self.fixture()):
            result = health.production_identity("fixture", health.SDK_SHA)
        self.assertEqual(result["pid"], 42)
        self.assertEqual(result["start_ticks"], 321)

    def test_pid_or_elf_change_fails(self):
        for fault in ("supervisor_changed", "wrong_elf", "reused_pid"):
            with self.subTest(fault=fault), patch.object(health.base, "ssh", side_effect=self.fixture(fault)), self.assertRaises(RuntimeError):
                health.production_identity("fixture", health.SDK_SHA)


if __name__ == "__main__":
    unittest.main()
