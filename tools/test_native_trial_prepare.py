#!/usr/bin/env python3
"""Host-independent negative controls for private deployment archives."""
import tarfile
import unittest

from native_trial_prepare import validate_members


def member(name, kind=tarfile.REGTYPE, target=""):
    entry = tarfile.TarInfo(name)
    entry.type, entry.linkname = kind, target
    return entry


class BackupPaths(unittest.TestCase):
    reserved = ["root/owrt-native-trial", "etc/init.d/owrt-native-trial",
                "etc/rc.d/S01owrt-native-trial", "root/owrt-v0.2.1-rollback-receipt"]

    def reject(self, entries):
        with self.assertRaises(AssertionError):
            validate_members(entries, self.reserved)

    def test_regular_config_and_unrelated_symlink(self):
        validate_members([member("etc/config/network"),
                          member("etc/localtime", tarfile.SYMTYPE, "/tmp/localtime")], self.reserved)

    def test_reserved_directory_and_descendant(self):
        self.reject([member("root/owrt-native-trial", tarfile.DIRTYPE)])
        self.reject([member("root/owrt-native-trial/armed")])

    def test_payload_ancestor_symlink(self):
        self.reject([member("root", tarfile.SYMTYPE, "/etc")])
        self.reject([member("etc/init.d", tarfile.SYMTYPE, "/tmp")])

    def test_original_member_ancestor_symlink(self):
        self.reject([member("etc/config", tarfile.SYMTYPE, "/tmp"), member("etc/config/network")])

    def test_hardlink_and_device_rejected(self):
        self.reject([member("etc/config/a", tarfile.LNKTYPE, "../../root/a")])
        self.reject([member("dev/unsafe", tarfile.CHRTYPE)])

    def test_duplicate_and_traversal(self):
        self.reject([member("etc/config/a"), member("/etc/config/a")])
        self.reject([member("etc/../root/a")])
        self.reject([member("etc/./config/a")])

    def test_member_list_injection(self):
        self.reject([member("etc/config/a\nroot/other")])
        self.reject([member("--checkpoint-action=exec=sh")])

    def test_old_layered_flag_rejected(self):
        self.reject([member("etc/owrt-dnsmasq.boot-enable")])

    def test_backup_cannot_override_candidate_integration(self):
        with self.assertRaises(AssertionError):
            validate_members([member("etc/init.d/dnsmasq")], ["etc/init.d/dnsmasq"])


if __name__ == "__main__":
    unittest.main()
