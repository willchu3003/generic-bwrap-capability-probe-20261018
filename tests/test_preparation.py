"""Pure/local temporary-file tests. No root, port, UID change or filter load."""
import ast
import copy
import ctypes
import importlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from common import identity_ok, remove_contents_fd, usage_fd, supervisor_identity_ok
from linux_filter import Compare
from policy import (DispatchLedger, accepts_result, clone_permitted, CLONE_THREAD,
                    CLONE_PARENT, NAMESPACE_FLAGS, DENY_EPERM, POLICY_SHA256)

ROOT = Path(__file__).resolve().parents[1]


class DispatchTests(unittest.TestCase):
    def test_exact_once_per_boot_and_wrong_boot_does_not_consume(self):
        ledger = DispatchLedger("run", "boot")
        self.assertFalse(ledger.accept({"run_id": "run", "boot_id": "other"}))
        self.assertFalse(ledger.accept({"run_id": "run", "boot_id": "boot", "command": "anything"}))
        self.assertTrue(ledger.accept({"run_id": "run", "boot_id": "boot"}))
        self.assertFalse(ledger.accept({"run_id": "run", "boot_id": "boot"}))

    def test_new_boot_rejects_old_request_without_claiming_external_once(self):
        ledger = DispatchLedger("run", "new-boot")
        self.assertFalse(ledger.accept({"run_id": "run", "boot_id": "old-boot"}))
        self.assertTrue(ledger.accept({"run_id": "run", "boot_id": "new-boot"}))


class IsolationContractTests(unittest.TestCase):
    def test_supervisor_exact_caps_nnp_and_root_ids(self):
        data = {"Uid": "0 0 0 0", "Gid": "0 0 0 0", "NoNewPrivs": "1",
                "CapEff": "e0", "CapPrm": "e0", "CapInh": "0", "CapAmb": "0"}
        self.assertTrue(supervisor_identity_ok(data))
        for key, bad in (("CapEff", "e1"), ("CapPrm", "ff"), ("CapAmb", "20"),
                         ("CapInh", "40"), ("NoNewPrivs", "0"), ("Uid", "0 0 10001 0")):
            self.assertFalse(supervisor_identity_ok({**data, key: bad}))

    def test_identity_checks_all_ids_caps_groups_and_nnp(self):
        data = {"Uid": "10011 10011 10011 10011", "Gid": "10011 10011 10011 10011",
                "Groups": "", "NoNewPrivs": "1", "CapEff": "0", "CapPrm": "0",
                "CapInh": "0", "CapAmb": "0", "CapBnd": "ffffffffffffffff"}
        self.assertTrue(identity_ok(data, 10011, (10011,)))
        for key, bad in (("Uid", "10011 10011 0 10011"), ("Gid", "10011 0 10011 10011"),
                         ("Groups", "10012"), ("NoNewPrivs", "0"),
                         ("CapEff", "20"), ("CapPrm", "40"), ("CapInh", "80"), ("CapAmb", "1")):
            changed = copy.deepcopy(data)
            changed[key] = bad
            with self.subTest(key=key):
                self.assertFalse(identity_ok(changed, 10011, (10011,)))

    def test_generation_is_strict_and_complete(self):
        self.assertTrue(accepts_result(1, 1, True))
        for generation, complete in ((0, True), (1, False), (True, True), ("1", True), (1, 1)):
            self.assertFalse(accepts_result(1, generation, complete))

    def test_thread_allowed_process_and_namespace_clones_denied(self):
        self.assertTrue(clone_permitted(CLONE_THREAD | 0x100 | 0x800))
        self.assertFalse(clone_permitted(0))
        self.assertFalse(clone_permitted(0x100))
        for flag in (CLONE_PARENT, *NAMESPACE_FLAGS):
            self.assertFalse(clone_permitted(CLONE_THREAD | flag))

    def test_policy_covers_network_scm_and_io_uring(self):
        self.assertTrue({"socket", "socketpair", "connect", "sendto", "sendmsg", "sendmmsg",
                         "recvmsg", "recvmmsg", "io_uring_setup", "io_uring_enter", "io_uring_register",
                         "fork", "vfork", "setsid", "setpgid", "ptrace", "process_vm_readv",
                         "process_vm_writev"} <= set(DENY_EPERM))
        self.assertEqual(len(POLICY_SHA256), 64)
        self.assertEqual(ctypes.sizeof(Compare), 24)
        self.assertEqual(Compare.datum_a.offset, 8)


class CleanupTests(unittest.TestCase):
    def test_unreadable_role_tree_is_quarantined_without_dac_fallback(self):
        import role
        with tempfile.TemporaryDirectory(prefix="generic-probe-quarantine-") as temp:
            root = Path(temp)
            (root / "trusted").mkdir()
            paths = []
            for lane in ("inputs", "scratch"):
                for name in "PVR":
                    path = root / lane / name
                    path.mkdir(parents=True)
                    paths.append(path)
            (paths[0] / "retained").write_text("synthetic")
            original_usage = usage_fd
            first = True

            def denied_once(fd):
                nonlocal first
                if first:
                    first = False
                    raise PermissionError(13, "synthetic denied traversal")
                return original_usage(fd)

            try:
                with patch.object(role, "WORK", root), patch.object(role, "identities"), \
                        patch.object(role, "usage_fd", side_effect=denied_once), \
                        patch.object(role, "RESULT", {"checks": []}):
                    role.cleanup()
                    self.assertEqual(len(role.RESULT["quarantines"]), 1)
                    self.assertFalse(role.RESULT["work_measurement_complete"])
                    self.assertEqual(paths[0].stat().st_mode & 0o777, 0)
                    self.assertFalse(role.RESULT["checks"][-1]["pass"])
            finally:
                paths[0].chmod(0o700)
            self.assertEqual((paths[0] / "retained").read_text(), "synthetic")

    def test_cleanup_never_follows_symlink_outside_open_directory(self):
        with tempfile.TemporaryDirectory(prefix="generic-probe-unit-") as temp:
            root = Path(temp)
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "keep"
            sentinel.write_text("keep")
            lane = root / "lane"
            lane.mkdir()
            (lane / "nested").mkdir()
            (lane / "nested" / "data").write_bytes(b"123")
            (lane / "link").symlink_to(outside, target_is_directory=True)
            fd = os.open(lane, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                size, files = usage_fd(fd)
                self.assertEqual(files, 2)
                self.assertGreaterEqual(size, 3)
                remove_contents_fd(fd)
                self.assertEqual(os.listdir(fd), [])
            finally:
                os.close(fd)
            self.assertEqual(sentinel.read_text(), "keep")


class PackagingContractTests(unittest.TestCase):
    def test_imports_have_no_execution_side_effects(self):
        for name in ("entry", "supervisor", "service_run", "service_finish", "role", "http_transport", "build_layout"):
            importlib.import_module(name)  # must not bind/load/drop/chown/signal on import

    def test_profile_and_docker_pins_and_no_runtime_chown(self):
        profile = json.loads((ROOT / "profile.json").read_text())
        self.assertEqual(profile["roles"], {"T": 10001, "P": 10011, "V": 10012, "R": 10013})
        self.assertFalse(profile["supervisor"]["runtime_chown"])
        self.assertEqual(set(profile["supervisor"]["capabilities"]), {"KILL", "SETGID", "SETUID"})
        docker = (ROOT / "Dockerfile").read_text()
        self.assertIn(profile["base_image"], docker)
        for package, version in profile["packages"].items():
            self.assertIn(package + "=" + version, docker)
        for path in ROOT.glob("*.py"):
            ast.parse(path.read_text(), filename=path.name)
            if path.name != "build_layout.py":
                self.assertNotIn("os.chown(", path.read_text())

    def test_generic_source_has_no_product_path_or_private_material(self):
        forbidden = ("/Users/", "customer_order", "BEGIN PRIVATE KEY",
                     "AKIA", "ghp_")
        # This test itself lists forbidden tokens, so inspect runtime files only.
        for path in [*ROOT.glob("*.py"), ROOT / "profile.json", ROOT / "Dockerfile"]:
            text = path.read_text()
            for token in forbidden:
                self.assertNotIn(token, text, (path.name, token))


if __name__ == "__main__":
    unittest.main()
