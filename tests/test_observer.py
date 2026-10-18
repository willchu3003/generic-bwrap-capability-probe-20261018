import ast
import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import observer as m


def phase(name, p="e0", pid=7):
    return {"stage": name, "pid": pid, "required_permitted_bits": m.required_bits(p)}


class LocalOnly(unittest.TestCase):
    def test_whitelist_preserves_full_uid_gid_and_raw_caps(self):
        source = "Uid:\t0 0 0 0\nGid:\t1 2 3 4\nGroups:\t5\nCapPrm:\t0000000000000060\nNoNewPrivs:\t1\nUnrelated:\texclude\n"
        result = m.parse_status(source)
        self.assertEqual(result["Gid"], "1 2 3 4")
        self.assertNotIn("Unrelated", result)
        self.assertEqual(result["CapPrm"], "0000000000000060")
        self.assertEqual(m.required_bits(result["CapPrm"]), {"CAP_KILL": True, "CAP_SETGID": True, "CAP_SETUID": False})

    def test_nnp_only_requested_as_one_or_not_requested(self):
        call = Mock(return_value={"value": 0, "errno": 0})
        self.assertFalse(m.restrict_nnp("1", call)["state_change_requested"])
        call.assert_not_called()
        self.assertTrue(m.restrict_nnp("0", call)["state_change_requested"])
        call.assert_called_once_with(38, 1)
        call.reset_mock()
        self.assertFalse(m.restrict_nnp(None, call)["state_change_requested"])
        call.assert_not_called()

    def test_stage_labels_do_not_claim_old_chain_or_causation(self):
        names = ["docker_entry_observer", "after_nnp_before_exec", "after_ordinary_exec"]
        all_present = [phase(name) for name in names]
        self.assertEqual(m.derive(all_present), "REQUIRED_P_BITS_PRESENT_AT_ALL_THREE_SNAPSHOTS")
        for index, expected in enumerate(("REQUIRED_P_BITS_MISSING_AT_FIRST_OBSERVER_ENTRY",
                "REQUIRED_P_BITS_MISSING_AT_SECOND_SNAPSHOT", "REQUIRED_P_BITS_MISSING_AFTER_ORDINARY_EXEC")):
            altered = copy.deepcopy(all_present)
            altered[index] = phase(names[index], "60")
            self.assertEqual(m.derive(altered), expected)
        self.assertEqual(m.derive(all_present[:2]), "INCONCLUSIVE_MISSING_PHASE")
        all_present[2]["pid"] = 8
        self.assertEqual(m.derive(all_present), "INCONCLUSIVE_PID_CHANGED")

    def test_owned_marker_roundtrip_and_first_start_no_replay(self):
        with tempfile.TemporaryDirectory(prefix="generic-observer-unit-", dir="/tmp") as temp:
            path = Path(temp) / "state.json"
            with patch.object(m, "STATE", path):
                m.write_state({"pid": 7, "phase": "reserved"}, first=True)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(m.load_state()["pid"], 7)
                with self.assertRaises(FileExistsError):
                    m.write_state({}, first=True)
                m.write_state({"pid": 7, "phase": "exec_pending"})
                self.assertEqual(m.load_state()["phase"], "exec_pending")
                path.unlink()
                sentinel = Path(temp) / "sentinel"
                sentinel.write_text("unchanged")
                path.symlink_to(sentinel)
                with self.assertRaises(OSError):
                    m.load_state()
                self.assertEqual(sentinel.read_text(), "unchanged")

    def test_transition_reports_lost_gained_and_unknown_securebits(self):
        before = {"status": {k: "e0" for k in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")},
                  "pr_get_securebits": {"value": 0, "errno": 0}}
        after = copy.deepcopy(before)
        after["status"]["CapPrm"] = "60"
        after["status"]["CapEff"] = "e1"
        change = m.transition(before, after)
        self.assertEqual(change["cap_deltas"]["CapPrm"], {"lost_hex": "0x80", "gained_hex": "0x0"})
        self.assertEqual(change["cap_deltas"]["CapEff"], {"lost_hex": "0x0", "gained_hex": "0x1"})
        self.assertFalse(change["securebits_changed_if_readable"])
        after["pr_get_securebits"] = {"value": -1, "errno": 1}
        self.assertIsNone(m.transition(before, after)["securebits_changed_if_readable"])

    def test_result_bound_and_no_privilege_writer_interfaces(self):
        with self.assertRaises(ValueError):
            m.encode({"large": "x" * 16385})
        source = Path(m.__file__).read_text()
        tree = ast.parse(source)
        forbidden = {"setuid", "setgid", "setresuid", "setresgid", "setgroups", "chown", "capset", "system", "popen"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)
        self.assertEqual((m.PR_GET_SECUREBITS, m.PR_SET_NO_NEW_PRIVS, m.PR_GET_NO_NEW_PRIVS), (27, 38, 39))
        self.assertNotIn("PR_SET_SECUREBITS", source)
        self.assertNotIn("PR_SET_KEEPCAPS", source)


if __name__ == "__main__":
    unittest.main()
