"""Failure-path and streaming tests. No ARP writes or real scan packets."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import IPFixStudio as core
import win_neighbor

CARD = {"name": "test", "scapyName": "test-guid", "index": 2,
        "mac": "02:00:00:00:00:01", "ips": ["192.168.0.181"],
        "ipv4": [{"ip": "192.168.0.181", "cidr": "192.168.0.0/24"}]}
IP = "192.168.0.40"
MAC = "70:b3:d5:21:b7:ce"


class StabilityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.patches = []
        self.mock(core, "app_dir", return_value=self.directory.name)
        self.mock(core, "pin_sweep", return_value=0)
        spec = importlib.util.spec_from_file_location(
            "backend_test", Path(core.__file__).with_name("electron-backend.py"))
        self.backend = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.backend)
        self.mock(self.backend, "emit_state")
        self.device = core.STORE.upsert(IP, MAC)
        core.STORE.ifindex, core.STORE.iface = 2, CARD["scapyName"]

    def mock(self, obj, name, **kwargs):
        patcher = patch.object(obj, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def isolated(self):
        core.STORE.isolated = self.device["key"]
        self.device["status"] = "isolated"

    def test_failed_release_keeps_ui_state(self):
        self.isolated()
        self.mock(core, "arp_unpin", return_value=(False, "access denied"))
        with self.assertRaises(RuntimeError):
            self.backend.run("release", {})
        self.assertEqual(core.STORE.isolated, self.device["key"])
        self.assertEqual(self.device["status"], "isolated")

    def test_failed_release_prevents_scan_and_preserves_list(self):
        self.isolated()
        original = core.STORE
        self.mock(core, "list_ifaces", return_value=[CARD])
        self.mock(core, "arp_unpin", return_value=(False, "cannot verify"))
        sweep = self.mock(core, "arp_sweep")
        with self.assertRaises(RuntimeError):
            self.backend.run("scan", {"iface": CARD, "target": IP})
        sweep.assert_not_called()
        self.assertIs(core.STORE, original)
        self.assertEqual(core.STORE.isolated, self.device["key"])

    def test_switching_device_requires_previous_release(self):
        self.isolated()
        other = core.STORE.upsert(IP, "70:b3:d5:21:b7:cf")
        self.mock(core, "arp_unpin", return_value=(False, "denied"))
        pin = self.mock(core, "arp_pin")
        with self.assertRaises(RuntimeError):
            self.backend.run("isolate", {"key": other["key"]})
        pin.assert_not_called()
        self.assertEqual(core.STORE.isolated, self.device["key"])

    def test_failed_pin_is_visible_and_releasable(self):
        self.mock(core, "arp_pin", return_value=(False, "unknown"))
        with self.assertRaises(RuntimeError):
            self.backend.run("isolate", {"key": self.device["key"]})
        self.assertEqual(core.STORE.isolated, self.device["key"])
        self.assertEqual(self.device["status"], "isolation_unknown")
        self.mock(core, "arp_unpin", return_value=(True, ""))
        result = self.backend.run("release", {})
        self.assertIsNone(result["isolated"])

    def test_block_mutations_during_scan(self):
        self.backend.SCAN_RUNNING = True
        for action in ("interfaces", "isolate", "release"):
            with self.assertRaises(RuntimeError):
                self.backend.run(action, {"key": self.device["key"]})

    def test_lookup_failure_is_not_release_success(self):
        self.mock(core, "run_cmd", return_value=(0, "", ""))
        self.mock(core, "run_ps", return_value=(0, "", ""))
        self.mock(win_neighbor, "read_neighbor", side_effect=OSError("unavailable"))
        self.assertIsNone(core._still_pinned(IP, 2))
        self.assertFalse(core._arp_unpin_now(IP, 2, "test")[0])

    def test_pin_checks_mac_and_permanent_state(self):
        for entry, expected in [
            ({"mac": MAC, "permanent": True}, True),
            ({"mac": "70:b3:d5:21:b7:cf", "permanent": True}, False),
            ({"mac": MAC, "permanent": False}, False), (None, False),
        ]:
            with patch.object(win_neighbor, "read_neighbor", return_value=entry):
                self.assertEqual(core.verify_pin(IP, MAC, 2)[0], expected)

    def test_pin_failure_keeps_recovery_record(self):
        self.mock(core, "run_cmd", return_value=(0, "", ""))
        self.mock(win_neighbor, "read_neighbor", side_effect=OSError("unavailable"))
        self.assertFalse(core.arp_pin(IP, MAC, 2, "test")[0])
        self.assertEqual(core._pin_read()[0]["mac"], MAC)

    def test_record_write_failure_prevents_pin(self):
        self.mock(core, "_pin_write", side_effect=OSError("disk full"))
        command = self.mock(core, "run_cmd")
        with self.assertRaises(OSError):
            core.arp_pin(IP, MAC, 2, "test")
        command.assert_not_called()

    def test_replies_publish_before_chunk_finishes(self):
        self.assertTrue(core.ensure_scapy())
        calls = []
        mac2 = "70:b3:d5:21:b7:cf"
        def fake_srp(packet, **options):
            self.assertTrue(options["multi"])
            self.assertEqual(options["retry"], 1)
            options["stop_filter"](core.Ether()/core.ARP(op=2, psrc=IP, hwsrc=MAC))
            self.assertTrue(calls, "first reply must be published before srp returns")
            options["stop_filter"](core.Ether()/core.ARP(op=2, psrc=IP, hwsrc=mac2))
            return [], []
        self.mock(core, "srp", side_effect=fake_srp)
        result, swept = core.arp_sweep(IP, "test", on_found=calls.append)
        self.assertEqual(set(result[IP]), {MAC, mac2})
        self.assertEqual(swept, [IP])
        self.assertEqual(set(m for batch in calls for m in batch[IP]), {MAC, mac2})

    def test_scan_rechecks_silent_and_responding_ips(self):
        fresh = dict(CARD, index=19)
        self.mock(core, "list_ifaces", return_value=[fresh])
        passes = []
        def fake_sweep(target, iface, **options):
            passes.append((target, core.STORE.ifindex))
            if len(passes) == 1:
                return {IP: [MAC]}, [IP, "192.168.0.41"]
            if len(passes) == 2:
                return {}, ["192.168.0.41"]
            return {IP: ["70:b3:d5:21:b7:cf"]}, [IP]
        self.mock(core, "arp_sweep", side_effect=fake_sweep)
        result = self.backend.run("scan", {"iface": CARD, "target": "192.168.0.40-41"})
        self.assertEqual(result["summary"]["conflictIps"], 1)
        self.assertTrue(all(index == 19 for _, index in passes))
        self.assertEqual(len(passes), 3)
        self.assertEqual(passes[1][0], "192.168.0.41")
        self.assertEqual(passes[2][0], IP)

    def test_own_ip_conflict_is_not_hidden(self):
        self.mock(core, "list_ifaces", return_value=[CARD])
        self.mock(core, "arp_sweep", return_value=({"192.168.0.181": [MAC]}, ["192.168.0.181"]))
        result = self.backend.run("scan", {"iface": CARD, "target": "192.168.0.181"})
        self.assertEqual(result["summary"]["conflictIps"], 1)
        self.assertEqual(result["summary"]["devices"], 2)

    def test_refresh_reports_read_failure_instead_of_partial_success(self):
        self.mock(core, "ensure_scapy", return_value=True)
        self.mock(core, "conf", new=SimpleNamespace(
            ifaces=SimpleNamespace(reload=Mock(side_effect=OSError("adapter changed")))))
        with self.assertRaises(RuntimeError):
            core.list_ifaces()

    def test_canceled_scan_keeps_discovered_devices(self):
        self.mock(core, "list_ifaces", return_value=[CARD])
        def fake_sweep(target, iface, **options):
            core.STORE.cancel.set()
            return {IP: [MAC]}, [IP]
        self.mock(core, "arp_sweep", side_effect=fake_sweep)
        result = self.backend.run("scan", {"iface": CARD, "target": IP})
        self.assertTrue(result["canceled"])
        self.assertEqual(result["summary"]["devices"], 1)
        self.assertFalse(core.STORE.scan_done)


if __name__ == "__main__":
    unittest.main()

