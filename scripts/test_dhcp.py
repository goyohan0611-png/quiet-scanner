"""DHCP server check. Packets are built and parsed only; nothing goes on the wire."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import IPFixStudio as core

CARD = {"name": "test", "scapyName": "test-guid", "desc": "Test adapter", "index": 2,
        "mac": "02:00:00:00:00:01", "ips": ["192.168.0.181"],
        "ipv4": [{"ip": "192.168.0.181", "cidr": "192.168.0.0/24"}]}
ROUTER_MAC = "50:c7:bf:11:22:33"
ROGUE_MAC = "70:b3:d5:21:b7:ce"


def reply(xid, server, mac, kind="offer", offered="192.168.0.57", relay="0.0.0.0"):
    """A server's answer, taken through bytes so it reads like a captured frame."""
    packet = (core.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
              / core.IP(src=server, dst="255.255.255.255")
              / core.UDP(sport=67, dport=68)
              / core.BOOTP(op=2, xid=xid, yiaddr=offered, siaddr=server, giaddr=relay,
                           chaddr=bytes.fromhex("020000000001"), flags=0x8000)
              / core.DHCP(options=[("message-type", kind), ("server_id", server),
                                   ("lease_time", 7200), ("subnet_mask", "255.255.255.0"),
                                   ("router", server), ("name_server", "8.8.8.8", "1.1.1.1"),
                                   ("domain", "lan"), "end"]))
    return core.Ether(bytes(packet))


class DhcpTestCase(unittest.TestCase):
    def setUp(self):
        self.assertTrue(core.ensure_dhcp(), core.DHCP_ERR)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.mock(core, "app_dir", return_value=self.directory.name)

    def mock(self, obj, name, **kwargs):
        patcher = patch.object(obj, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result


class OfferParsingTests(DhcpTestCase):
    def test_offer_fields(self):
        offer = core.parse_dhcp_offer(reply(7, "192.168.0.1", ROUTER_MAC), 7)
        self.assertEqual(offer["ip"], "192.168.0.1")
        self.assertEqual(offer["mac"], ROUTER_MAC)
        self.assertEqual(offer["offered"], "192.168.0.57")
        self.assertEqual(offer["mask"], "255.255.255.0")
        self.assertEqual(offer["router"], ["192.168.0.1"])
        self.assertEqual(offer["dns"], ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(offer["domain"], "lan")
        self.assertEqual(offer["lease"], 7200)
        self.assertEqual(offer["relay"], "")

    def test_relay_address_is_reported(self):
        offer = core.parse_dhcp_offer(reply(7, "10.0.0.5", ROUTER_MAC, relay="192.168.0.254"), 7)
        self.assertEqual(offer["relay"], "192.168.0.254")

    def test_everything_that_is_not_our_offer_is_ignored(self):
        ours = (core.Ether(src=CARD["mac"], dst="ff:ff:ff:ff:ff:ff")
                / core.IP(src="0.0.0.0", dst="255.255.255.255") / core.UDP(sport=68, dport=67)
                / core.BOOTP(op=1, xid=7) / core.DHCP(options=[("message-type", "discover"), "end"]))
        self.assertIsNone(core.parse_dhcp_offer(core.Ether(bytes(ours)), 7))
        self.assertIsNone(core.parse_dhcp_offer(reply(7, "192.168.0.1", ROUTER_MAC, kind="nak"), 7))
        self.assertIsNone(core.parse_dhcp_offer(reply(8, "192.168.0.1", ROUTER_MAC), 7))
        arp = core.Ether() / core.ARP(op=2, psrc="192.168.0.1", hwsrc=ROUTER_MAC)
        self.assertIsNone(core.parse_dhcp_offer(arp, 7))


class DiscoverTests(DhcpTestCase):
    def test_every_server_is_listed_once(self):
        sent = []

        def fake_srp(packet, **options):
            sent.append((packet, options))
            xid = packet[core.BOOTP].xid
            answers = [reply(xid, "192.168.0.254", ROGUE_MAC),
                       reply(xid, "192.168.0.1", ROUTER_MAC),
                       reply(xid, "192.168.0.1", ROUTER_MAC),          # the same offer, repeated
                       reply(xid + 1, "192.168.0.9", "00:11:22:33:44:55")]  # someone else's
            return [(packet, answer) for answer in answers], []
        self.mock(core, "srp", side_effect=fake_srp)
        servers = core.dhcp_discover("test-guid", CARD["mac"])
        self.assertEqual([s["ip"] for s in servers], ["192.168.0.1", "192.168.0.254"])
        self.assertEqual(len(sent), 1, "a second DISCOVER is only for a silent first round")

        packet, options = sent[0]
        self.assertEqual(options["iface"], "test-guid")
        self.assertTrue(options["multi"], "must keep listening after the first offer")
        self.assertEqual(packet.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(packet.src, CARD["mac"])
        self.assertEqual((packet[core.UDP].sport, packet[core.UDP].dport), (68, 67))
        wire = core.Ether(bytes(packet))
        self.assertEqual(wire[core.BOOTP].chaddr[:6], bytes.fromhex("020000000001"))
        self.assertEqual(int(wire[core.BOOTP].flags), 0x8000)
        self.assertIn(("message-type", 1), wire[core.DHCP].options)

    def test_scapy_pairs_the_offer_with_the_discover(self):
        checked = []

        def fake_srp(packet, **options):
            answer = reply(packet[core.BOOTP].xid, "192.168.0.1", ROUTER_MAC)
            # srp drops any reply that fails these two. They only pass because the
            # address check is off for the duration of the call.
            self.assertFalse(core.conf.checkIPaddr)
            self.assertEqual(answer.hashret(), core.Ether(bytes(packet)).hashret())
            self.assertTrue(answer.answers(core.Ether(bytes(packet))))
            checked.append(True)
            return [(packet, answer)], []
        self.mock(core, "srp", side_effect=fake_srp)
        self.assertEqual(len(core.dhcp_discover("test-guid", CARD["mac"])), 1)
        self.assertTrue(checked)

    def test_address_check_is_put_back(self):
        for before in (True, False):
            core.conf.checkIPaddr = before
            with patch.object(core, "srp", return_value=([], [])):
                core.dhcp_discover("test-guid", CARD["mac"])
            self.assertEqual(core.conf.checkIPaddr, before)
            with patch.object(core, "srp", side_effect=OSError("adapter gone")):
                with self.assertRaises(OSError):
                    core.dhcp_discover("test-guid", CARD["mac"])
            self.assertEqual(core.conf.checkIPaddr, before)
        core.conf.checkIPaddr = True

    def test_asks_again_only_after_silence(self):
        silent = self.mock(core, "srp", return_value=([], []))
        self.assertEqual(core.dhcp_discover("test-guid", CARD["mac"]), [])
        self.assertEqual(silent.call_count, 2)

    def test_unusable_mac_sends_nothing(self):
        send = self.mock(core, "srp")
        for mac in ("", "00:00:00:00:00:00", "02:00:00"):
            with self.assertRaises(ValueError):
                core.dhcp_discover("test-guid", mac)
        send.assert_not_called()


class BackendTests(DhcpTestCase):
    def setUp(self):
        super().setUp()
        self.mock(core, "pin_sweep", return_value=0)
        spec = importlib.util.spec_from_file_location(
            "backend_dhcp_test", Path(core.__file__).with_name("electron-backend.py"))
        self.backend = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.backend)
        self.mock(self.backend, "emit_state")
        self.mock(core, "list_ifaces", return_value=[CARD])

    def servers(self, *pairs):
        return [core.parse_dhcp_offer(reply(1, ip, mac), 1) for ip, mac in pairs]

    def test_two_servers_are_flagged(self):
        discover = self.mock(core, "dhcp_discover", return_value=self.servers(
            ("192.168.0.1", ROUTER_MAC), ("192.168.0.254", ROGUE_MAC)))
        result = self.backend.run("dhcp_servers", {"iface": CARD})
        discover.assert_called_once_with("test-guid", CARD["mac"])
        self.assertEqual(len(result["servers"]), 2)
        self.assertEqual(result["iface"], "Test adapter")
        warnings = [log["msg"] for log in result["state"]["logs"] if log["level"] == "warn"]
        self.assertEqual(len(warnings), 3, "one line per server and one summary")
        self.assertFalse(self.backend.DHCP_LOCK.locked())

    def test_silence_is_not_an_error(self):
        self.mock(core, "dhcp_discover", return_value=[])
        result = self.backend.run("dhcp_servers", {"iface": CARD})
        self.assertEqual(result["servers"], [])
        self.assertFalse([log for log in result["state"]["logs"] if log["level"] == "warn"])

    def test_refused_while_scanning(self):
        discover = self.mock(core, "dhcp_discover")
        self.backend.SCAN_RUNNING = True
        with self.assertRaises(RuntimeError):
            self.backend.run("dhcp_servers", {"iface": CARD})
        discover.assert_not_called()

    def test_scan_and_isolation_wait_for_the_check(self):
        sweep = self.mock(core, "arp_sweep")
        pin = self.mock(core, "arp_pin")
        device = core.STORE.upsert("192.168.0.40", ROGUE_MAC)
        with self.backend.DHCP_LOCK:
            with self.assertRaises(RuntimeError):
                self.backend.run("scan", {"iface": CARD, "target": "192.168.0.40"})
            with self.assertRaises(RuntimeError):
                self.backend.run("isolate", {"key": device["key"]})
            with self.assertRaises(RuntimeError):
                self.backend.run("dhcp_servers", {"iface": CARD})
        sweep.assert_not_called()
        pin.assert_not_called()

    def test_failure_does_not_leave_the_check_locked(self):
        self.mock(core, "dhcp_discover", side_effect=OSError("Npcap unavailable"))
        with self.assertRaises(OSError):
            self.backend.run("dhcp_servers", {"iface": CARD})
        self.assertFalse(self.backend.DHCP_LOCK.locked())

    def test_vanished_adapter_sends_nothing(self):
        discover = self.mock(core, "dhcp_discover")
        with self.assertRaises(RuntimeError):
            self.backend.run("dhcp_servers", {"iface": dict(CARD, scapyName="gone")})
        discover.assert_not_called()

    def test_runs_off_the_reader_thread(self):
        self.assertIn("dhcp_servers", self.backend.SLOW_ACTIONS)


if __name__ == "__main__":
    unittest.main()
