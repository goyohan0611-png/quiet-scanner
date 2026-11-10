"""Regression checks using a temporary user-data directory; no network writes."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import IPFixStudio as core


class DeviceBookTests(unittest.TestCase):
    def test_registration_persistence_and_removal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                core, "app_dir", return_value=directory), patch.object(
                core, "pin_sweep", return_value=0):
            spec = importlib.util.spec_from_file_location(
                "scanner_backend", Path(core.__file__).with_name("electron-backend.py"))
            backend = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(backend)
            core.BOOK = core.DeviceBook()
            device = core.STORE.upsert("192.168.0.40", "70:b3:d5:21:b7:ce")
            original_vendor = device["vendor"]
            result = backend.run("book_save", {
                "prefix": "70-B3-D5-21", "vendor": "현장 녹화기", "kind": "NVR"})
            self.assertTrue(result["created"])
            self.assertEqual(device["kind"], "NVR")
            saved = core.DeviceBook()
            self.assertTrue(saved.load())
            self.assertEqual(saved.match(device["mac"])["vendor"], "현장 녹화기")
            backend.run("book_save", {
                "prefix": "70-B3-D5-21-B7-CE", "vendor": "특정 장비", "kind": "녹화기"})
            self.assertEqual(device["vendor"], "특정 장비")
            backend.run("book_remove", {"prefix": "70-B3-D5-21-B7-CE"})
            self.assertEqual(device["vendor"], "현장 녹화기")
            backend.run("book_remove", {"prefix": "70-B3-D5-21"})
            self.assertEqual(device["vendor"], original_vendor)
            self.assertEqual(device["kind"], "")
            for prefix in ("ZZ-70-B3-D5", "70-B3-D", "70-B3-D5-21-B7-CE-FF"):
                with self.assertRaises(ValueError):
                    backend.run("book_save", {"prefix": prefix})
            with self.assertRaises(RuntimeError):
                backend.run("snmp_ports", {})


if __name__ == "__main__":
    unittest.main()
