"""Offline validation for registry refreshes and the bundled data."""
import copy
import gzip
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_oui", ROOT / "tools/build_oui.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class VendorDataTests(unittest.TestCase):
    def test_csv_rejects_error_pages_empty_and_invalid_assignments(self):
        for text in ["<html>Error</html>", "Registry,Assignment,Organization Name\n",
                     "Registry,Assignment,Organization Name\nMA-L,not-hex,Vendor\n"]:
            with self.assertRaises(ValueError):
                builder.parse_registry(text, 6)

    def test_expansion_preserves_rules_and_does_not_guess_kind(self):
        book = {"entries": [{"vendor": "Brand", "kind": "Existing kind", "prefixes": ["001122"]}]}
        original = copy.deepcopy(book["entries"][0])
        registry = {"001122": "Brand Ltd", "aabbcc": "Brand Ltd", "112233": "Unrelated Ltd"}
        self.assertEqual(builder.expand_book(book, registry), 1)
        self.assertEqual(book["entries"][0], original)
        self.assertEqual(book["entries"][1]["prefixes"], ["aabbcc"])
        self.assertEqual(book["entries"][1]["kind"], "")
        self.assertEqual(builder.expand_book(book, registry), 0)

    def test_incomplete_legacy_prefix_is_removed(self):
        book = {"entries": [{"vendor": "Brand", "prefixes": ["02-04-", "001122"]}]}
        builder.expand_book(book, {})
        self.assertEqual(book["entries"][0]["prefixes"], ["001122"])

    def test_ambiguous_organization_is_not_expanded(self):
        book = {"entries": [{"vendor": v, "prefixes": [p]} for v, p in [("A", "001122"), ("B", "112233")]]}
        self.assertEqual(builder.expand_book(book, {p: "OEM" for p in ["001122", "112233", "aabbcc"]}), 0)

    def test_bundled_prefixes_are_unique_and_provenance_matches(self):
        book = json.loads((ROOT / "src/device-book.json").read_text(encoding="utf-8"))
        prefixes = [p for e in book["entries"] for p in e["prefixes"]]
        self.assertEqual(len(prefixes), len(set(prefixes)))
        import re
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{6,12}", p) for p in prefixes))
        table = gzip.decompress((ROOT / "src/oui.dat.gz").read_bytes()).decode("utf-8")
        import hashlib
        provenance = json.loads((ROOT / "docs/vendor-data.json").read_text(encoding="utf-8"))
        self.assertEqual(provenance["vendor_prefixes"], len(table.splitlines()))
        self.assertEqual(provenance["device_book_prefixes"], len(prefixes))
        self.assertEqual(provenance["oui_sha256"], hashlib.sha256((ROOT / "src/oui.dat.gz").read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
