"""Reject mismatched artifacts and prevent pending requests becoming releases."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("macos_notarization", Path(__file__).with_name("macos_notarization.py"))
notary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notary)


class NotarizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name)
        self.dmg = self.folder / "Quiet.Scanner.4.2.0.macOS.AppleSilicon.dmg"
        self.dmg.write_bytes(b"signed fixture")
        self.manifest = {
            "repository": notary.REPOSITORY, "source_sha": "a" * 40,
            "source_run_id": "123", "target": "aarch64-apple-darwin",
            "team_id": "A123456789", "version": "4.2.0",
            "file_name": self.dmg.name, "submitted_sha256": notary.digest(self.dmg),
            "submission_id": "12345678-1234-1234-1234-123456789abc",
        }
        self.save()
        self.environment = patch.dict(os.environ, {
            "EXPECTED_SOURCE_SHA": "a" * 40, "EXPECTED_SOURCE_RUN_ID": "123",
            "NOTARY_TEAM_ID": "A123456789", "CARGO_BUILD_TARGET": "aarch64-apple-darwin",
            "GITHUB_OUTPUT": str(self.folder / "output.txt"),
            "GITHUB_STEP_SUMMARY": str(self.folder / "summary.md"),
        })
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def save(self):
        notary.write_json(self.folder / "manifest.json", self.manifest)

    def test_matching_artifact(self):
        data, path = notary.load_manifest(self.folder)
        self.assertEqual(path, self.dmg.resolve())
        self.assertEqual(data["source_run_id"], "123")

    def test_modified_dmg_is_rejected(self):
        self.dmg.write_bytes(b"modified after submission")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            notary.load_manifest(self.folder)

    def test_manifest_bindings_are_checked(self):
        changes = {
            "repository": "other/repo", "source_sha": "b" * 40,
            "source_run_id": "456", "target": "x86_64-apple-darwin",
            "team_id": "B123456789", "file_name": "../escape.dmg",
            "submission_id": None, "version": "../../4.2.0",
        }
        for key, invalid in changes.items():
            with self.subTest(key=key):
                original = self.manifest[key]
                self.manifest[key] = invalid
                self.save()
                with self.assertRaises((ValueError, KeyError)):
                    notary.load_manifest(self.folder)
                self.manifest[key] = original
                self.save()

    def test_pending_request_does_not_create_verified_artifact(self):
        response = {"id": self.manifest["submission_id"], "status": "In Progress"}
        with patch.object(notary, "notary", return_value=response), patch.object(notary, "run_native") as native:
            notary.finalize(self.folder, self.folder / "verified")
        native.assert_not_called()
        self.assertFalse((self.folder / "verified").exists())
        self.assertEqual((self.folder / "output.txt").read_text().strip(), "ready=false")

    def test_rejected_request_cannot_be_published(self):
        responses = [{"id": self.manifest["submission_id"], "status": "Invalid"},
                     {"status": "Invalid", "statusSummary": "fixture rejection"}]
        with patch.object(notary, "notary", side_effect=responses), patch.object(notary, "run_native") as native:
            with self.assertRaisesRegex(ValueError, "not accepted"):
                notary.finalize(self.folder, self.folder / "verified")
        native.assert_not_called()
        self.assertFalse((self.folder / "verified").exists())

    def test_wrong_apple_response_id_is_rejected(self):
        with patch.object(notary, "notary", return_value={"id": "other", "status": "Accepted"}):
            with self.assertRaisesRegex(ValueError, "ID mismatch"):
                notary.finalize(self.folder, self.folder / "verified")

    def test_source_run_is_bound_to_main_and_signing_workflow(self):
        data = {"id": 123, "head_repository": {"full_name": notary.REPOSITORY},
                "head_branch": "main", "event": "workflow_dispatch", "status": "completed",
                "conclusion": "success", "head_sha": "a" * 40,
                "path": ".github/workflows/macos-signed.yml"}
        self.assertEqual(notary.validate_source(data, "123"), "a" * 40)
        for key, invalid in {"head_branch": "untrusted", "event": "pull_request",
                             "path": ".github/workflows/other.yml", "status": "in_progress",
                             "conclusion": "cancelled", "head_repository": {"full_name": "fork/repo"},
                             "id": 456, "head_sha": "not a SHA"}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                notary.validate_source({**data, key: invalid}, "123")


if __name__ == "__main__":
    unittest.main()

