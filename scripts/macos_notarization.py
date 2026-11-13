"""Submit once, retain the signed DMG, and finalize only an accepted request."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

REPOSITORY = "goyohan0611-png/quiet-scanner"
TARGETS = {"aarch64-apple-darwin": ("AppleSilicon", "arm64"),
           "x86_64-apple-darwin": ("Intel", "x86_64")}


def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_native(args, *, timeout=180):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Do not include argv: notarytool receives an app-specific password.
        message = (result.stderr or result.stdout)[-3000:]
        for key in ("APPLE_ID", "APPLE_PASSWORD"):
            secret = os.environ.get(key)
            if secret:
                message = message.replace(secret, "***")
        raise ValueError(f"{args[0]} failed: {message}")
    return result.stdout, result.stderr


def notary(command, *args):
    team = os.environ["NOTARY_TEAM_ID"]
    require(re.fullmatch(r"[A-Z0-9]{10}", team), "Invalid Apple Team ID")
    identity, password = os.environ["APPLE_ID"], os.environ["APPLE_PASSWORD"]
    require(identity and password, "Missing Apple notarization credentials")
    output, _ = run_native([
        "xcrun", "notarytool", command, *map(str, args),
        "--apple-id", identity, "--team-id", team, "--password", password,
        "--output-format", "json",
    ])
    return json.loads(output)


def validate_source(data, expected_run):
    require(str(expected_run).isdigit(), "Invalid source run ID")
    require(str(data.get("id")) == str(expected_run), "Unexpected source run")
    require(data.get("head_repository", {}).get("full_name") == REPOSITORY,
            "Artifacts must originate in this repository")
    require(data.get("head_branch") == "main", "Artifacts must originate on main")
    require(data.get("event") == "workflow_dispatch", "Unexpected source event")
    require(data.get("path", "").split("@", 1)[0] == ".github/workflows/macos-signed.yml",
            "Artifacts must originate in the signing workflow")
    require(data.get("status") == "completed", "Source workflow has not finished")
    require(data.get("conclusion") in ("success", "failure"), "Source workflow was cancelled")
    sha = data.get("head_sha", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha), "Invalid source commit")
    return sha


def source_run(path):
    run = os.environ["SOURCE_RUN_ID"]
    sha = validate_source(json.loads(Path(path).read_text(encoding="utf-8")), run)
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        output.write(f"EXPECTED_SOURCE_SHA={sha}\nEXPECTED_SOURCE_RUN_ID={run}\n")
    print(json.dumps({"source_run": run, "source_sha": sha, "trusted_source": True}))


def submit(dmg, output, version):
    target = os.environ["CARGO_BUILD_TARGET"]
    require(target in TARGETS, "Unexpected macOS target")
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version), "Invalid version")
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY, "Unexpected repository")
    require(re.fullmatch(r"[0-9a-f]{40}", os.environ["GITHUB_SHA"]), "Invalid source commit")
    require(os.environ["GITHUB_RUN_ID"].isdigit(), "Invalid source run")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    name = f"Quiet.Scanner.{version}.macOS.{TARGETS[target][0]}.dmg"
    destination = output / name
    shutil.copyfile(dmg, destination)
    manifest = {
        "repository": REPOSITORY, "source_sha": os.environ["GITHUB_SHA"],
        "source_run_id": os.environ["GITHUB_RUN_ID"], "target": target,
        "team_id": os.environ["NOTARY_TEAM_ID"], "version": version,
        "file_name": name, "submitted_sha256": digest(destination),
        "submission_id": None,
    }
    # Persist the signed file before the upload, including on network failure.
    write_json(output / "manifest.json", manifest)
    response = notary("submit", destination)  # Deliberately no --wait.
    request_id = str(uuid.UUID(response["id"]))
    manifest["submission_id"] = request_id
    write_json(output / "manifest.json", manifest)
    print(json.dumps({"submitted": request_id, "version": version,
                      "target": target, "verified_installer": False}))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(f"## {target}: submitted, awaiting Apple\n\n")
            stream.write(f"Submission: `{request_id}`. Signed DMG and manifest are retained. "
                         "This is not yet a verified installer.\n")


def load_manifest(folder):
    folder = Path(folder).resolve()
    path = folder / "manifest.json"
    require(not path.is_symlink(), "Manifest must not be a symlink")
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data.get("repository") == REPOSITORY, "Unexpected artifact repository")
    require(data.get("source_sha") == os.environ["EXPECTED_SOURCE_SHA"], "Source commit mismatch")
    require(str(data.get("source_run_id")) == os.environ["EXPECTED_SOURCE_RUN_ID"],
            "Source run mismatch")
    target = os.environ["CARGO_BUILD_TARGET"]
    require(target in TARGETS and data.get("target") == target, "Architecture mismatch")
    require(data.get("team_id") == os.environ["NOTARY_TEAM_ID"], "Apple Team ID mismatch")
    require(re.fullmatch(r"[A-Z0-9]{10}", data["team_id"]), "Invalid Apple Team ID")
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", data.get("version", "")),
            "Invalid artifact version")
    name = data.get("file_name", "")
    expected_name = f"Quiet.Scanner.{data['version']}.macOS.{TARGETS[target][0]}.dmg"
    require(name == expected_name, "Unexpected DMG filename")
    dmg = folder / name
    require(not dmg.is_symlink() and dmg.resolve().parent == folder and dmg.is_file(),
            "DMG must be a regular file in the artifact directory")
    require(digest(dmg) == data.get("submitted_sha256"), "Submitted DMG hash mismatch")
    require(str(uuid.UUID(data.get("submission_id") or "")) == data["submission_id"],
            "Missing or invalid notarization submission ID")
    return data, dmg


def verify_team(path, expected_team, *, runtime=False):
    run_native(["codesign", "--verify", "--deep", "--strict", str(path)])
    _, details = run_native(["codesign", "-d", "--verbose=4", str(path)])
    require(f"TeamIdentifier={expected_team}" in details.splitlines(), "Signing team mismatch")
    if runtime:
        require("(runtime)" in details, "Hardened runtime is missing")


def verify_mounted_app(dmg, data):
    temporary = Path(tempfile.mkdtemp(prefix="quiet-notary-mount-"))
    mount = temporary / "image"
    mount.mkdir()
    try:
        run_native(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(mount), str(dmg)])
        app = mount / "Quiet Scanner.app"
        require(app.resolve().is_relative_to(mount.resolve()), "App path escapes mounted image")
        verify_team(app, data["team_id"], runtime=True)
        with open(app / "Contents/Info.plist", "rb") as source:
            plist = plistlib.load(source)
        require(plist.get("CFBundleIdentifier") == "com.lab241.quietscanner", "Bundle ID mismatch")
        require(plist.get("CFBundleShortVersionString") == data["version"], "App version mismatch")
        binary = app / "Contents/MacOS/quiet-scanner"
        require(binary.resolve().is_relative_to(app.resolve()), "Binary path escapes app")
        arches, _ = run_native(["lipo", "-archs", str(binary)])
        require(arches.split() == [TARGETS[data["target"]][1]], "App architecture mismatch")
        run_native(["spctl", "--assess", "--type", "execute", "--verbose=2", str(app)])
    finally:
        # Never recursively delete a mount path, including on attach/detach failure.
        try:
            run_native(["hdiutil", "detach", str(mount)])
        finally:
            mount.rmdir()
            temporary.rmdir()


def finalize(folder, output):
    data, dmg = load_manifest(folder)
    response = notary("info", data["submission_id"])
    require(response.get("id") == data["submission_id"], "Apple submission ID mismatch")
    status = response.get("status")
    print(json.dumps({"submission_id": data["submission_id"], "apple_status": status}))
    if status == "In Progress":
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write("ready=false\n")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
                stream.write("## Still awaiting Apple\n\nNo verified installer was produced. "
                             "Run this finalization again later with the same source run ID.\n")
        return
    log = notary("log", data["submission_id"])
    require(status == "Accepted" and log.get("status") == "Accepted",
            f"Apple notarization was not accepted: {status}; {log.get('statusSummary', '')}")
    verify_team(dmg, data["team_id"])
    # Tickets can take a short time to propagate after Apple reports acceptance.
    for attempt in range(3):
        try:
            run_native(["xcrun", "stapler", "staple", str(dmg)])
            break
        except ValueError:
            if attempt == 2:
                raise
            time.sleep(10)
    run_native(["xcrun", "stapler", "validate", str(dmg)])
    run_native(["hdiutil", "verify", str(dmg)])
    run_native(["spctl", "--assess", "--type", "open", "--context", "context:primary-signature",
                "--verbose=2", str(dmg)])
    verify_mounted_app(dmg, data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    published = output / dmg.name
    shutil.copyfile(dmg, published)
    final_hash = digest(published)
    (output / "SHA256SUMS.txt").write_text(f"{final_hash}  {published.name}\n", encoding="utf-8")
    write_json(output / "notarization-report.json", {
        **data, "status": "Accepted", "stapled_sha256": final_hash, "issues": log.get("issues"),
    })
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write("ready=true\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(f"## Verified notarized installer: {data['target']}\n\n"
                         f"Apple accepted `{data['submission_id']}`. Signature, ticket, "
                         "Gatekeeper, version and architecture checks passed.\n")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source")
    source.add_argument("path")
    upload = commands.add_parser("submit")
    upload.add_argument("--dmg", required=True)
    upload.add_argument("--output", required=True)
    upload.add_argument("--version", required=True)
    finish = commands.add_parser("finalize")
    finish.add_argument("--input", required=True)
    finish.add_argument("--output", required=True)
    options = parser.parse_args()
    if options.command == "source":
        source_run(options.path)
    elif options.command == "submit":
        submit(options.dmg, options.output, options.version)
    else:
        finalize(options.input, options.output)


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired:
        # TimeoutExpired includes argv, which can contain Apple credentials.
        print("An external notarization command timed out; no verified installer was published.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError, OSError) as error:
        message = str(error)
        for key in ("APPLE_ID", "APPLE_PASSWORD"):
            if os.environ.get(key):
                message = message.replace(os.environ[key], "***")
        print(f"Notarization step failed: {message}", file=sys.stderr)
        sys.exit(1)
