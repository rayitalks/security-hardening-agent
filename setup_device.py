"""Prepare this checkout using its existing, pinned optional engine installers."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
INSTALLERS = {
    "skillspector": "install_skillspector.py",
    "trivy": "install_trivy.py",
    "model": "install_model_tools.py",
    "audit": "install_audit_tools.py",
}


def verify_baseline():
    manifest = json.loads((ROOT / "BASELINE-MANIFEST.json").read_text(encoding="utf-8"))
    failures = []
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if not path.is_file():
            failures.append(entry["path"] + " (missing)")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            failures.append(entry["path"] + " (changed)")
    if failures:
        print("Files differ from the saved baseline:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Baseline verified: {len(manifest['files'])} files; app {manifest['appVersion']}.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engines", nargs="+", choices=["none", "all", *INSTALLERS], default=["none"])
    parser.add_argument("--launch", action="store_true", help="Open the local console after successful setup")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan without installing or starting anything")
    parser.add_argument("--verify-baseline", action="store_true", help="Check files against the saved baseline; no installation")
    args = parser.parse_args()
    if args.verify_baseline:
        return verify_baseline()
    if sys.version_info < (3, 10):
        parser.error("The console requires Python 3.10 or newer.")
    if len(args.engines) > 1 and any(value in args.engines for value in ("all", "none")):
        parser.error("Use all or none by itself, or list individual engines.")
    selected = list(INSTALLERS) if args.engines == ["all"] else ([] if args.engines == ["none"] else list(dict.fromkeys(args.engines)))
    if "model" in selected and not (3, 12) <= sys.version_info[:2] < (3, 14):
        parser.error("Model tools require Python 3.12 or 3.13. Install Python 3.12, then run this setup with that interpreter.")
    if "skillspector" in selected and not (3, 12) <= sys.version_info[:2] < (3, 15):
        parser.error("SkillSpector requires Python 3.12, 3.13, or 3.14.")
    print(f"Device: {platform.system()} {platform.machine()} | Python {platform.python_version()}", flush=True)
    print(f"Project: {ROOT}", flush=True)
    print("Optional engines: " + (", ".join(selected) or "none; basic console only"), flush=True)
    for name in selected:
        command = [sys.executable, str(ROOT / INSTALLERS[name])]
        print("Run: " + " ".join(command), flush=True)
        if not args.dry_run:
            try:
                subprocess.run(command, cwd=ROOT, check=True)
            except subprocess.CalledProcessError as error:
                print(f"{name} installation failed (exit {error.returncode}). Fix the error above and rerun setup; the console has not been launched.", file=sys.stderr)
                return error.returncode or 1
    if args.launch:
        print("Launch: http://127.0.0.1:8765/", flush=True)
        if not args.dry_run:
            return subprocess.run([sys.executable, str(ROOT / "launch.py")], cwd=ROOT).returncode
    if not args.dry_run:
        print("Setup complete. Use Start-Windows.bat on Windows or sh start.sh on macOS/Linux.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
