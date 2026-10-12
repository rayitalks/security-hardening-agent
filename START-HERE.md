# Move this baseline to another device

Public repository: https://github.com/rayitalks/ray-i-security-hardening-agent

This is the application source for **Ray-i Security Hardening Agent 3.1.0**, captured October 10, 2026 (America/New_York). The `baseline-v1` Git tag identifies this starting point. The original application remains installed separately on the first Windows computer; this repository is the portable working copy.

## First setup on your Mac or second Windows computer

1. Download or clone this public repository; a GitHub account is not required to download it.
2. Install Git, or use GitHub Desktop to clone the repository. Install **Python 3.12** from https://www.python.org/downloads/. Python 3.13 is also accepted by the bundled engine installers. Python 3.14 can run the console but is not supported by the model-tools installer.
3. Clone into a local folder outside OneDrive or iCloud, such as `~/Projects` on macOS or `%USERPROFILE%\Projects` on Windows:

   ```sh
   git clone https://github.com/rayitalks/ray-i-security-hardening-agent.git
   cd ray-i-security-hardening-agent
   ```

4. **Windows:** double-click `Setup-Windows.bat`. **Mac:** open Terminal in the cloned folder and run:

   ```sh
   sh Setup-Mac.command
   ```

These setup launchers install SkillSpector, Trivy, ModelAudit/model and packet tools, and the audit tools including Gitleaks using the existing pinned installers. They need internet access, may take several minutes, and stop at the first failure. They create platform-specific runtimes inside this folder. Re-run setup after resolving any reported dependency/platform problem. The included Windows YARA wheel is used only when compatible; other platforms obtain their compatible dependency from the package index.

For a quick console launch without optional engine downloads, run `python setup_device.py --launch` on Windows or `python3 setup_device.py --launch` on Mac. Optional scanners will remain unavailable until installed.

The browser should open **http://127.0.0.1:8765/**. Verify version **3.1.0** and the engine availability in the app. If an older instance is already running, finish its work and stop it before starting this checkout: the launcher reuses an existing instance on that port.

## What transfers

The repository includes source, UI, tests, pinned dependency constraints, bundled wheels and licenses, Docker configuration, launchers, and documentation. `BASELINE-MANIFEST.json` records hashes for the baseline files:

```sh
python setup_device.py --verify-baseline
```

On Mac use `python3` if `python` is unavailable. This check is read-only. It will report changed files after intentional development; the original hashes stay attached to `baseline-v1`. The manifest is an integrity inventory, not an independent signature.

Local `.data` databases, scan histories, audit records/keys, credentials, logs, downloaded scanner binaries, virtual environments and caches are excluded. Each device starts with its own local data and keys. Supply provider credentials locally through the environment or the app as documented; do not commit them. The app does not automatically load an `.env` file.

The existing app and its data on the first Windows computer are preserved. This checkout does not replace that installation or change its desktop shortcut. Use this repository for future source changes; launch it explicitly after stopping an older instance if you want it to become the active installation.

## Keep devices in sync

Before editing on a device, with a clean working tree:

```sh
git pull --ff-only
```

After finishing changes:

```sh
git status
git add path/to/the-files-you-changed
git commit -m "Describe the change"
git push
```

Use actual file paths in place of the example. Review `git diff --cached` before committing. If a pull reports divergent history, resolve it deliberately; do not force-push or discard work. Update optional engines only when the versioned installer/constraint files change, then restart the app after source changes. Git does not update an already running process.

To create a separate copy of the original baseline without disturbing your current changes:

```sh
git clone --branch baseline-v1 https://github.com/rayitalks/ray-i-security-hardening-agent.git security-hardening-agent-baseline
```

That clone starts in detached-HEAD mode. Create a branch before developing from it.

## Platform expectations

- Windows-specific Defender, Hyper-V and Windows event-log features require Windows and the relevant local tools/permissions.
- macOS host checks include SIP, Gatekeeper, FileVault and the application firewall. VMware Fusion/VirtualBox need their own installed CLI. Antivirus, packet capture, Docker, inference endpoints and other external engines need their own platform setup.
- Node.js with the required cryptographic support is optional for the PQ evaluation tools; setup does not install Node, antivirus engines, Docker, models or hypervisors.
- Native Mac execution and installation on the second Windows device must be verified on those actual machines. Source transfer alone does not establish feature parity or a successful remote installation.

See [BASELINE-VERIFICATION.md](BASELINE-VERIFICATION.md) for this snapshot's validation and [README.md](README.md) for the full application reference.
