# Baseline verification

Prepared October 10, 2026 (America/New_York) for the private repository `rayitalks/security-hardening-agent`.

## Captured application

- Application source version: **3.1.0**.
- All application Python, JavaScript, HTML, PowerShell, existing batch launchers, vendor wheels and license files were copied from the existing installation. No scanner or application behavior was changed for this snapshot.
- Added: portable setup orchestration, Windows/Mac setup launchers, this verification note, START-HERE, a baseline manifest and Git attributes. Expanded `.gitignore`; added a new-device link to README; normalized the shell launcher to LF line endings.
- The original installation, desktop shortcut, live service and user data were not modified.

## Checks performed on the current Windows computer

- **191 Python tests passed**, zero failures or skips, using the existing Python 3.12.14 model runtime and temporary links to the installed optional engines. The links were removed after testing; they are not portable dependencies or repository contents.
- **11 password security checks passed** (`node test_password.cjs workspace.js`).
- **14 PQ cryptography checks passed** (`node test_pqc.cjs ./pqc_worker.cjs`). These use synthetic, temporary test keys and make no production certification claim.
- JSON/HTML model report export checks passed (`node test_model_exports.cjs`).
- JavaScript syntax checks passed for workspace, model assurance, endpoint providers and team workspace.
- Setup dry-runs passed for the basic console on Python 3.14.7 and all optional engine installers on Python 3.12.14. The setup launchers select Python 3.12 or 3.13 for all engines.
- A clean basic-console HTTP smoke test was run separately with no linked optional runtimes, separate temporary data and an unused loopback port; the returned identity and version were verified before stopping the test process.
- Gitleaks 8.30.1 checked the prepared source tree with fully redacted reporting. It reported one match: the deliberately synthetic credential string in `test_app.py`, line 17, used to test redaction. That fixture was reviewed and retained unchanged. No actual credential was identified by this check. A pattern scan does not prove absence of all secrets.
- Baseline SHA-256 inventory and original application-file comparisons were checked before publication. Byte preservation is configured through `.gitattributes`.

## Exclusions and remaining device checks

Credentials, `.data` databases/audit keys, scan results, logs, PCAPs, installed runtimes, downloaded scanner executables and caches are excluded from Git. Generated test state is local and ignored. A new device starts with its own state and keys.

The Mac and second Windows computer were not connected to this session. Their Python installation, engine downloads, native scanner availability, permissions and actual startup remain to be verified on those devices. The Docker image was not rebuilt. Existing test success does not establish production endpoint safety, platform parity, or successful fresh dependency resolution on a different OS.

The older `VERIFICATION.md` is retained as historical context; statements there about prior live service versions and pending restarts refer to the original development sessions, not this portable snapshot.
