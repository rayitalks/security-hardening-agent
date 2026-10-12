# Ray-i Security Hardening Agent 3.0 — verification

Trademark of Ray-i Consulting LLC.

Verified on October 4, 2026, native Windows. **135 automated tests passed, zero failures, zero skips** using the existing `.model-runtime` Python. Native watcher and encryption tests use the installed audit runtime where needed. Skill frontmatter/reference validation passed.

## Installed source and activation

Version 3.0 source is installed in the existing SecurityHardeningAgent application directory. The original desktop shortcut and the bundled Windows/macOS/Linux launchers remain the entry points. A pre-upgrade source backup and the previous session report were saved locally under the working folder.

At packaging time, the original process on port 8765 still serves version 2.0.0. Automatic approval review blocked the attempted stop/restart of that verified idle process (PID 8324), returning “blocked by policy” without a more specific reason. Restart authorization has been requested. Opening the existing launcher alone reuses the old process; the server must restart to load the changed Python modules. This is an activation constraint, not a claim that version 3 is already running on port 8765.

A separate test instance on loopback port 8767 was used for UI and native monitoring verification with isolated synthetic state. No production gateway routes, signed scopes, provider keys, full-payload capture or persistent monitoring were enabled in the user's main data store.

## Evidence exercised

- Existing 111 assessment/gateway/deployment tests plus 24 new operation tests.
- Real native filesystem notifications: benign test files were rewritten with random bytes; rapid-file-churn and encryption-like-burst rules fired. No ransomware, encryption program, real secret or malicious binary was run.
- Start button opened a separate dashboard tab. CPU/RAM, disk metrics, live NVIDIA GeForce RTX 3080 Ti telemetry, event counts, coverage and alerts rendered. The stop button ended collection; `running:false`, `status:off` were verified.
- Real CIRCL HTTPS hash lookup for the public SHA-256 of an empty file returned known-file membership. No user file hash or file content was submitted. VirusTotal/MalwareBazaar credentials were not supplied; those APIs are covered by bounded adapter logic, not a live credentialed smoke test.
- Ten source links and all five VM choices rendered. VMware discovery command construction, risky VMX parsing, libvirt entity rejection and read-only Proxmox API selection/reduced evidence were tested using fixtures.
- AES-256-GCM payload round-trip with a temporary supplied key, default hash-only retention, missing-key failure, chain tampering and trusted-anchor tail-deletion checks.
- Exact signed engagement scope, tampering/expiry rejection and separate production approval.
- Token hashing, expiry, rotation and revocation; context/task restrictions; exact-payload and single-use approval; real HTTP MCP requests blocked before any synthetic tool effect until approval; old tokens rejected after HTTP rotation.
- Encrypted managed-memory snapshots, rollback and gateway quarantine; behavioral new-domain/tool/token/cost anomaly rules.
- Synthetic forbidden-tool proposals intercepted; no tool executed; failed probes created remediation records and passing retests resolved them. Inference failures remained unknown.
- AI-BOM baseline/drift, synthetic authentication-burst rules, vLLM metric parsing, missing inference usage staying unknown, and malware database misses staying unknown.
- Existing tests retain real local Gitleaks/PDF fixtures, SkillSpector checks, packet fixtures, MCP descriptor-change rejection and input/output enforcement. No app-origin JavaScript errors were observed in the tested new screens.

## Local gaps and untested targets

Windows currently disables PowerShell script execution. This prevents the new authentication-event and Hyper-V `.ps1` collectors from running on this installation. No execution policy was changed. Their UI reports unavailable evidence. An administrator must approve/sign scripts under the applicable policy and provide the necessary event-log/Hyper-V permissions.

No live VMware, VirtualBox, KVM/libvirt, Proxmox, external probe machine, VPS, production agent/model endpoint, real RAG knowledge base, trusted signed model or production container was supplied. Native connectors need their actual target credentials/CLI/certificates and target-specific validation. VMware integration is Workstation/Fusion plus VMX import, not vCenter/ESXi. Docker build and macOS/Linux execution were not run for this release. Scapy warned that no libpcap provider was available; packet fixtures passed but live native capture still needs its capture driver.

The agent harness simulates carrier content, memory and peer-agent claims; it does not exercise native Hermes/Paperclip orchestration or poison live vector stores. Its sandbox intercepts tools; it is not an OS sandbox for arbitrary code. CI blocking requires installing the provided gate/example in a trusted pipeline. Governance mappings are topic-level guidance rather than certification. Runtime protection, incidents and credentials apply to routed/integrated clients.

Audit capture remains off until a user-supplied key is configured locally and the setting is enabled. External model/provider keys, event logs and production payloads were not captured during verification.


## AI endpoint engine catalog — October 4, 2026

Added 22 engine profiles and a separately reported, single-request text-chat
compatibility check. Provider selection is shared across endpoint validation,
asset discovery, expanded red team, signed agent scope, routes and behavioral
baselines. Docker COPY includes the new backend catalog and browser script.

Verification: 17 endpoint tests passed. The established 172-test Python suite
finished with 167 passes and 5 packet-runtime skips. JavaScript syntax checks,
11 existing password checks and 14 existing PQ crypto checks passed. Browser
verification used an isolated app at 127.0.0.1:18765 and a synthetic inference
fixture at 127.0.0.1:18766; both were stopped after testing. The UI exercised
engine defaults, custom prefixes, authorization, model discovery, signed scope
prefill, the compatibility report and all eight boundary cases. No real engine
installation or external inference endpoint was tested. No Docker rebuild.

An intermediate full run encountered two existing gateway timeouts and temporary
SQLite cleanup failures. Both focused reruns and the final established suite
passed. Another broad discovery run picked up concurrently added model-analysis
tests outside this change; 12 failed because NumPy was absent in the selected
runtime. Those files were preserved and were not modified for this endpoint task.

Activation remains pending: automatic approval review rejected the live service
restart as blocked by policy. The current service still reports version 2.0.0.
New endpoint-only controls stay hidden on that old backend. Its completed report
was saved separately before requesting restart permission. Do not stop an active
assessment or gateway; recheck status immediately before an approved restart.

The task output endpoint-update-verification.json records verification details
and source hashes; ai-endpoint-validation-preview.png shows the test interface.


## Version 3.1 model assurance verification — October 4, 2026

- 68 Python tests passed across test_model_assurance, test_app, test_inference_providers and test_model_actions. The 19 new assurance tests cover actual worker execution, synthetic HTTP endpoint evaluation, exact authorization and production-scope checks, single-job exclusion, parser bounds/malformed headers, F32/F64/BF16 statistics, NaN/Infinity, empty values, digest mismatch, custom profiles, positive controls, canary redaction, expired scopes, cancellation, unusable/truncated inference and evidence checksum reproduction.
- The isolated worker analyzed a synthetic Safetensors file and returned independently checked file/tensor hashes and statistics. A Windows Path.stat/fstat change-time discrepancy was resolved by comparing ctime within each API and common identity across APIs.
- test_model_exports.cjs verified the actual browser JSON/HTML export handlers preserve complete weight/behavior evidence and escape hostile text. The in-app browser download-event wait timed out, so native download completion was not asserted.
- An isolated temporary preview on loopback port 8877 used separate test storage and a synthetic model endpoint. Through the UI, numerical analysis completed and displayed tensor statistics; the 12-case behavior profile completed with 12 passes. No JavaScript errors were reported. No real model was evaluated or certified.
- Python/JavaScript syntax checks passed. Docker source COPY includes the new modules and UI script; a Docker build, large production weight file, and real inference engine evaluation were not performed.
- Updating the installed source succeeded. Automatic approval review blocked stopping/restarting the original backend, reporting blocked by policy. A manual backend restart remains necessary to activate the new source on port 8765. Reopening the launcher alone reuses an old running process.
