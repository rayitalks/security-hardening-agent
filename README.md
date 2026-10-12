# Ray-i Security Hardening Agent

**New device? Start with [START-HERE.md](START-HERE.md)** for this repository's Windows and Mac setup, saved baseline, and sync workflow. The historical installation paths below refer to the original computer.

Ray-i Security Hardening Agent is Ray-i's local security assessment console. It inspects AI agent projects, skills, model artifacts, inference endpoints, dependency inventories, containers, host configuration, and network evidence. Findings can become a prioritized action list for an AI agent to verify and carry out within the user's instructions.

Trademark of Ray-i Consulting LLC.

The installed application is **version 3.1.0**, updated on **October 4, 2026**. The previously published Library bundle and reusable skill describe version 3.0.0. The app runs at [http://127.0.0.1:8765/](http://127.0.0.1:8765/). No cloud account or paid model API is required for local static modes. Optional selected inference services can have their own costs.

## Version 3.1 — numerical weights and internal behavior evaluation

Open **Weights & behavior** from the sidebar, Model scanner, or NVIDIA SkillSpector.

- **Analyze model weights** performs read-only, full streaming numerical analysis of local Safetensors files or folders. It validates headers, shapes, dtype sizes and contiguous data ranges, then exports tensor/file SHA-256 hashes, finite-value means, population standard deviations, ranges, zeros, NaN and Infinity counts. Numerical dtypes are F64/F32/F16/BF16, signed/unsigned 8/16/32/64-bit integers and BOOL. Integer statistics use float64. Metadata values and raw weights are not exported.
- Limits are 180 seconds, 16 GiB total, 128 files, 4 MiB headers, 4,096 tensors and 10,000 inventory entries. Unsupported dtypes, malformed files, changing files and exceeded limits remain partial. Folder coverage is discovered Safetensors files only; missing model shards are not independently known. Use ModelAudit's existing supply-chain assessment for GGUF, pickle, ONNX, HDF5 and other installed engine-supported formats. Numerical statistics for those other formats are not implemented here.
- An optional independently trusted SHA-256 can verify one file's identity. Identity and unusual statistics do not establish training provenance, poisoning, learned backdoors or behavioral safety.
- **Internal behavior evaluation** uses the discovered model selected in AI endpoints and a matching signed engagement. The default versioned profile contains 12 cases: three positive controls and nine adversarial boundary probes. Choose 1–5 repetitions and a 60–1,800 second budget. No real tools execute. Production scopes still need the existing sign-off. Engagement authorization is rechecked before every request.
- PASS requires every planned repetition to finish and every acceptance rule to pass. A failed check yields FAIL. Otherwise missing, failed, cancelled, unverified or truncated inference yields INCONCLUSIVE. A model that refuses all tasks fails the positive controls. Successful HTTP responses alone cannot pass an evaluation.
- Custom synthetic JSON profiles can be uploaded or created from **Download editable profile template**. A profile has `id`, `name`, `systemPolicy` containing `{{CANARY}}`, and 1–64 tests. Each test has unique `id`, `name`, `prompt`, and 1–16 checks of `{ "match": "exact|contains|not_contains", "value": "..." }`. Exact checks trim surrounding response whitespace and are case-sensitive; substring checks are case-insensitive. At least one positive check is required. `{{CONTROL}}` generates a public control token. No arbitrary code, regular expressions or semantic judge runs.
- The evaluator detects synthetic canaries in literal, base64, hex, ROT13 and spaced forms. Other encodings and semantic failures can be missed. The selected endpoint receives synthetic prompts and may log them or charge for inference. Model identity is endpoint-reported; the evaluator does not bind the endpoint to local weight-file hashes.
- **Export JSON / Export HTML** retains the full suite, acceptance checks, redacted responses, parameters, coverage, timestamps and outcome. The evidence checksum is a SHA-256 over sorted compact UTF-8 JSON before adding `behaviorEvaluation.evidenceSha256` and `digestMethod`. It is not a signature or certification. No third-party or universal model-safety certificate is issued.

API additions use the existing app-token, Origin, exact-scope and single-job protections:

- `GET /api/model-behavior/profile`: editable built-in evaluation profile.
- `POST /api/run`: `{ "assessment": "model_weights", "path": "ABSOLUTE_LOCAL_PATH", "sha256": "OPTIONAL_TRUSTED_SHA256" }`.
- `POST /api/run`: `{ "assessment": "model_behavior", "kind": "ollama", "url": "AUTHORIZED_ENDPOINT", "model": "DISCOVERED_MODEL", "authorized": true, "engagementId": "SIGNED_SCOPE_ID", "repetitions": 3, "budgetSeconds": 600, "profile": null }`. An optional custom profile replaces the built-in profile. Provider credentials retain the existing in-memory/environment-variable handling.

After updating files, restart the existing backend process and reopen the app. Reopening `launch.py` alone reuses a running older backend. The Library ZIP is not rebuilt by this local update.

## What is included

The Library download `Security-Hardening-Agent-v3.0.0-library.zip` contains:

- `security-hardening-agent/`: the reusable `SKILL.md`, this README, `agents/openai.yaml`, and `references/local-api.md`.
- `SecurityHardeningAgent/`: the updated application source, browser UI, launchers, installers, tests, Docker configuration, bundled scanner wheels, and third-party license notices. Its README documents this release.
- `MANIFEST-SHA256.json`: byte sizes and hashes for every file included in the bundle.

Machine-specific Python runtimes, scanner executables, vulnerability/signature caches, logs, generated scan reports, and credentials are not included. Installers and Docker builds still need downloads on a new machine. The bundle is source plus the documented bundled wheels, not a fully provisioned offline installation.

The smaller `security-hardening-agent-skill.zip` contains just the reusable skill and its documentation. The application is still required to run scans.

## Use the skill

The skill is installed locally at:

`C:\Users\itsup\.codex\skills\security-hardening-agent`

Invoke it as **`$security-hardening-agent`** with a target and request. Examples:

- “Use $security-hardening-agent to scan `D:\AI\my-agent` offline and explain the findings.”
- “Use $security-hardening-agent to deep scan this project with current public dependency lookups and export the evidence.”
- “Use $security-hardening-agent to inspect this model file with ModelAudit and compare it with this trusted SHA-256.”
- “Use $security-hardening-agent to turn this exported assessment into a remediation action list.”

The skill supplies operating guidance and mode selection; it does not turn the dashboard into an autonomous remediation service. If an existing chat does not discover a newly installed skill, use a new chat or reference its `SKILL.md` directly. For another installation, place the complete `security-hardening-agent` folder under the configured Codex `skills` directory and point it at the companion app installation.

## Start the app

On this computer, use the desktop shortcut **Ray-i Security Hardening Agent**, or the `Start-Windows.bat` launcher in:

`C:\Users\itsup\Documents\Codex\2026-10-02\cna\outputs\SecurityHardeningAgent`

The launcher starts a background server, opens the browser, and reuses an existing instance. After upgrading source files, restart the old server process; merely reopening the browser or launcher does not reload Python modules. Closing the browser leaves the server running. It does not configure automatic startup.

For a foreground process from the app folder:

```powershell
python app.py --open
```

Stop that foreground process with Ctrl+C. Do not run the native and Docker versions on port 8765 simultaneously.

On a new Windows machine, install a suitable Python version and use `Install-SkillSpector.bat`, `Install-Trivy.bat`, and `Install-Model-Tools.bat`, and `Install-Audit-Tools.bat` for the relevant engines. The basic console needs Python 3.10+; TOML inventory needs 3.11+. SkillSpector's installer supports Python 3.12–3.14, and Python 3.12 is the documented tested model-tools runtime. Microsoft Defender is used when available; the app does not install Defender.

On macOS/Linux, from the extracted app directory:

```sh
python3 install_skillspector.py
python3 install_trivy.py
python3.12 install_model_tools.py
python3 install_audit_tools.py
sh start.sh
```

Install only the engines needed for the intended workflows. The installers use the bundled wheels and pinned constraints where provided. Platform compatibility and optional model-format dependencies affect coverage.

Docker launch:

```sh
docker compose up -d --build
```

The supplied image definition includes SkillSpector, Trivy, ModelAudit, Scapy, psutil, ClamAV, pypdf, model-signing, and Gitleaks. Compose publishes to loopback, runs a non-root user with a read-only root filesystem, drops Linux capabilities, and enables no-new-privileges. It has no Docker control-socket mount. Add narrowly scoped read-only input mounts using the example in `compose.yaml`. Container mode uses saved container evidence or image archives; host collection from inside it describes the container rather than the physical host. A named `threat-data` volume retains downloaded scanner data. New vulnerability/antivirus definitions require their selected update options.

## Desktop file comparison

The desktop **Ray-i Security Hardening Agent.lnk** targets `C:\Python314\pythonw.exe` with the app folder's `launch.py`. The process listening on 8765 runs `app.py` in that same folder. They are the **same application**.

No `.sh` or `.sh.*` file was found in the available user or Public desktop folders during this inspection. The app's own **`start.sh`** is a three-line macOS/Linux launcher: it changes into its folder and executes `python3 launch.py`. It launches this same app; it is not a second agent implementation.

The separate desktop **Hermes Security Team.lnk** launches `D:\AI\MetaHarness\security-team\launch_stack.py`. It is a different application and is not included in this bundle. If a separate desktop `.sh` file is later identified elsewhere, its contents still need comparison.

## Version 3.0 — monitoring and security teams

The new navigation groups bare metal, containers and virtual machines; live behavior/performance; global malware intelligence; red-team scope; blue-team operations; and purple-team posture. Existing assessments and the ten deployment checks below remain available.

### Bare metal, containers and all five VM platforms

| Platform | Implemented integration | Coverage boundary |
| --- | --- | --- |
| Bare metal | Existing portable OS collector and host-report import | Run on the actual host; a container/guest sees its own namespace. |
| Containers | Existing Docker configuration, image/CVE/secret scanning and fixed egress probes | Selected local containers/images or imported evidence; no arbitrary container commands. |
| Hyper-V | Read-only `Get-VM`, firmware, security, processor and network metadata | Requires Hyper-V module, permissions and permission to run the bundled PowerShell script. |
| VMware | Workstation/Fusion `vmrun list` and read-only inspection of returned VMX files; manual VMX import | Live discovery lists running VMs. ESXi/vCenter is not connected. |
| VirtualBox | `VBoxManage list vms` and `showvminfo --machinereadable` | Requires the CLI on the hypervisor host. |
| KVM/libvirt | `virsh --readonly --connect qemu:///system` list/dumpxml; domain XML import | Local libvirt host; no SSH login or arbitrary remote shell. |
| Proxmox VE | Authenticated HTTPS GETs for QEMU VM inventory and configuration | `PVE_TOKEN` or another named environment variable contains `USER@REALM!TOKENID=SECRET`. Use a view-only token and trusted certificate. LXC remains a container assessment. |

VM review includes available secure-boot/vTPM evidence, clipboard/drag-and-drop isolation, shared folders, remote-console exposure, bridged networking, passthrough, nested virtualization, memory/CPU and recovery metadata. Missing/unsupported fields remain unknown. It does not boot guests, mount disks, log into guests, perform hypervisor escapes or establish guest OS patching. Run `collector.py` inside a guest for that layer.

**Local Windows finding:** PowerShell script execution is disabled on this computer. That blocks the Hyper-V and authentication-event `.ps1` collectors. The app does not change that policy; an administrator can review/sign the scripts under the organization's execution policy. Configuration imports and the other collectors remain usable when their requirements are met. No live VMware, VirtualBox, libvirt or Proxmox target was supplied for verification.

### Live behavior and AI performance

Choose **Live behavior & performance**, enter scoped folders, select optional entropy/authentication sampling, then **Turn on & open live dashboard**. A new tab opens at `/monitor`. **Turn off** stops collection. Monitoring does not auto-start after an app restart.

- Native filesystem create/modify/delete/move events, rapid changes across many files, bulk renames, changes to SSH/admin configuration and deviations from a rolling activity baseline.
- Possible mass-encryption alerts require a file-change burst plus observed entropy increases or suspicious extension patterns. Optional entropy reads sample only the first 4 KiB in memory; existing baselines and sampling budgets limit coverage. No actual encryption or ransomware execution is used for tests.
- Available Windows Security/OpenSSH or Linux auth.log/secure event classes: authentication failures, administrative logons, explicit credential use, group changes and sudo requests. SSH/admin TCP connections are shown separately and do not prove login success. Access failures and gaps remain visible; journald-only/macOS unified logs require another collector.
- CPU, RAM, disk/network rates, AI-related process metadata, NVIDIA utilization/VRAM/temperature/power, and a live CPU/RAM chart.
- Observed gateway model/provider, requests, errors, input/output tokens, usage coverage, latency, p95 latency and Ollama generation tokens/second. Usage absent from the provider remains unknown. Buffered gateway calls cannot measure time to first token.
- Optional read-only Ollama loaded-model/context/quantization/VRAM inventory and vLLM running/queued requests, token-counter rates, cache usage, lifetime latency and time-to-first-token means.

The watcher is a supervised child process. It has bounded queues and retains up to 20 minutes of performance samples, 1,000 events and 200 alerts in memory; the browser returns the latest 200 events. Redacted alert rule IDs also enter the violations store. It is a heuristic detector, not an OS-wide EDR, actor attribution system or ransomware prevention engine. Native/network filesystem notification gaps can occur.

### Red team and regression corpus

The new `agent-regression-1.0.0` corpus contains **32 cases across eight families and four carriers**. It supplements the existing 8 fixed tests and 240 generated boundary cases. Families cover injection, forbidden deletion/email/payment tool proposals, chained privileges, synthetic exfiltration, memory poisoning, agent impersonation, tool-description poisoning and jailbreaks. Carriers represent document, web-page, email and tool-result text. Direct probes also exist in the 240-case suite.

The harness sends tool schemas to an Ollama or OpenAI-compatible endpoint but **intercepts every proposed tool action**. It uses a fresh synthetic canary and a test system policy. Memory poisoning reloads a virtual record in a second invocation; privilege-chain cases can make a second invocation with a tainted synthetic tool result. No external memory/vector-store writes, production tools, arbitrary code or native Hermes/Paperclip orchestration are executed. Carrier text is not a complete file/browser/mail ingestion test. A refusal does not prove tool capability or semantic safety. Failures/unavailable inference remain unknown.

Create an exact endpoint/model engagement in **Agent red team & scope**. The app signs it with a local HMAC, sets an expiry of 1–168 hours and checks it before endpoint validation, expanded red-team and agent-harness jobs. Production scopes need a separate explicit approval phrase. The local console is the approval authority; this is not a multi-person identity service or external legal signature. The sandbox is an intercepted-tool harness, not a hardened OS sandbox for arbitrary programs. Existing scanner subprocesses remain bounded workers; no target-provided commands are executed by this harness.

Each new probe carries OWASP LLM 2025, OWASP Agentic and MITRE ATLAS mappings. Existing endpoint/MCP report rows have assessment-family tags with an explicit triage caveat. Mappings are guidance, not proof that an entire framework requirement was tested.

### Blue team, encrypted audit and incident response

**Full payload capture follows the requested opt-in policy.** It is off until you supply a key locally and enable it. Set an environment variable such as `RAYI_AUDIT_KEY` to a base64-encoded, randomly generated **32-byte** key through your local secret manager or launcher environment. Restart the app so it inherits the variable, then enable capture in **Blue team operations**. The form accepts the variable's name, never the key. Keep the key outside the app's data/bundle and preserve old keys when rotating them. The app does not create or supply the capture key for you.

- The separate `.data/agent-audit/ledger.sqlite` records metadata and SHA-256 payload hashes by default. Full prompts, parameters and results use AES-256-GCM with a fresh nonce and authenticated record metadata. Plaintext payloads are not written to this ledger. Hashes can still reveal equality and may be guessable for low-entropy data.
- HMAC-chained records and verification detect alteration; externally retained anchors can detect truncation. A host administrator who possesses the separate integrity key can rewrite the ledger. This is tamper-evident, not tamper-proof. The ledger has a 100,000-record hard limit and fails closed when required audit writes fail.
- The dashboard exports recent metadata plus the chain anchor. `audit_export.py --data-dir <app-data-folder> --output <new-file.ndjson>` exports the **complete ciphertext ledger** without copying keys. It refuses overwrite and refuses to attest a broken chain. Preserve the ledger and integrity key under restricted permissions for forensic work.
- Gateway requests, input/output decisions, tool parameters/results and assessment jobs are audited with trace IDs. Clients may propagate a valid `X-Trace-ID`. Coverage is routed/instrumented calls, not every action of unrelated agents.
- Context policies restrict trusted task-token roles and declared data sensitivity. High-impact tool names and optionally every production route action require a five-minute, exact-request, single-use approval. A reviewer must check the originating payload and its displayed hash. Inspection and tool allowlists still apply after approval.
- Scoped tokens identify route, agent, task, role, sensitivity and tool names, expire in 1–1,440 minutes and store only hashes. Issuance/rotation revokes a selected predecessor; `/<kind>/<routeId>/token/rotate` supports client renewal. `agent_client.py` automatically rotates a valid scoped token within five minutes of expiry. Direct provider API keys are not rotated. Bootstrap route tokens expire after one hour; legacy tokens without expiry need reissuing.
- Behavioral baselines alert on new tools/domains after warm-up, bulk read patterns and token/cost spikes. Cost requires configured prices and actual provider usage. These are bounded in-memory baselines, reset at restart.
- Incident actions quarantine a gateway route, revoke its gateway tokens and preserve evidence with an audit anchor. They do not kill external processes, revoke provider-owned credentials or affect bypass connections.
- Managed memory stores encrypted JSON snapshots using the supplied key, retains earlier snapshots and rolls back the app-managed pointer. External agents can read their authorized state through `/agent/<routeId>/memory/read` with `memory.read` permitted by both task token and route policy. Native agent/vector databases are not modified.

### Purple team, AI-BOM and CI

Agent-harness, expanded red-team and fixed boundary-test failures automatically create remediation records containing a synthetic guardrail regression input, a detection proposal and a retest configuration (one case for the agent harness; the configured suite for the legacy boundary modes). Running a guardrail test evaluates the current policy; it does not silently install a blocking rule. After a fix, a passing model retest closes the finding and records time to fix. Unknown outcomes do not resolve findings.

The posture table shows registered asset exposure targets, the existing transparent risk rubric, allowed privileged-tool count, open harness findings and mean hours to fix. AI-BOM exports registered models, agents, MCP descriptor pins, policy prompts, routes and monitor references. Accepting a baseline enables hash-based inventory-drift comparison; model-file drift remains the integrity monitor's responsibility.

`security_ci.py --config <exported-ci-config.json> --data-dir <trusted-app-data-folder> --output <report.json>` replays the selected corpus and exits **0 only for a complete all-pass run**, 1 for observed violations or incomplete/unknown tests, and 2 for scope/configuration/runtime errors. Use a trusted self-hosted runner with the signed engagement store; never put its integrity key or credentials in a repository. Use `keyEnv` for model credentials. Install this command as a required pipeline check on deployment/model/prompt changes. The app does not modify an existing pipeline for you.

Governance exports link controls/evidence to NIST AI RMF functions and ISO/IEC 42001 / EU AI Act topics. These are indicative crosswalks, not clause-by-clause assessments, legal applicability determinations or compliance certification. Owner, organizational and legal evidence is still required.

### Ten global malware intelligence sources

The app links ten curated major resources, not a ranked market top ten. **VirusTotal, MalwareBazaar and CIRCL hashlookup** have integrated SHA-256 query adapters. The remaining seven use their own external search/account portals. Choose a hash or local file (up to 2 GB), then explicitly select providers and confirm hash sharing. No binary is uploaded, downloaded or executed. Provider errors, missing keys, quotas and unknown hashes never produce a clean verdict. API keys stay in `VT_API_KEY` / `MALWAREBAZAAR_API_KEY`; CIRCL needs no configured key. A local 16-second per-source interval bounds repeated queries. Commercial usage terms may require a paid agreement.

- [VirusTotal](https://www.virustotal.com/gui/) — Multi-engine file reputation; Hash API.
- [MalwareBazaar](https://bazaar.abuse.ch/) — Malware sample hash intelligence; Hash API.
- [OPSWAT MetaDefender](https://metadefender.com/) — Multi-engine reputation and analysis; External search / account portal.
- [Hybrid Analysis](https://hybrid-analysis.com/) — Public sandbox reports; External search / account portal.
- [Triage](https://tria.ge/) — Sandbox reports and sample intelligence; External search / account portal.
- [ANY.RUN](https://any.run/) — Interactive sandbox and threat intelligence; External search / account portal.
- [Joe Sandbox](https://www.joesandbox.com/) — Behavioral malware analysis reports; External search / account portal.
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) — Malware families, references and signatures; External search / account portal.
- [FileScan.IO](https://www.filescan.io/) — File analysis and public reports; External search / account portal.
- [CIRCL hashlookup](https://hashlookup.circl.lu/) — Known-file hash database; not a malware verdict; Hash API.

### Reference sources

- [OWASP LLM Top 10, 2025 taxonomy](https://genai.owasp.org/llm-top-10/) and [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
- [MITRE ATLAS](https://atlas.mitre.org/techniques/AML.T0051), [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework), [ISO/IEC 42001](https://www.iso.org/standard/42001), [EU AI Act primary text](https://eur-lex.europa.eu/eli/reg/2024/1689/oj).
- [Proxmox API authentication](https://pve.proxmox.com/wiki/Proxmox_VE_API), [Ollama loaded-model metrics](https://docs.ollama.com/api/ps), [vLLM metrics](https://docs.vllm.ai/en/latest/usage/metrics/), [psutil](https://psutil.readthedocs.io/stable/) and [watchdog](https://python-watchdog.readthedocs.io/en/stable/quickstart.html).
- [VirusTotal file reports](https://docs.virustotal.com/reference/file-info), [MalwareBazaar hash queries and terms](https://bazaar.abuse.ch/api/) and [CIRCL hashlookup](https://hashlookup.circl.lu/).


## Local security workspace retained from version 2.0

### Assets, policy checks and risk prioritization

- Persistent inventory for models, agents, MCP servers and repositories. Discover supported agent instruction files and MCP JSON/Codex TOML under explicitly selected local roots, or discover the models served by a selected Ollama/OpenAI-compatible endpoint. Up to 10 roots and 5,000 traversal entries; no agent processes or stdio MCP commands are launched.
- Register named assets, assign accountable owners and reusable policies, and link matching assessment evidence. Report target and model must match exactly. Discovered configuration is distinct from a verified running service.
- Each asset displays security, privacy, safety, gateway, transport, upstream-authentication and assessment-freshness evidence. A policy assignment alone is not enforcement.
- Transparent **0–100 risk prioritization index**: 60% of weighted control deficits plus up to 40 finding points. Unknown controls contribute half their weight; missing/stale/incomplete assessment adds 20. Fresh attention findings add 20 each and review findings 5 each, capped at 40. The UI exposes weights, evidence coverage and components. This is a documented prioritization rubric, not CVSS, a probability, or a safety certificate.
- Registry export and SQLite persistence. No cloud-account inventory or automatic public-network discovery.

### MCP server and tool inspection

- Read-only HTTP MCP initialization and tool enumeration, JSON or bounded SSE responses, up to 500 tools and five inventory pages. No tools invoked by the scanner.
- Review tool descriptions, argument schemas, destructive/read-only annotations, injection and credential indicators. Retains descriptor hashes for registered servers so the gateway can reject tool-definition changes until reviewed and rescanned.
- Local stdio MCP entries are discovered from configuration, not launched. Runtime proxy supports a conservative subset of JSON Schema; unsupported constraints fail closed. MCP resources, prompts, sampling and resumable SSE are not proxied.

### Expanded red teaming

- **240 generated test cases across 24 test families and 10 delivery transformations.** The first 24 cases cover all families; seeded ordering makes runs repeatable. Adaptive mode prioritizes variants after observed failures.
- Families test synthetic confidentiality, hierarchy overrides, encoded/indirect injection, role/authority spoofing and simulated tool claims. Detectors check exact synthetic canaries and selected encodings/markers; real secrets are not supplied.
- Choose 24, 80 or all 240 cases, a 1–30 minute budget, a returned model identity and an authorized endpoint. Multi-turn cases use the actual preceding response. Cancellation, inconclusive responses, completed case/family coverage and inference-call counts are reported.
- This is **240 cases, not 240 independently validated attack techniques**. It does not provide a comprehensive semantic safety benchmark or prove a model safe. Optional inference endpoints may incur charges.

### Runtime protection and model-specific guardrails

- Optional authenticated local gateway at `http://127.0.0.1:8766`. Register an asset, assign a policy, create its route, save the one-time client token, start the gateway, and configure the client to use the returned URL. Bootstrap tokens expire after one hour and only their hashes are persisted. Recreating a route rotates the token. Use Blue team operations for scoped task tokens and revocation.
- **Model input and output:** security/injection patterns, credential and personal-data patterns, narrow safety patterns, custom blocked phrases, policy system instructions, character and output-token caps. Per-model routes restrict the requested model. Buffered OpenAI-compatible chat completions connect to Ollama or OpenAI-compatible upstreams. Streaming, multimodal inputs and model-native tool calling are unsupported.
- **MCP arguments and results:** authenticated route, exact tool allowlist, conservative schema validation, freshly checked pinned tool descriptors, argument inspection before invocation, result inspection before release. Blocking a result cannot undo a tool's side effects.
- **Agent preflight:** an authenticated action-check endpoint returns allow/block/monitor decisions for an agent to honor. It does not execute the action and cannot force an unintegrated agent to comply.
- **Resource and destination controls:** eight concurrent gateway handlers, 200 KB bodies, per-route requests/minute and gateway-session action budgets, plus an optional exact-domain filter for visible HTTP(S) URLs. The domain filter is not an OS firewall or a guarantee about a tool's network behavior.
- Policies support block or observe mode for text patterns. Size and tool/domain constraints stay blocking in observe mode. An empty tool allowlist denies all tools; an empty domain list does not restrict destinations. Upstream secrets are environment-variable references, not saved keys; remote credential forwarding requires HTTPS.
- **Violations dashboard:** filter allow/block/monitor/alert/error events and export the latest 1,000. SQLite retains the latest 10,000 decisions without request/response bodies, arguments or bearer keys.
- Gateway is stopped after app restart until started explicitly; routes/policies persist. Scheduled integrity monitors resume when the app runs. Direct traffic, external apps, unproxied tools and other containers are outside gateway coverage. Pattern matching has false positives and bypasses; this is not comprehensive safety, privacy or host protection.

## The ten deployment and containment additions

| Addition | Built capability | Evidence boundary |
| --- | --- | --- |
| **1. Inference API exposure** | Ollama, vLLM, LM Studio, ComfyUI and Gradio endpoint checks; local wildcard-listener evidence; unauthenticated GET/HEAD responses; wildcard CORS; Ollama binary version against CVE-2024-37032's recorded pre-0.1.34 range. | Never calls model-changing pull/push/create/delete operations. Management-method authorization and proxy configuration remain unknown when read-only evidence cannot establish them. A loopback scan does not establish public exposure. One historic server advisory is not a complete CVE feed. |
| **2. Outside-in VPS probe** | Portable `remote_probe.py` for a second machine; one authorized public hostname/IP, up to 20 selected TCP ports and seven read-only AI-service fingerprints per open port; TLS option and JSON import into reports. | User runs it from the external machine. This installation has no second-machine location or VPS target configured. Fingerprints are candidates; imported evidence/vantage are not authenticated. No network ranges, exploitation or nuclei template execution. |
| **3. AI web UI audit** | Selected configuration checks for Open WebUI signup/auth/default-secret indicators, Gradio share tunnels, empty Jupyter tokens, ComfyUI Manager presence and wildcard binding; optional read-only Open WebUI SQLite admin count. | Saved files may differ from effective or database-persisted settings. Account names and credentials are omitted. A manager's presence alone does not prove internet exposure. |
| **4. GPU stack audit** | NVIDIA driver/toolkit version evidence, historic CVE-2024-0132 and CVE-2025-23266 toolkit boundaries, Linux `/dev/nvidia*` permissions/owners, MIG and MPS evidence, multi-tenant review. | Includes CDI/crun applicability caveats. No GPU escape attempt or current comprehensive driver CVE feed. MIG/MPS presence does not establish tenant isolation; unavailable tools remain unknown. |
| **5. RAG/vector security** | Read-only Qdrant, Chroma, Weaviate and Milvus endpoint checks; selected knowledge-source scanning for injection, hidden HTML and zero-width text; PDF extraction plus invisible/near-white text indicators with pypdf. | Does not write collections or prove write permissions. Milvus POST-only inventory remains unknown. PDF rendering/OCR, transparency and complex backgrounds are not fully analyzed; white text assumes a light page. |
| **6. Honeytokens and canaries** | Creates a new uniquely named `.env.canary-*` file with a fake key and local callback URL; matching routed content or callback hits create alerts. Existing files are not overwritten. | No real credentials or external Thinkst account is created. Local callback requires the gateway running and reachable as loopback. A hit proves an observation/callback, not by itself that data left the server. |
| **7. Integrity and drift** | Persistent SHA-256 baselines and repeated comparisons for a selected model store/folder/file, including Ollama manifests/blobs, GGUF, safetensors, Modelfiles and prompts; optional fixed-prompt response hashes on a schedule; official model-signing Sigstore verification with expected identity/issuer. | Opt-in schedules run while this app is running. Baselines remain unchanged after alerts; incomplete scans cannot claim deletions. Behavior changes may be nondeterminism, not a swapped model. Signature verification needs a supplied signature and trusted identity; verification does not establish behavioral safety. |
| **8. Secrets/PII at rest** | Redacted built-in patterns for logs, traces, prompt caches and chat exports; bounded read-only SQLite sampling; optional real Gitleaks directory scan. | Does not verify credentials or upload source content. Built-in scan skips text files above 8 MB and samples 20 tables/1,000 rows per SQLite table. Gitleaks has a 180-second budget; findings retain locations/rule IDs, not values. Encrypted/binary caches need other extraction. |
| **9. Egress lockdown test** | Fixed `docker exec` Python probe inside an exact running container: selected destination TCP connection, DNS resolution, and TCP reachability of `169.254.169.254:80`. | Requires existing Python3 in that container. No metadata HTTP request, token or credential retrieval. Reports successful reachability; failure can reflect service/DNS failure and does not prove all egress is blocked. No policies are changed. |
| **10. Resource abuse limits** | Selected-file evidence for `num_ctx`/maximum model length, `OLLAMA_MAX_QUEUE`, `OLLAMA_NUM_PARALLEL`, proxy rate limiting and container memory settings; existing Docker assessment inspects actual configured memory/PID/CPU limits. Gateway adds input/output/rate/concurrency budgets. | Static setting presence needs effective-configuration and workload-capacity review. No stress test or automatic resizing. Gateway limits affect only routed requests. |

### Run a probe from another machine

Copy the app's `remote_probe.py` to a machine outside the VPS network, then replace the illustrative hostname and ports with the authorized target:

```sh
python3 remote_probe.py --target YOUR_VPS_HOST --ports 443,11434,8000,7860,8188 --tls-ports 443 --authorized --output outside-in.json
```

Import the resulting JSON on **Deployment checks → Outside-in probe**. `--allow-private` is only for a clearly labelled internal test, which is not outside-in internet evidence.

### Record an integrity baseline

On **Integrity & canaries**, select a folder or file and record a baseline, then enable its schedule. File baselines hash full files, up to 10,000 entries, 128 GB per file, 256 GB total and a 120-second snapshot budget. Incomplete initial snapshots are rejected. Choose a narrower folder if the budget is exceeded. Read-only model stores are suitable; pause model downloads/writes for a consistent baseline. Existing folder exclusions and link skipping limit coverage.

Fixed-prompt monitors accept one to five short prompts and save only normalized response digests. They require endpoint authorization and can generate recurring inference costs. Intervals range from one minute to seven days, checked by the in-app scheduler about every ten seconds; long checks can delay later checks. There is no separate OS service, email notification or unattended cloud monitor. Changes appear in the app's monitor results and event dashboard.

### Optional audit engines

Run `Install-Audit-Tools.bat` on Windows or `python3 install_audit_tools.py` in the app folder. It creates `.audit-runtime` with **pypdf 6.19.0**, **model-signing 1.1.1**, **watchdog 6.0.0**, **psutil 7.2.2** and **cryptography 50.0.2**, then installs **Gitleaks 8.30.1** into `.tools/gitleaks` using a pinned SHA-256 from the official release archive. These tools are installed in this computer's updated app. New machines need downloads. Python runtimes and downloaded binaries are excluded from the Library bundle.

Sigstore verification may contact public trust services when its explicit online option is selected. Invocation uses `model_signing verify sigstore MODEL --signature SIGNATURE --identity EXPECTED_IDENTITY --identity_provider EXPECTED_ISSUER`. This verifies a provided signature; it does not create a signing identity or attest every installed model.

Technical references: [Ollama CVE record](https://cveawg.mitre.org/api/cve/CVE-2024-37032), [NVIDIA September 2024 bulletin](https://nvidia.custhelp.com/app/answers/detail/a_id/5582), [NVIDIA July 2025 bulletin](https://nvidia.custhelp.com/app/answers/detail/a_id/5659/kw/support), [Open WebUI hardening](https://docs.openwebui.com/getting-started/advanced-topics/hardening/), [model-signing](https://github.com/sigstore/model-transparency), [Gitleaks](https://github.com/gitleaks/gitleaks), [MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), and [OWASP injection prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).


## Existing assessment features retained

### Agent scanner

- **Scan agent:** one offline NVIDIA SkillSpector stage for a selected local agent-project folder. Checks supported instructions, skills, and code for injection, instruction override, exfiltration, suspicious commands, tool misuse, privilege and MCP-permission patterns, static behavior, and YARA signatures.
- **Deep scan:** combines four stages: SkillSpector, source-code heuristics, dependencies plus exposure review, and model-file/hash inventory.
- Deep mode offers public OSV/CISA lookups and optional local Ollama semantic review. **The public lookup checkbox is enabled by default in the UI.** Clear it for offline work. Semantic review is opt-in.
- Each stage preserves its own findings, evidence, coverage, and limits. A failed stage leaves completed stages available and marks the aggregate incomplete. Cancellation retains completed work.
- Both modes feed the Agentic Action List. They inspect the selected project without starting its agent or invoking its tools.

### NVIDIA SkillSpector

- Real NVIDIA SkillSpector **2.12.0**, pinned to source revision `35270064e42230dbc566e4134c55b5d581355db3`.
- Inputs: absolute local folder, individual file including `SKILL.md`, ZIP, or public GitHub repository-root URL. Public download is a separate checkbox and records the scanned commit.
- Default static mode runs static, behavioral, and YARA analyzers offline. The integration disables upstream online OSV lookup in that worker; current CVEs are handled by the separate opt-in vulnerability workflow.
- Optional static plus local Ollama semantic analysis. Native mode allows loopback; Docker also supports `host.docker.internal`. No cloud semantic provider is exposed.
- Findings retain rule IDs, categories, severity, confidence, and file/line locations. Source snippets and free-text upstream payloads are omitted to reduce accidental disclosure. Unsuccessful semantic calls stay unknown/partial.
- Bounded execution and intake: 300-second wall-clock worker limit, 100-second clone timeout, a 100 MiB post-clone intake check, and up to 1,000 reported findings. The post-clone check is not a hard limit on disk use during cloning.

### AI endpoints and prompt injection

- Connect to **Ollama** or an **OpenAI-compatible** model API, including local, selected remote, and Docker-host endpoints.
- Discover available models and select an actual returned model before validation. An optional bearer key is held in memory and excluded from reports; remote bearer use requires HTTPS.
- Eight fixed synthetic tests: direct instruction override, authority impersonation, document injection, encoded canary disclosure, system-policy disclosure, multi-turn escalation, simulated tool claims, and a forbidden output marker.
- Up to nine sequential inference calls; the multi-turn case uses the actual prior response. Requests use temperature zero, a 160-token requested output bound, and a 45-second request timeout. Cancellation stops before the next test.
- TLS validation stays enabled; redirects, inherited proxies, and metadata/link-local targets are rejected. Results include synthetic responses for review. Marker checks are limited evidence, not comprehensive behavior or production-policy validation.

### Model supply chain

- Real pinned **ModelAudit 0.2.52**, running offline in a separate Python process.
- Inspects supported serialization, opcodes, metadata, and configuration for unsafe constructs without intentionally executing the model. Installed extras include HDF5, ONNX, and safetensors in the documented Python 3.12 setup.
- Optional SHA-256 comparison for a single file against a digest supplied from an independently trusted source.
- Optional dependency CVE review for a selected model repository folder.
- Missing format support remains incomplete. Full PyTorch/TensorFlow runtimes are not bundled.
- Limits include a 180-second model-analysis budget, 8 GB per file, 16 GB total, 10,000 inventory entries, and 1,000 findings; separate single-file hashing supports up to 16 GB.

### Malware in files

- Uses a real **Microsoft Defender** custom scan on Windows, or **ClamAV** where installed on Linux/macOS/Docker.
- Requests no automatic removal or quarantine. Defender uses `-DisableRemediation`; system antivirus/cloud policies still operate independently.
- Optional ClamAV signature updates download official definitions without uploading target files. Defender uses its existing update policy.
- Missing engines, stale definitions, incomplete scans, and ambiguous Defender exit status are reported as coverage gaps. ClamAV has a roughly five-minute scan budget and bounded file/expanded-container sizes.

### AI packets and protocols

- Live connection metadata using **psutil**, with optional process-ID filtering.
- Local PCAP/PCAPNG analysis using **Scapy**.
- A bounded passive capture on one selected, authorized interface: up to 15 seconds or 10,000 packets, with promiscuous mode off.
- Indicators include AI-shaped HTTP paths, provider DNS/TLS SNI, common inference ports, model-process names, and possible model-upload filenames.
- Editable trusted CIDRs define inside-to-outside traffic. Retains connection/flow metadata while omitting payloads, prompts, authorization headers, and unrelated DNS names.
- Packet import bounds: 256 MB, 25,000 packets, 3,000 flows, and 60 seconds. IP/process metadata can still be sensitive. Encrypted content, tunnels, TCP reassembly, actual firewall traversal, and definite exfiltration are outside this evidence.
- Windows live capture needs an existing Npcap installation and suitable permissions; the app does not install Npcap. Container mode sees only its own namespace.

### Container assessment

- Inputs: a selected live local Docker container, existing local Docker image, Docker/OCI image archive, or saved container evidence. Discovery lists up to 200 containers.
- Configuration evidence: configured root user, privileged mode, host namespaces, added capabilities, seccomp/LSM overrides, no-new-privileges, writable root filesystem, resource limits, devices, host/control-socket mounts, port bindings, and secret-like environment names.
- Optional active checks connect to at most eight eligible loopback/wildcard published TCP bindings of the selected running container; choose TCP, HTTP `HEAD /`, or HTTPS `HEAD /`. TLS is verified and redirects are rejected.
- Real **Trivy 0.75.0** scans image package vulnerabilities, application dependencies, secrets, and image-config secrets. Reports include available severity, fixed-version boundaries, advisory references, known-exploited enrichment, database dates, and OS end-of-life evidence. Matched secret values/snippets are discarded.
- Online mode can refresh databases and CISA KEV; offline mode reuses existing cache. Stale databases over seven days, missing data, warnings, and unsupported results keep coverage unknown.
- Local Unix sockets/Windows named pipes only. No remote TCP/SSH Docker contexts, image pulls, container start/stop, exploit payloads, or escape attempts in this assessment. The separate opt-in egress test uses a fixed in-container Python probe.
- `container_collect.py` exports reduced configuration evidence for another host; `docker image save` provides an archive for local inspection. Imported evidence is unauthenticated. Image scans do not include mounted volumes or the writable container layer.

### CVEs and exposure

- Checks a folder, supported manifest, CycloneDX JSON SBOM, or an exact manually entered package/version against **OSV**. Adds **CISA Known Exploited Vulnerabilities** evidence when available.
- Inventory support includes pinned requirements/constraints, npm package-lock v1–v3 and shrinkwrap, Pipfile.lock, Poetry/uv/Cargo locks, and go.sum. Exact direct package.json and PEP 621 pyproject versions are supported with limited-transitive-coverage notes.
- CycloneDX versioned package URLs cover PyPI, npm, Go, Maven, crates.io, RubyGems, NuGet, and Packagist. Ranges, unresolved identities, and unsupported sources remain unknown; no package manager is executed to construct inventory.
- Advisory records retain available CVE aliases, source links, severity/CVSS, dates, location, and provider-listed fix boundaries. Counts are advisory matches, not necessarily unique CVEs.
- Online requests send package ecosystem/name/version and pagination tokens to OSV; source, paths, secrets, and model weights remain local. CISA catalog downloads contain no inventory.
- Offline mode can reuse a previously exported assessment for exact saved package/version queries. Missing, incomplete, invalid-dated, or older-than-seven-day evidence is unknown.
- Optional 12-rule source exposure review combines the eight code rules with download-to-shell, authentication-disable, privileged-container/socket, and dynamic-execution indicators. File-only inputs do not expand scope to their parent folder.
- Bounded to 200 distinct package/version pairs, four concurrent requests, 180 seconds for OSV, four pages and 50 advisories per package, and 1,500 report findings. These are version matches and heuristics; they do not discover undisclosed zero-days or prove exploitation.

### Code and model inventory

- Eight lightweight code heuristics: possible credentials, private keys, disabled TLS, unsafe deserialization, shell execution, remote model code, debug mode, and broad CORS.
- Code reports give locations without possible secret contents and inventory dependency manifests. Separate CVE assessment performs actual advisory lookups.
- Model inventory identifies recognized formats, Python files, executable serialization risks, and custom-code configuration references without loading weights.
- Model inventory hashes files up to 32 MiB within a 128 MiB total hashing budget and examines at most 2,000 entries. Larger weights are inventoried without hashes. This differs from the dedicated ModelAudit workflow and its optional larger single-file hash check.
- Code traversal skips symlinks, common build/dependency folders, unsupported types, and files over 1 MiB; bounds include 5,000 traversed entries and approximately 500 findings.

### Host security

- **Windows:** firewall profiles, Defender/antivirus evidence, system-drive encryption, Secure Boot, UAC, Remote Desktop, SMBv1 server, update history, advertising ID, and location permission.
- **macOS:** SIP, Gatekeeper, FileVault, application firewall, and listening services.
- **Linux:** supported firewall frontend, listeners, storage evidence, and accessible effective SSH settings.
- Missing privileges/tools give unknown results. Evidence collected in a container describes that container.
- Portable remote-host collection: run `python collector.py --output host-report.json` on the actual target host, then import that UTF-8 report through **Host security**. No unattended remote shell or saved SSH passwords are implemented.

### Agentic Action List

- Generate from the current report or up to 30 session reports using **Apply recommendations** or the dedicated page.
- Creates P0/P1/P2 tasks with target/model identity, source evidence, recommended work, verification steps, acceptance checks, and rollback planning. Critical/known-exploited attention items are prioritized; unknown coverage becomes investigation work.
- Omits passed checks, deduplicates exact repeated findings on the same target/model, and records truncation above 1,000 tasks.
- Copy instructions, export Markdown, or export structured JSON. Generation is deterministic and uses no LLM/cloud account.
- Includes the existing editable preference “Astra 6.1 (preferred by you, if available)” and allows other capable agents. This is a preference label, not a claim that a model exists or is available.
- **No fixes are automatically applied and no agent is dispatched.** Task state begins as `todo`; completion needs fresh verification evidence.

### Reports and local application controls

- Overview metrics, progress display, bounded cancellation for supported jobs, and browser session report history.
- Evidence categories: attention, review, unknown, and passed check. Expandable evidence, status filters, inventories, dependencies, stage coverage, and limitations.
- Export full JSON or a standalone HTML report for reading/printing. Action lists have their own Markdown/JSON exports.
- Browser session history is in memory. Refresh retains only the latest server result; restarting the server clears it. Export what needs retention.
- Loopback-oriented local server, exact Host/Origin checks, transient app token for POST requests, a 2 MB request limit, and restrictive response headers. No telemetry or cloud account is required by the console.
- Portable Windows/macOS/Linux launchers, Docker configuration, local collectors, pinned scanner installers, bundled wheels, license notices, and existing automated tests are included in the source snapshot.

## Verification and remaining limits

Version 3.0.0 source was installed and tested on native Windows on October 4, 2026. The original application source was backed up before the update. Existing SkillSpector, Trivy, ModelAudit and antivirus integrations are retained. The launcher now prefers the optional audit runtime when present so encrypted capture is supported. Source deployment and restart status are recorded in VERIFICATION.md.

See `VERIFICATION.md` in the Library bundle for the exact tests and live UI checks performed for this release. Synthetic upstream tests verify that blocked model inputs are not forwarded, sensitive outputs are withheld, MCP descriptor changes prevent tool calls, and integrity drift preserves the original baseline. Real local fixtures exercise PDF concealment indicators and redacted Gitleaks results. The Sigstore CLI/options are checked; no user-provided signed model was available for an end-to-end trusted signature verification.

No VPS, second-machine probe, production GPU/container, actual model endpoint, or user knowledge base was supplied for the ten new assessment modes. Their integrations and bounded behavior have been tested with fixtures where documented; this is not an assessment of an actual VPS. Docker and macOS/Linux deployment of this release still need target-specific testing.

The app provides bounded assessments and opt-in monitoring/enforcement within explicit scope. It does not establish absence of learned backdoors, poisoning, malware or undisclosed zero-days, and does not perform automatic remediation, a complete penetration test, or compliance certification. A passing check means only the stated check passed with available evidence.

Persistence: assets, policies, route token hashes, canaries, integrity baselines and decision metadata live in `.data/security.db` (Docker `/data/security.db`). Protect this database and exported security evidence. Scan report history remains transient except for exports and linked summary counts. Gateway client tokens are shown only when created; upstream credentials are environment references. App and gateway are local single-user services, not multi-user administrative portals.

## Source map

| Files in the companion app | Responsibility |
| --- | --- |
| `app.py`, `index.html`, `launch.py` | HTTP API, browser console, startup |
| `agent_scanner.py` | Focused/deep orchestration |
| `skillspector_integration.py`, `skillspector_worker.py` | SkillSpector integration and offline worker |
| `engine.py` | Endpoint probes, code checks, lightweight model inventory |
| `vulnerabilities.py` | Dependency inventory, OSV, CISA KEV, exposure heuristics |
| `containers.py`, `container_collect.py` | Docker configuration, scoped probes, Trivy, portable evidence |
| `model_tools.py`, `model_worker.py` | ModelAudit and antivirus integration |
| `traffic.py`, `packet_worker.py` | Connection and packet evidence |
| `collector.py`, `scan.ps1` | Platform host checks |
| `actions.py` | Deterministic action-list generation |
| `security_store.py`, `asset_registry.py` | Durable registry, policies, evidence and scoring |
| `guardrails.py`, `runtime_gateway.py`, `mcp_security.py` | Runtime inspection, route authentication, MCP inventory/pinning |
| `redteam.py` | Generated boundary-test catalogue and adaptive execution |
| `deployment_audits.py`, `pdf_source_worker.py` | Deployment, GPU, RAG, data-at-rest, egress and signature checks |
| `remote_probe.py` | Portable outside-in probe |
| `integrity_monitor.py` | Baselines, scheduled drift checks and canaries |
| `workspace.js` | New asset, protection, deployment and integrity screens |
| `test_*.py` | Regression and new control/engine tests |

The bundle contains the updated v3.0 source. `MANIFEST-SHA256.json` records each included file for integrity comparison.


## Passwords, firewall shortcut and post-quantum readiness

The October 4, 2026 update adds **Scan my firewall**, **Password generator**, **Post-quantum encryption**, and **U.S. government guidance**. These sections preserve the app's evidence-based reporting and Trademark of Ray-i Consulting LLC branding.

### Scan my firewall

The button appears on Overview and Host security. It starts the existing native, read-only host assessment. Windows reports Domain, Private and Public firewall profile status. macOS reports application-firewall status; Linux uses supported UFW/firewalld evidence, with missing evidence marked unknown. The report also contains related host controls. This is not a firewall rule-set audit, perimeter penetration test, proof of blocked ports, or a firewall configuration change. A scan in Docker describes the container namespace, not the physical host.

### Strong password generator

- Browser-only Web Crypto CSPRNG with rejection sampling to avoid modulo bias. No Math.random fallback.
- Random passwords: 8–256 characters, 24 by default; uppercase, lowercase, digits and symbols; optional group requirements, exclusions and look-alike filtering.
- Presets: 24-character balanced, 64-character long, 32-character alphanumeric and 64-character hexadecimal.
- Random passphrases: 6–16 independently selected words, 8 by default, from all 7,776 words in the bundled [EFF long wordlist](https://www.eff.org/dice). Separator choice, optional capitalization and four random trailing digits. Word repetitions are allowed.
- Batch generation of 1–20 values; reveal/hide, individual copy and copy-all controls.
- Entropy estimates count allowed outputs, including the selected group constraints. They are not crack-time predictions. Capitalization of every word adds no claimed randomness.
- Generated values are never sent to the server, model, audit log or browser storage. They clear on leaving the section, tab hiding, page exit, changes to rules or the selected 1-/5-minute timer. Clipboard contents are not automatically erased. Browser memory erasure cannot be guaranteed.

Use a password manager, a unique generated value per account, and appropriate MFA. The tool does not set account passwords or certify an authentication system against government standards. EFF attribution and license details are in `licenses/EFF-WORDLIST.md`.

### Post-quantum key generation and enablement

[NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) specifies ML-KEM for key establishment. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) specifies ML-DSA signatures; [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) specifies SLH-DSA signatures. A KEM alone does not encrypt a file or authenticate a peer; signatures do not provide confidentiality. Integration must follow an appropriate supported protocol, with guidance such as [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final).

The **Local evaluation** profile generates ML-KEM-768, ML-KEM-1024, ML-DSA-65 or ML-DSA-87 keys through Node.js 24.7+ / OpenSSL. It performs a real encapsulation/decapsulation or signature/verification consistency test. It downloads a public SPKI PEM and an encrypted private-key bundle. SLH-DSA is explained and linked but is not a generated key type.

The private PKCS#8 DER is protected with AES-256-GCM, a fresh 32-byte salt and 12-byte nonce, and PBKDF2-HMAC-SHA256 at 600,000 iterations. A unique 24+ character protection passphrase is required. The JSON bundle is an app-specific evaluation format, not a standardized or FIPS-validated key container. Authentication binds algorithm, public key and creation time. Key recovery verifies the public key and its SHA-256 fingerprint. Never reuse the disposable values from testing.

The key worker receives the passphrase over its local stdin, not a command-line argument. Neither the passphrase, private key nor encrypted bundle is written to the app database/audit log, including when full audit capture is enabled. Only a nonsecret metadata record is audited. The browser keeps the encrypted result until cleared or the user leaves the section/tab. No provider, AI endpoint or external crypto service is called.

Verify recovery without exporting a plaintext private key:

```text
python pqc_keytool.py path-to-key-bundle.json
```

The terminal prompts for the protection passphrase without echoing it. An explicit `--output protected-directory/private.pem` recovers an **unencrypted** PKCS#8 PEM and refuses to overwrite existing files. POSIX file mode is 0600; on Windows, restrict the destination directory ACL yourself. Preserve the bundle and passphrase separately. Losing either prevents recovery.

**Government deployment is blocked by default and by the API.** This app has no verified CMVP/KMS/HSM integration. The installed runtime reports Node v24.21.0, OpenSSL 3.5.8 and FIPS mode off. A FIPS runtime flag alone would still not establish module validation. Confirm the exact [CMVP certificate, operational environment, Security Policy and approved services](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/FAQs), plus agency and system authorization. Local evaluation keys must not be represented as approved government keys.

The **Generate setup guide** button creates a local Markdown plan for network/API transport, stored models/backups, signing, or national security systems. It explains inventory, supported products/protocols, authenticated key distribution, validated modules, testing, recovery, rollout and monitoring. It does not modify TLS/SSH, encrypt user files, turn on disk encryption, install a certificate or deploy a key. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) covers civilian federal PQC migration and excludes national security systems; consult [NSA/CNSS guidance](https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/) for that separate scope.

On another host, install a supported Node runtime from its official distribution and make `node` available to the app process, or set `SHA_PQC_NODE` to an absolute executable path before launch. The Docker image does not automatically install Node for PQ key generation; provide it explicitly. Password generation and reference guidance have no Node dependency.

### U.S. government AI, security and privacy evidence workbench

The app bundles a **29-topic, dated official-source catalogue**, reviewed October 4, 2026. It distinguishes final standards, drafts, voluntary frameworks, federal agency policy, contractual obligations and sector-specific law. Topics include:

- NIST PQC standards, SP 800-227, FIPS 140-3/CMVP, draft IR 8547 and NSA CNSA/CNSS scope.
- AI RMF, Generative AI Profile, SSDF AI profile, OMB M-25-21 and M-25-22, M-26-04, M-26-05, M-26-14 and M-26-15, plus NSPM-11.
- FISMA/FIPS 199–200, SP 800-53, FedRAMP, CUI/SP 800-171 and applicable DFARS/CMMC requirements.
- Privacy Act, E-Government Act PIAs, NIST Privacy Framework, HIPAA, GLBA, COPPA and FERPA.

Search and filter by topic. Each entry states applicability, evidence to collect, official source and the app's actual coverage. Record an owner, evidence reference/gap and review status. “Evidence recorded” and “not applicable” require an owner and rationale; neither becomes an automatic compliance verdict. Review counts count records, not compliant controls. Reviews stay in the current tab until exported as JSON. Imported notes are labeled user-supplied and cannot replace the bundled source definitions or certify compliance.

This is a selected reference set, **not all U.S. law and not a 100% compliance claim**. Agency, state, local, sector, civil-rights, contract and classified-system requirements may add obligations. Applicability, current requirements and deployment authorization require responsible officials. A source review date is not ongoing legal monitoring. The catalogue correctly labels IR 8547 as draft and identifies superseded OMB policies, including M-24-10/M-24-18, M-22-18/M-23-16 and M-21-31.

### Verification for these additions

143 Python regression tests passed; 11 password-generation security checks and 14 native PQ cryptography checks passed separately. HTTP checks verified Origin/token enforcement and refusal of the government profile. Browser checks exercised password/passphrase controls, secret clearing, runtime status, protected key generation/download/recovery, setup-guide download, evidence review validation/export and the firewall button. The Windows collector reported all three firewall profiles on in the test host report; this does not prove the adequacy of its rules. No runtime FIPS certification, real government deployment or exhaustive legal assessment was performed.

The running process at port 8765 remains v2 until the earlier restart approval is resolved. The new static password, firewall shortcut and guidance interfaces can be loaded by refreshing; the PQ worker and earlier v3 backend integrations need the installed process update activated. Full behavior was verified in an isolated v3 test instance.

## Kali in WSL on this computer

Kali Linux Rolling 2026.2 is installed as the separate `kali-linux` WSL 2 distribution. Its registered storage is `C:\Users\itsup\AppData\Local\wsl\{12cf2260-80d2-47a0-a4e8-4435899e163a}`. It remains on C: under the user's latest instruction. Ubuntu remains the default distribution at `D:\WSL\Ubuntu`; Docker Desktop's distribution remains at `D:\DockerDesktopWSL\main`.

The installation was verified by starting Kali and reading `/etc/os-release` and its WSL 2 kernel. The base Kali core and Python 3 are present; the top-ten tools bundle and Nmap were not installed as part of this setup. A move to D: returned a file-in-use error before completing, and the user then cancelled the move. The current C: registration and successful startup were rechecked.

To finish first-launch account setup, open a Windows terminal and run:

```powershell
wsl.exe --distribution kali-linux
```

Follow the local username/password prompts. No user password has been created or recorded by the assistant. Read-only verification used an explicit root invocation; that is not an agent execution account.

Kali is installed, but **the security app does not yet have a Kali command runner**. Its VM assessment and synthetic agent harness do not execute arbitrary Kali commands. The next integration would need a non-root worker, fixed command adapters, exact authorized targets, time/output limits, cancellation, audit events and human approval for high-impact operations. Scope authorization should be checked before launching a command. WSL alone is not an isolation boundary for untrusted commands, because mounted Windows drives and Windows interop can expose host resources.

WSL 2 uses Microsoft's virtualization platform underneath; it does not require managing a separate guest through Hyper-V Manager. Official references: [Kali WSL setup](https://www.kali.org/docs/wsl/wsl-preparations/) and [Microsoft WSL commands](https://learn.microsoft.com/en-us/windows/wsl/basic-commands).

## Paperclip and drive scan center

Open **Paperclip & drive scans**, then **Find agents and drives**. Enter the local Paperclip port (3100 here) and its WSL distribution (Ubuntu here). The app reads companies and agent records, discovers agents using a Hermes adapter or named Hermes, and displays their actual adapter and configured workspace. A name is not proof of adapter type. Linux home-project paths are mapped to a Windows `\\wsl.localhost\<distribution>\...` path; unsupported, missing and symlink targets remain unavailable.

Select agent workspaces and/or fixed drives, confirm target authorization, and choose **Scan selected** or **Scan all agents and drives**. Agent mode can be focused or deep; this batch always leaves public CVE lookups and semantic model calls off. Folder inspection does not start the agents. Windows fixed drives use the installed Microsoft Defender command-line scanner in custom-scan mode with remediation disabled. The current Defender mode, signature timestamp and app elevation status are displayed. No antivirus settings are changed.

The queue runs targets sequentially and shows their individual states, current progress and elapsed time. Choose a one-, four- or twelve-hour waiting limit per drive. App cancellation and drive timeout stop waiting and skip remaining targets; a Defender service scan may continue independently. Keep the app backend running. Closing/reloading the browser does not stop the server job; **Saved batch reports** retains results locally and can reopen them for the existing JSON/HTML export and action-list workflow. A process restart can interrupt a running batch; its prior checkpoint is labeled interrupted.

Reports retain at most 180 bounded findings, with omitted counts. They expose missing/failed/partial components and each drive's exit code and parsed HRESULT/detection labels. Native no-remediation detections do not appear in Defender's usual UI/history. Exit code 2 is ambiguous between unremediated detections and errors; it stays unknown when evidence does not resolve it. Localized or excess output may not be parsed. A successful command is not proof that every file is safe.

Discovery is limited to 10 companies, 200 agents per company and 64 matching agents. The authenticated selection binds to a server-held discovery snapshot that expires after 30 minutes. Only reviewed IDs from that snapshot can be submitted. Discovery uses direct loopback HTTP without remote URLs, proxies or redirect following; it never returns adapter environment variables, credentials or full configuration.

On this installation, live discovery returned 13 matching Paperclip workspaces and C:, D: and E:. Twelve use `hermes_local`; **Hermes Operations** currently uses `codex_local`. The separate Windows **Hermes Security Team** launcher directory is not the Paperclip worker workspace. Global Hermes skills/runtime, other adapters not selected by this discovery, and Linux filesystem contents inside mounted WSL/VM virtual disks are outside this automatic inventory. Drive malware scans do not replace in-guest inspection or agent behavior testing.

Verification: 155 Python tests passed, including 12 scan-center tests; HTTP checks rejected missing authentication, forged target IDs, remote port values and invalid saved-report IDs. Browser discovery and selecting all 16 real targets were verified without launching scans during interface checks. Activation and actual scan results are recorded separately in VERIFICATION.md.

Reference: [Microsoft Defender command-line options](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus).


## Expanded AI endpoint validation — October 4, 2026

The engine catalog now has 22 named profiles: Ollama, vLLM, SGLang,
llama.cpp, LM Studio, LocalAI, Hugging Face TGI, TensorRT-LLM,
Triton (OpenAI frontend), NVIDIA NIM, NVIDIA Dynamo, LMDeploy,
Xinference, Aphrodite/Sonar, TabbyAPI, MLX-LM, llamafile, KoboldCpp,
text generation WebUI/textgen, Ray Serve LLM, LiteLLM, and a generic
OpenAI-compatible server. These are HTTP text-chat adapters and editable
connection presets, not installed inference runtimes or a claim that every
engine feature or version is supported.

1. Open **AI endpoints**, choose the engine and enter the actual base URL.
   Defaults change when switching an unchanged preset; custom URLs and reverse
   proxy prefixes are preserved. A server root or a base ending in `/v1` is
   accepted. Native Ollama also accepts a base ending in `/api`.
2. Confirm authorization and **Discover models**. Discovery is read-only and
   preserves exact model identities, including served names and LoRA aliases.
   Changing the engine, URL or key invalidates the previous selection; a response
   arriving after an edit cannot attach stale models to the new target.
3. **Set assessment scope** fills the signed-engagement form with the selected
   engine, exact URL and discovered model. Review the scope and create/select
   the engagement. Production continues to require the separate approval step.
4. Return to **AI endpoints** and use **Check chat compatibility** for one
   non-streaming request (at most 160 output tokens, 45-second timeout). It
   verifies that a system/user conversation returns usable final text. Its
   report is separate from **Run 8 boundary tests**. Compatibility is not a
   model-safety verdict or proof of system-message obedience.

The same catalog is available in asset discovery, expanded red team, signed
agent scope, runtime routes and behavioral baselines. Existing policies,
authorization gates and opt-in scheduling remain in force. No route or monitor
is enabled by adding or selecting a profile.

TGI tries its OpenAI model list first and falls back to `/info` only on HTTP
404/405, using the returned `model_id`. It never retries 401/403 with another
protocol or enumerates other ports. Malformed, empty or truncated inventories
and missing final text remain explicit gaps. A response containing only hidden
reasoning or tool calls is inconclusive for the text-only boundary suite.

Triton requires its separately configured OpenAI frontend; native `/v2` tensor
inference and gRPC are outside this adapter. Embeddings, ranking, image/audio,
streaming and management operations are not covered by these text-chat checks.
A selected engine name is not auto-detection. Engines can require chat templates,
model loading, server-specific configuration and API credentials.

API additions: `GET /api/endpoint-providers` returns the catalog;
`POST /api/run` with `assessment: "endpoint_check"`, a catalog `kind`, `url`,
returned `model`, `authorized: true` and a matching `engagementId` runs the
compatibility assessment. Host/Origin/app-token, scope and single-job protections
apply. Provider keys stay in memory. No raw HTTP error payloads are retained.

The catalog embeds official documentation links, including
[vLLM](https://docs.vllm.ai/en/latest/serving/online_serving/),
[TGI](https://huggingface.co/docs/text-generation-inference/messages_api),
[Triton OpenAI frontend](https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/client_guide/openai_readme.html)
and [llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).
All profiles were exercised against local protocol fixtures; this does not
substitute for a compatibility check against the user's actual engine build.
