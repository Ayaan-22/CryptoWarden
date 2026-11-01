# CryptoWarden project audit

Historical audit of revision `e100d34`. See [the 3.0 remediation record](REMEDIATION.md) for subsequent changes and current validation.

Date: 2026-11-01, Asia/Karachi. Source revision: `e100d34da39ec419f43eaa3ad3f20ea2cdd425c3`.

## Assessment

CryptoWarden has a useful modular prototype: monitoring, state tracking, entropy analysis, detection, response, and dashboard code are separated. Its current automatic termination path is unsafe for general desktop deployment. The strongest reason is that the system promotes a guessed process association into permission to kill that process. Detection confidence and actor attribution confidence are different facts, and the current design does not enforce that distinction.

This audit identifies **19 findings: one Critical, nine High, and nine Medium**. These are engineering priorities, not externally assigned CVSS scores. Critical means a core behavior can terminate an unrelated application under ordinary desktop activity. High findings can cause data loss, unauthorized control, serious protection failures, or an applicable dependency exposure. Medium findings reduce coverage, reliability, observability, or reproducibility.

Recommended immediate order: make alert-only the safe default; require verified process identity and file-operation attribution before automatic termination; secure dashboard control; repair canary ownership; validate configuration; upgrade the web dependency set. Do those before adding detection rules or machine learning.

Only audit artifacts were added. Application source, configuration, dependencies, and existing tests were not changed. The protection daemon and ransomware simulator were not started. All response calls in the reproduction harness were mocked. Canary deletion was demonstrated only on disposable, explicitly created fixtures. The StaticFiles resolver was intercepted before OS or network access.

## Scope and verification

Reviewed all tracked Python modules and scripts, YAML configuration, dependency manifest, dashboard HTML/JavaScript/CSS, tests, README, implementation plan, and task checklist. No applicable AGENTS.md was found in the project or checked ancestors.

| Check | Result | Meaning and limits |
| --- | --- | --- |
| `python -m pytest tests/ -q --cov=src --cov-report=term-missing` | 43 passed; 39% statement coverage | Existing tests pass; this does not validate live prevention. |
| Main orchestration coverage | 0% | Event attribution, detection-to-response flow, commands, and lifecycle are untested by the existing suite. |
| Honeypot / process monitor coverage | 0% / 0% | Canary lifecycle and I/O sampling lack existing test execution. |
| Process tools / dashboard bridge coverage | 19% / 46% | Cache behavior, process termination, WebSocket authentication, and broadcasting are poorly covered. |
| `python audit/reproduce_findings.py` | Completed successfully; 19 observation records | Isolated evidence of current behavior, including one positive authentication control. Not a regression suite that asserts desired behavior. |
| `node --check dashboard/dashboard.js` | Passed | Syntax validation only; no browser or visual QA performed. |
| `python -m bandit -r src tools -f json -o audit/evidence/bandit.json` | Six Low findings | Mostly empty-token defaults and broad exception suppression. Automated static analysis misses the main architectural defects. Exit 1 means findings were reported. |
| Installed runtime dependency scan | 16 raw records, nine unique advisory IDs, two packages | Starlette 0.36.3: seven unique; AnyIO 4.13.0: two. Duplicate records were not counted as distinct vulnerabilities. Exit 1 means vulnerabilities were found. |
| `git diff --check` | Passed | Whitespace check, not behavioral validation. |

The dependency snapshot is the installed Windows/Python 3.11.9 environment, expanded through active runtime dependencies and supplemented with the missing direct PyYAML import. It is **not** a lockfile or a fresh installation result. No packages were installed or upgraded. Dependency database access and the asynchronous probes required execution outside the restricted sandbox: Windows asyncio's local socket-pair initialization stalled inside it. That environment limitation is not attributed to CryptoWarden.

Evidence:

- [Reproduction harness](reproduce_findings.py)
- [Recorded observations](evidence/reproduction-output.txt)
- [Static scan](evidence/bandit.json)
- [Installed runtime versions](evidence/runtime-environment.txt)
- [Raw dependency scan](evidence/dependency-audit.json)

## Findings

### F01 — Critical: guessed actor attribution authorizes termination

**Sources:** `src/main.py:102-114`, `src/main.py:142-151`, `src/main.py:53-64`; `src/monitoring/file_monitor.py:31-41`; `src/detection/engine.py:29-40`.

When an event has no PID, the orchestrator assigns it to a top-I/O non-whitelisted process. A suspicious rename can also be assigned to a recent writer without any connection to that file. The event's `attribution_confidence` is never used to restrict response. Extreme I/O plus the entropy of somebody else's file is sufficient to trigger automatic termination. Filtering developer folders does not establish process causality.

**Reproduced:** an unattributed modified-file event with entropy 7.9 was assigned to synthetic `benign-backup.exe`, and its response mock was called. The process had no observed handle or write to that path.

**Improve:** keep attribution evidence, age, method, confidence, and immutable process identity on the event. Use guessed actors for investigation only. Permit automatic response only when the attribution source satisfies an explicit policy. Open-handle ownership itself must not be labeled proof of the write: readers can hold handles too. Evaluate an ETW-backed collector with file-object and thread/process lifecycle correlation; preserve UNKNOWN when correlation fails. [psutil documents incomplete Windows open-file enumeration](https://psutil.io/faq/), and [Microsoft describes ETW file-write correlation fields](https://learn.microsoft.com/en-us/windows/desktop/ETW/fileio-readwrite). ETW integration would still require loss detection and validation.

**Acceptance:** simultaneous benign high-I/O activity and unattributed suspicious writes must never cause an automatic kill of the benign actor. Test recent-writer and cached-reader associations separately.

### F02 — High: default dashboard control is unauthenticated and accepts arbitrary Origins

**Sources:** `config.yaml:78-82`; `src/utils/dashboard_bridge.py:36-55`, `src/utils/dashboard_bridge.py:76-98`; `src/main.py:175-195`.

The empty default token disables authentication. There is no Origin allowlist or per-command authorization. Any client able to reach the listener can enqueue positive-PID termination and process-name whitelist commands. The default loopback bind limits direct remote access; it does not authenticate local clients. Cross-origin browser exposure depends on browser network policy, but the application does not reject those requests.

**Reproduced:** an in-process ASGI WebSocket exchange with `Origin: https://untrusted.invalid`, no token, and a kill command was accepted and queued. No real network listener or command consumer was started. A nonempty configured token correctly rejected a missing token, so the conditional token check itself works.

**Improve:** require authentication for control, enforce an exact permitted Origin set, separate viewing from response privileges, and bound command sizes/rates/queues. Make remote binding an explicit secured configuration. Validate PID types strictly: `int()` currently also accepts booleans and truncates floats. Provide a real login/token flow: the UI only reads an otherwise unset `window.CRYPTO_WARDEN_WS_TOKEN`. Avoid persistent URL secrets. [OWASP recommends WebSocket authentication, Origin validation, authorization, and resource limits](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).

**Acceptance:** reject unauthenticated control and disallowed Origins; ensure authorized users can connect through the supplied UI and receive command results.

### F03 — High: installed Windows static-file serving matches a published credential-disclosure advisory

**Sources:** `src/utils/dashboard_bridge.py:71-72`; `audit/evidence/runtime-environment.txt`; `audit/evidence/dependency-audit.json`.

The scanned environment has Starlette 0.36.3 and serves the dashboard through default `StaticFiles` on Windows. This matches [GHSA-wqp7-x3pw-xc5r / CVE-2026-48818](https://github.com/Kludex/starlette/security/advisories/GHSA-wqp7-x3pw-xc5r): UNC path resolution can initiate outbound SMB authentication before containment validation. The advisory identifies 1.1.0 as its fix. The actual installed `lookup_path()` was inspected and has the described ordering.

**Reproduced safely:** a UNC path reached an intercepted resolver before containment checking. No SMB connection, credential disclosure, or exploit request was attempted. Practical disclosure also depends on listener access and outbound network policy.

**Improve:** upgrade FastAPI and Starlette together to a compatible, supported patched set, then lock and test it. Installed FastAPI 0.110.0 requires `starlette>=0.36.3,<0.37.0`, so overriding only Starlette would violate its declared constraint. Until upgraded, replace this static-serving path or apply a reviewed mitigation. Do not enable symlink following casually as a shortcut.

The scan found **nine unique advisories**, not 16 independent vulnerabilities:

| Dependency / advisory group | Applicability to this code |
| --- | --- |
| Starlette Windows UNC resolution | Matches OS, installed version, and static mount; safe resolver check confirms ordering. |
| Starlette multipart / form resource limits | No application form parsing/upload endpoint found; not shown reachable. |
| Starlette reconstructed URL / Host interpretation | No security decision based on `request.url` found; not shown reachable. |
| Starlette HTTPEndpoint method dispatch | No custom HTTPEndpoint subclass found; not shown reachable. |
| AnyIO IDNA/TLS validation and process-worker stderr | No relevant outbound TLS or AnyIO process-pool use found in application code; not shown reachable. |

The separate [Starlette Range-header advisory](https://github.com/Kludex/starlette/security/advisories/GHSA-7f5h-v6xp-fcq8) affects 0.39.0–0.49.0, so it was **not** assigned to installed 0.36.3. Run the scanner again after choosing the replacement versions; fixing one advisory is not complete dependency maintenance.

### F04 — High: PID reuse can transfer evidence and response to a different process

**Sources:** `src/analysis/process_tracker.py:49-54`; `src/monitoring/process_monitor.py:10,46-59`; `src/utils/process_tools.py:12-19,171-180`; `src/response/responder.py:15-39`.

Tracking, previous counters, cache entries, and deduplication use bare PIDs. No evidence captures process creation time. `get_or_create()` keeps the old name and state even if a new process is supplied for the same PID. The responder resolves one Process object for a name check, then `kill_process()` creates another object for termination. A fresh psutil object cannot verify identity against the earlier file event.

**Reproduced:** two different process names supplied under one synthetic PID returned the same state with the old name.

**Improve:** key evidence and commands by `(pid, create_time)` plus executable identity; retain and revalidate a stable process object/handle at response. Expire exited instances and their suppression keys. If identity cannot be checked, report that uncertainty and refuse automated destructive action.

**Acceptance:** simulated PID replacement between sampling, detection, name resolution, and response never kills or suppresses the replacement.

### F05 — High: stale I/O and file ownership remain eligible for attribution

**Sources:** `src/monitoring/process_monitor.py:54-59`; `src/analysis/process_tracker.py:69-74`; `src/utils/process_tools.py:64-77,82-91`.

I/O state updates only when a sampled rate exceeds two; it never returns to zero when a process becomes idle. Top-writer selection has no freshness requirement. Cache refresh updates the existing file map rather than replacing/expiring it, and history has no timestamps. Size caps limit count, not age. Old ownership can survive process exit and subsequent writes by someone else.

**Reproduced:** an idle second sample retained the earlier approximately 100 ops/s rate. A three-pass cache refresh still returned a process after the final enumeration contained no processes.

**Improve:** record monotonic observation times, update every live sample including zero, discard exited instances, and apply short explicit validity periods to associations. Historical handle associations must remain historical evidence and cannot be promoted to current writers.

**Acceptance:** idle and exited processes disappear from attribution candidates; expired ownership never authorizes response.

### F06 — High: dashboard delivery is on the detection and response critical path

**Sources:** `src/main.py:60,92,137,154`; `src/utils/dashboard_bridge.py:115-132`.

Each event awaits dashboard activity broadcasting before analysis. Detection then awaits alert broadcasting before response. Broadcast sends sequentially to every client with no application timeout or bounded per-client delivery channel. A client whose send stalls delays the whole path; an alert publication exception aborts response entirely. OS/process polling also runs synchronously on the same event loop.

**Reproduced:** a deliberately stalled client kept alert publication pending until explicitly released. A mocked alert-publication error prevented the response call and left the deduplication key set, preventing a later retry.

**Improve:** make detection and response independent of UI delivery. Publish through bounded per-client queues with timeout/disconnect policies and batching. Move expensive process enumeration off the event loop. Ensure telemetry failures cannot cancel the decision path.

**Acceptance:** disconnected, slow, and throwing clients do not change response decisions or materially delay them. Measure detection-to-response latency under dashboard backpressure.

### F07 — High: canary setup adopts user files and cleanup deletes them

**Sources:** `src/monitoring/honey_pot.py:22-35`; `tools/cleanup_honeypots.py:21-30`.

Existing `_passwords.txt`, `_confidential.docx`, `backup_keys.dat`, and `private_keys.key` files are registered and hidden without proving CryptoWarden created them. Cleanup later deletes every matching path without ownership checks. A real existing private-key file can therefore be deleted by the documented maintenance command.

**Reproduced:** setup registered a pre-existing user-content fixture; cleanup deleted it. All paths were confined to a disposable temporary directory.

**Improve:** use collision-resistant names, exclusive creation, a durable ownership manifest, and verified file identity/content markers. Skip existing user files. Cleanup should remove only verified owned canaries, preserve unexpected changes, and offer a preview. Preserve original attributes when relevant.

**Acceptance:** existing files, replaced files, and ownership-manifest mismatches are never deleted or silently hidden.

### F08 — High: invalid configuration can enable termination instead of failing safely

**Sources:** `src/config.py:25-71,109`; `src/response/responder.py:20-31`; `config.yaml:40-42`.

The committed and fallback modes are `terminate`. The responder recognizes only `alert_only` and `dry_run` as non-destructive: any unknown value falls through to termination. Malformed YAML logs an error and retains termination defaults. There is no schema validation for sections, thresholds, paths, ports, modes, or unknown keys; partial merging can leave partially applied values on error.

**Reproduced:** `typo_mode` was accepted; malformed YAML returned `terminate`.

**Improve:** validate a complete immutable configuration before enabling services; enumerate allowed modes and reject invalid modes in the responder too. Default to alert-only. Refuse startup for an explicitly supplied invalid/missing config. Resolve relative paths against a defined base, reject unexpanded variables, validate directories and overlaps, and log the resolved protection scope.

**Acceptance:** misspellings, null sections, wrong types, invalid bounds, and unreadable configuration never activate termination or claim successful protection.

### F09 — High: whitelisting contradicts the detector's high-confidence override

**Sources:** `src/detection/engine.py:60-75`; `src/main.py:62`; `src/utils/process_tools.py:45-47,115-117`; `src/config.py:91-103`.

The detector deliberately flags a whitelisted process for canary access or strong encryption patterns, but the orchestrator unconditionally prevents its automatic response. The attribution cache also omits whitelisted processes, making an unrelated writer a possible fallback. Trust is based on executable basename, so an untrusted executable with a listed name inherits that trust. There is no policy persistence or removal UI for runtime whitelist entries.

**Reproduced:** an `explorer.exe` canary event was detected and counted as blocked, while the responder mock received zero calls.

**Improve:** define one policy for trust, detection, and response. Separate immutable system protection from user allow rules. Scope trust to verified executable identity where appropriate and expose rule reason, persistence, and revocation. Decide explicitly how confirmed malicious behavior interacts with allow rules without defeating protected-process safeguards.

**Acceptance:** whitelisted high-confidence detections produce the documented action and truthful outcome; name spoofing does not inherit broad trust.

### F10 — High: blocked counts and permanent suppression hide failed responses

**Sources:** `src/main.py:53-68`; `src/response/responder.py:20-35,43-54`; `src/utils/process_tools.py:175-180`; `dashboard/dashboard.js:195-204`.

`blocked` increments and the dedup key is stored before any action. Unknown actors, whitelisted actors, alert-only decisions, protected processes, and failed kills can all count as blocked. The responder returns no structured outcome. `NoSuchProcess` is treated as successful termination. A failed action or dashboard error is suppressed for the rest of the session; all unattributed outbreaks share `(-1, "Unknown process")`. Popups say "blocked" even in alert-only and protected-process branches.

**Reproduced:** a failed mocked response was attempted only once across two detections; the counter was one. A failed dashboard alert yielded blocked=1 and zero response attempts, including on retry.

**Improve:** distinguish detections, attempted actions, confirmed exits, already-exited targets, refusals, and failures. Return an ActionResult with incident and process-instance IDs. Deduplicate notifications separately from response attempts, using bounded TTL/cooldowns and a safe retry policy. Verify exit before reporting termination.

**Acceptance:** unsuccessful or skipped actions never increase confirmed-block counts; repeated independent UNKNOWN incidents remain visible; eligible failed actions can be retried.

### F11 — Medium: modification-rate units and time-window expiry are wrong

**Sources:** `src/analysis/process_tracker.py:20-45`; `src/detection/engine.py:23-27`; `src/main.py:160-173`.

The setting says modifications per second, but the getter returns the number of events retained in a ten-second window. Expiry runs only when another modification or rename is added. Background analysis can therefore score minute-old events as current. It counts notifications, not distinct files, so repeated writes to one file can appear as mass file modification.

**Reproduced:** six modifications spread over nine seconds were compared as rate=6 against the configured 5/s threshold; six minute-old modifications remained present and triggered with I/O=8.

**Improve:** define consistent units and window duration; use monotonic durations, prune at evaluation time, and track unique file identities as well as operation counts. Specify handling for delayed/out-of-order notifications.

**Acceptance:** boundary tests cover real 1s/10s rates, expiry during idle periods, duplicate file events, and delayed event processing.

### F12 — Medium: filtering discards suspicious renames and creates coverage holes

**Sources:** `src/monitoring/file_monitor.py:24-29,62-74`; `config.yaml:10-24`.

A source with an ignored suffix is dropped before checking its destination. A rename from an ignored directory into a protected directory is also dropped because either endpoint causes exclusion. All writes to configured excluded suffixes/directories are invisible, even if they contain valuable data. Directory move events are ignored entirely.

**Reproduced:** `document.tmp` → `document.tmp.enc` emitted zero events.

**Improve:** evaluate both endpoints and protection boundaries before suppressing moves. Prioritize suspicious destinations and canary identity. Document exclusions as coverage limitations, with explicit patterns rather than accidental global basename assumptions. Define directory-move handling and recovery scans.

**Acceptance:** suspicious renames from excluded sources and moves into protected roots remain detectable; ordinary excluded noise stays bounded.

### F13 — Medium: canary path identity and provisioning miss protected scope

**Sources:** `src/monitoring/honey_pot.py:18-20,23,35,45`; `src/monitoring/file_monitor.py:100-108`; `src/main.py:215-224`.

Canary paths use `normpath` without absolute/case normalization, while watches use absolute paths. The committed relative `RansomwareTestArea` therefore has a path mismatch. Windows case variants also fail exact set membership. Setup runs before the monitor creates missing directories, so newly created roots get no canaries. Only four files per root are planted; there is no rotation, integrity check, or replenishment after modification/deletion. Plain reads are not monitored despite README's broad "any interaction" claim.

**Reproduced:** both relative-versus-absolute and case-variant membership checks returned false.

**Improve:** normalize a single resolved path representation, provision roots before deploying owned canaries, and monitor canary health/replacement. Define Windows reparse-point/file-identity policy. Expose which roots actually have healthy canaries and which interactions the collector observes.

**Acceptance:** absolute, relative, and case variants identify the same canary on supported Windows paths; new roots receive owned canaries; damaged canaries create a health event.

### F14 — Medium: event and command processing have no bounded workload policy

**Sources:** `src/main.py:45,75-158`; `src/utils/dashboard_bridge.py:19,54`; `src/monitoring/file_monitor.py:60`; `src/monitoring/process_monitor.py:30-64`.

Both asyncio queues are unbounded. A single consumer awaits entropy work per event and emits per-event dashboard updates. A burst can grow memory and queue age while response analyzes old data. Process state, previous counters, and suppression sets are not evicted. Full process enumeration occurs every 100ms plus the separate cache scan. Adding only a queue maxsize would move QueueFull failures into the watchdog callback without a recovery policy.

**Improve:** budget queue capacity, prioritize canaries, coalesce redundant path events, bound entropy workers and I/O time, batch UI traffic, and evict state. Define overflow telemetry and a reconciliation/re-scan policy. Measure collector and application queue losses, queue age, CPU, memory, and latency before changing polling frequency.

**Acceptance:** a sustained synthetic burst stays within defined resource budgets and reports every coverage loss; priority events meet an explicit latency budget.

### F15 — Medium: heuristic combinations confuse compressed data with encryption

**Sources:** `src/detection/engine.py:29-40,77-89`; `src/analysis/entropy.py:24-54`; `src/monitoring/process_monitor.py:43`; `tests/ransomware_simulator.py`.

High absolute entropy plus moderate I/O can detect on one ordinary archive output, with no modifications or renames in state. No pre-write baseline, entropy delta, distinct-file requirement, or file-type context is used. The I/O metric adds write calls to bytes/4096 but labels the result ops/s. Entropy read failures return the same zero as genuinely low entropy. Sampling fixed positions may miss partial encryption. Historical entropy, accessed_dirs, and suspicion_score are not used in decisions.

**Reproduced:** entropy=7.9 on `ordinary-backup.zip` with I/O=8 triggered while modification and rename counts were both zero.

**Improve:** keep write calls and bytes/sec separate; require corroborated behaviors appropriate to action severity; record analysis success/unknown separately from entropy. Evaluate file-type-aware baselines, unique-file fan-out, overwrite/rename sequences, and partial-encryption coverage. Use a labeled benign workload and varied attack-like fixture corpus before tuning weights. ML would not repair incorrect attribution or missing ground truth.

**Acceptance:** quantify false positives on archives, backups, sync, browsers, installers, builds, and databases; measure files/bytes affected before detection across slow, burst, extensionless, partial-write, and multi-process scenarios.

### F16 — Medium: response stops one PID and does not preserve the promised forensic snapshot

**Sources:** `src/utils/process_tools.py:171-180`; `src/response/responder.py:15-35`; `README.md`, "Mitigation Logic".

The implementation kills only the selected PID, not its process tree as documented. It does not wait for exit, manage descendants, or write a structured incident snapshot. A worker can continue after its parent exits. Rotating text logs contain reasons but lack stable incident IDs, evidence, attribution provenance, executable identity, affected paths, and action outcomes. There is no recovery mechanism for already changed files.

**Improve:** design containment for verified process instances and descendants, applying protected-process and identity checks to every action. Consider Windows job containment where appropriate. Record a bounded structured incident before evidence disappears, with restrictive permissions and retention. Keep backup/recovery expectations explicit; do not promise rollback without an implementation.

**Acceptance:** controlled parent/worker fixtures verify containment and record per-target outcomes; forensics survive UI disconnect and process exit.

### F17 — Medium: startup and shutdown can leave partial protection reported as operational

**Sources:** `src/main.py:201-240,242-263`; `src/utils/dashboard_bridge.py:100-113`; `src/monitoring/file_monitor.py:98-116`; `src/utils/process_tools.py:21-27`.

Initialization occurs before the main cleanup try/finally. A failure after earlier services start can leak them. Bridge.start schedules a server task without awaiting readiness or supervising failure. Missing/failed directory setup is silently skipped, and the application still announces operational status. Cache.stop does not join its thread; observer.join runs synchronously on the event loop. Background tasks lack supervision/restart or degraded-health signaling. Multiple instances have no explicit ownership coordination.

**Improve:** implement staged startup with cleanup registered after each acquired resource, readiness checks for every component, actual watched-scope reporting, graceful Uvicorn shutdown, bounded joins, and task supervision. Expose degraded/stopped states and enforce single-instance or explicit shared ownership.

**Acceptance:** injected failures at each startup stage clean up prior resources; port conflicts, empty watch scope, observer failure, and background-task death never appear as fully operational.

### F18 — Medium: the dashboard can imply success or security without backend evidence

**Sources:** `dashboard/dashboard.js:155-178,182-219,325-346,357-365`; `dashboard/index.html:58`; `src/utils/dashboard_bridge.py:57-60,140-148`.

The initial page says Secure even before a connection exists. Disconnect changes only the connection badge; stale health remains. Health depends on lifetime blocked count rather than current component health. Sending a kill removes an alert even when disconnected or when the backend refuses/fails; there are no command acknowledgments, and command_error messages are ignored. Local activity counts compete with authoritative stats after reconnect. Counter animation creates a new interval per update and moves one integer per 30ms, so a jump to 10,000 takes five minutes in one animation while more can accumulate. Reconnection restores no incident history.

Chart.js is loaded externally and used before connect(); if it fails offline, the script can abort before connecting. It has no integrity attribute; Google Fonts is also external. Dynamic event and process text uses textContent/createTextNode, which is a positive injection safeguard; the innerHTML assignments inspected use fixed local templates.

**Improve:** use backend readiness/heartbeat and durable incident state; show unknown/offline explicitly; wait for correlated action acknowledgments. Use one authoritative counter source and bounded time-based animation. Bundle dashboard runtime assets locally and define a content security policy. Keep incident rendering safe and bound the full alert list.

**Acceptance:** test offline asset loading, disconnect/reconnect, missed incidents, refused actions, malformed command results, and high counter jumps without false success indications.

### F19 — Medium: installation and quality gates are not reproducible

**Sources:** `requirements.txt`; `src/config.py:4`; tracked test suite; `README.md`; `implementation_plan.md`; `task.md`.

PyYAML is imported directly but absent from requirements. Tests use pytest with no development dependency manifest. Runtime requirements are unversioned, and there is no committed lock, packaging metadata, CI workflow, lint/type configuration, or clean-environment smoke test. Current global packages can conceal installation defects. The task checklist claims manual simulator verification without committed run evidence. README claims entropy transition detection, sensitive-directory sequence scoring, process-tree termination, forensic snapshots, and canary interaction coverage beyond the implementation.

**Improve:** declare direct runtime/dev dependencies, choose and test a supported Python/Windows matrix, lock the supported dependency resolution, and add Windows CI for tests, integration scenarios, dependency scanning, and artifact checks. Document actual limitations and replace unsupported operational claims with measured evidence. Harden the simulator: use a uniquely owned temporary workspace/manifest and process-instance-specific outcome checks; it currently deletes arbitrary files in an existing CWD-based test directory and assumes survival means failed detection.

**Acceptance:** a fresh environment installs and imports successfully using only declared dependencies; automated checks cover the core pipeline and truthful outcomes. Simulator testing cannot touch unrelated files or terminate unrelated Python processes.

## Recommended implementation sequence

| Stage | Changes | Evidence required before advancing |
| --- | --- | --- |
| 1. Stop unsafe outcomes | F01/F02/F07/F08/F10: alert-only default, attribution gate, authenticated commands, canary ownership, truthful results | No kill for inferred actors; no user-file deletion; invalid configuration rejected; correct result counters. |
| 2. Bind identity and freshness | F04/F05/F09/F11/F13: process instances, cache expiry, coherent allow policy, real windows, normalized canary scope | PID-reuse, stale ownership, idle-rate, allow-override, and path-identity scenarios pass. |
| 3. Isolate and bound the runtime | F06/F12/F14/F17: UI independence, move filtering, bounded work, readiness and cleanup | Slow-client, overflow, startup-failure, and sustained-load scenarios meet declared budgets. |
| 4. Repair dependency and delivery baseline | F03/F18/F19: compatible patched dependencies, offline dashboard, CI, documentation | Clean Windows installation, rescanned locked versions, reliable control UI, truthful health. Stage 4 dependency fixes can proceed alongside stages 1–3. |
| 5. Qualify detection and containment | F15/F16: calibrated evidence, validated worker containment, incident records | Representative benign/attack-like evaluation with latency, damage, false positives, attribution accuracy, and action outcomes. |

Suggested internal contracts: FileEvent carries provenance and process-instance identity; DetectionResult carries signals and uncertainty; ResponsePolicy decides eligible actions; ActionResult records attempted/confirmed/refused/failed outcomes; IncidentStore persists evidence; DashboardPublisher consumes bounded notifications independently. This is a design proposal, not an implemented rewrite.

## Required next tests

1. Benign high-I/O process plus unrelated suspicious filesystem activity; include cached reader handles and recent-writer guesses.
2. Process exits/reuses its PID between observation and response; identity becomes inaccessible; protected descendant appears.
3. Canary filename collision, changed owned file, replacement/reparse point, relative/case path variants, missing root, and deleted canary.
4. Missing/bad authentication, disallowed Origin, command flooding, wrong PID types, nonempty-token UI access, and correlated acknowledgments.
5. Slow/failed dashboard send, entropy read failure, event overflow, process poll failure, occupied port, and shutdown during startup.
6. Alert-only, whitelist/protected refusal, failed kill, already-exited target, verified exit, safe retry, and independent UNKNOWN incidents.
7. Window boundaries, repeated writes to one file, out-of-order events, stale I/O reset, and cache expiry.
8. Clean installation plus benign workload and attack-like fixture evaluation. Report attribution accuracy and files/bytes changed before confirmed response; a single simulator kill is insufficient.

No live malware, real process termination, recovery guarantee, tamper resistance, field effectiveness, or production readiness was established by this audit. The recommended path is a safer, measurable research prototype first, followed by controlled Windows validation of any automatic prevention mode.
