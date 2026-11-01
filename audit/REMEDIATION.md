# CryptoWarden 3.0 remediation record

This is the 3.0 hardening baseline. See [the 3.1 management upgrade](MANAGEMENT_UPGRADE.md) for subsequent controls, typography, and current validation.

Date: 2026-11-01, Asia/Karachi.

The original audit describes revision `e100d34`. This record describes the subsequent working-copy upgrade. It distinguishes corrected code paths from prevention and deployment capabilities that still require qualification.

## Validation

- 116 backend tests passed, including a real watchdog-to-authenticated-console integration restricted to a temporary directory.
- Approximately 86% statement coverage, compared with 39% before remediation. The event orchestrator is now covered at approximately 81%.
- Four Edge browser workflows passed: authenticated incident review/acknowledgment/export/lock; mobile layout and local-only assets; invalid-key refusal; and direct-file opening with relative assets and an explicit server handoff. Desktop, mobile, and direct-file screenshots were visually inspected.
- Ruff checks/formatting and dashboard formatting passed.
- Hash-locked runtime and development dependency audits reported zero known vulnerabilities: 11 runtime packages and 30 development packages.
- npm audit reported zero vulnerabilities in the locked browser development toolchain.
- A clean second virtual environment installed the runtime using distribution hashes and imported the built wheel, including offline dashboard assets.
- Wheel and source archives were built. CI defines Windows/Linux and Python 3.11/3.12 jobs; those remote jobs have not been executed from this workspace.
- No live response target was terminated. Response behavior was checked with process doubles, native critical-status refusal checks, and a suite-wide prohibition on real endpoint kills. Test-owned browser/server helpers were started and stopped during validation.

## Finding-by-finding disposition

| Finding | Implemented correction | Qualification boundary |
| --- | --- | --- |
| F01: unsafe inferred attribution | Removed high-I/O/recent-writer/open-handle attribution from the action path. Incoming filesystem events cannot assert verified identity. Automatic termination is disabled. | Qualified native writer collection remains an open release gate. |
| F02: unauthenticated dashboard | Required random/operator-supplied access key; HttpOnly SameSite session; exact Origin/Host; CSRF; strict commands bound to incidents and process instances; size/rate/session limits; push-only sockets. | Loopback, current-user workspace only; remote/multi-user deployment unsupported. |
| F03: vulnerable dependencies/static resolver | Replaced the FastAPI dependency chain with patched Starlette 1.10.0/AnyIO 4.15.1 and updated Uvicorn/WebSockets. Assets use an exact in-memory allowlist, never untrusted filesystem paths. Added runtime/dev hash locks and audits. | Current audits are time-bound, not a permanent vulnerability guarantee. |
| F04: PID lifetime ambiguity | Captured PID/create-time/executable identities; state resets for replacement instances; manual response revalidates the same process object before action; critical status and essential-process protection. | Collector does not identify a writer; native OS handle qualification remains open. |
| F05: stale I/O/cache | Idle samples reset rates; samples/counters use process lifetimes and monotonic timing; exited/stale state is pruned. Unsafe ownership cache behavior is removed; compatibility helpers return UNKNOWN. | Process I/O is investigation context only. |
| F06: UI blocks detection/response | Bounded per-client queues with nonblocking publication, sender deadlines and slow-client eviction; process polling off the event loop; incidents persisted independently. | Full-load latency/soak qualification remains open. |
| F07: canary data loss | Random exclusive file creation; durable normalized ownership manifest; file identity/hash validation; no legacy file adoption; preview cleanup; changed/replaced files retained; cleanup respects instance lock. | Same-user adversarial filesystem races and administrator tampering require a stronger service boundary. |
| F08: unsafe config fallback | Strict schema/ranges/unknown-key checks, rejected malformed/explicit-missing files, defined path base, overlap/variable checks, alert-only default, invalid modes refused again at response. Imports do not activate unrelated configuration. | Installation/site policy must choose valid local roots. |
| F09: inconsistent whitelist | Rejected basename-only trust; no actor omission based on process name. Persisted executable review fingerprints with reasons and revocation; canary incidents remain visible. | Review records are annotations, not broad allow/bypass rules. |
| F10: false blocked/retry accounting | Structured outcomes and per-target confirmed exits; no fake blocked count for alerts/refusals/failures; TTL notification deduplication; durable payload-bound command reservation and replay results; pending outcomes fail closed after interruption. | Command replay history has a declared retention horizon. |
| F11: bad rates/windows | Monotonic evaluation-time expiry; actual unique-file count/window rate; duplicate file events do not create fake multi-file behavior. | Workload thresholds still need corpus calibration. |
| F12: rename filtering gaps | Evaluate both endpoints, preserve suspicious destination renames and boundary moves, retain directory-change observations and degrade scope confidence. | No claim that a moved subtree was exhaustively reconciled. |
| F13: canary scope/identity | One absolute/case-normalized representation; require valid existing roots before provisioning; persistent canary health checks and integrity incidents. | Changed/missing canaries remain evidence; not silently replenished over user content. |
| F14: unbounded processing | Bounded thread handoff, scheduled callback count, priority queue, coalescing, bounded entropy worker admission, state limits, visible overflow/skips/timeouts. | Lost events are reported as coverage loss, not claimed recovered. |
| F15: uncalibrated/noisy features | I/O is no longer detection authority; absolute entropy on a single archive cannot trigger; multi-file corroboration and explicit entropy status/delta; calls/sec and bytes/sec kept separate. | Field precision/recall and partial/slow encryption coverage remain open. |
| F16: incomplete response/forensics | Guarded optional descendant snapshot, per-target critical/identity checks and exit verification; persistent incident evidence, pre-action audit and command journal, then final outcomes. | Snapshot tree handling is best effort; no file rollback or protected backup. |
| F17: partial startup/shutdown | Staged readiness, actual scope checks, OS-held single-instance lock, supervised tasks, observer health check, cleanup on initialization failure, bounded observer/server shutdown. | Dedicated Windows service packaging/recovery and multi-day operation remain open. |
| F18: misleading dashboard | Rebuilt responsive local console with truthful posture, explicit offline/stale state, persistent/replayed incidents, acknowledged actions, bounded direct counters, full retained-incident export, safe text rendering, local SVG charts/assets and CSP. | Browser workflows and visual inspection passed; formal accessibility review remains a release gate. |
| F19: packaging/claims/validation | Declared PyYAML/dev dependencies, versioned project/CLI, locked installs, wheel assets, CI, static/browser/integration tests, safe owned-fixture simulator, updated limitations and operations docs. | Remote matrix/field certification is not implied by local tests. |

## Evidence and reproducibility

- [Coverage](evidence/v3-coverage.json)
- [Runtime dependency audit](evidence/v3-dependency-audit.json)
- [Development dependency audit](evidence/v3-dev-dependency-audit.json)
- [npm audit](evidence/v3-npm-audit.json)
- [Static analysis](evidence/v3-bandit.json)
- [Bound validation record](evidence/v3-validation.json)
- [Desktop screenshot](../docs/assets/console-desktop.png) and [mobile screenshot](../docs/assets/console-mobile.png), both explicitly marked demonstration data

Bandit emits conservative findings for empty configuration-token placeholders (which now generate mandatory authentication), the reviewed Windows SID query subprocess (absolute system path, no shell), and the lock generator's fixed HTTPS PyPI URL. These are reviewed tool findings, not evidence that authentication is disabled or that arbitrary URL schemes are accepted.

The original v2 reproduction source is archived as inert [historical text](historical/reproduce_v2_findings.py.txt). Its recorded observations remain unchanged. The current `reproduce_findings.py` runs the regression suite; it does not execute the obsolete unsafe assumptions.

## Release decision

The audited unsafe paths are corrected or explicitly disabled, and the dashboard/runtime upgrade is validated within the recorded scope. This is a hardened monitoring and operator-response candidate. It must not be represented as a certified or field-proven industry prevention product. Close the [release gates](../docs/RELEASE_GATES.md) before enabling or claiming native automatic prevention.
