# CryptoWarden 3.1 management and readability upgrade

This upgrade turns the local dashboard into a management console. The 3.0 audit/hardening baseline remains documented in [REMEDIATION.md](REMEDIATION.md); current 3.1 implementation details are in [MANAGEMENT.md](../docs/MANAGEMENT.md).

## Implemented controls

- Start/resume and pause file/process collectors while the authenticated console remains available.
- Timed pauses with bounded automatic-resume retries, and an explicit indefinite-pause choice. Paused intent survives an engine restart.
- Restart collectors using saved policy without closing the console.
- Edit protected directories, exclusions, context-sampling interval, detection thresholds, alert cooldown, manual response mode, and captured-descendant policy.
- Review normalized before/after values, warnings, and an operational reason before applying. Manual termination mode requires typed confirmation.
- Persist reviewed policy independently of startup-file settings; reject stale revisions and mismatched preview fingerprints.
- Record management decisions and transition/pause gaps in the operator history.
- Restore the previous policy/collectors after a failed apply. Preserve a durable recovery marker if the transition is interrupted or restoration fails.
- Keep the console available when collection cannot start, so the operator can correct directory scope and retry.
- Coordinate shutdown with already-admitted operations and refuse new commands while closing.

The policy endpoint cannot change listener binding, authentication secrets, runtime storage, queue capacity, or protected-process safeguards. Operator selection remains distinct from verified writer attribution. Automatic termination remains unavailable.

## Readability

The console now uses a 16px body/input scale, 14–15px labels/table text, larger section headings, stronger contrast, and 44px action targets. Desktop and mobile checks verify computed sizes, form usability, and page overflow. Local-file opening still loads bundled assets and directs sign-in to the running HTTP console.

Screenshots use an isolated demonstration workspace:

- [Overview](../docs/assets/console-desktop.png)
- [Desktop management](../docs/assets/console-management-desktop.png)
- [Mobile management](../docs/assets/console-management-mobile.png)

## Validation evidence

Validation passed 144 backend tests and seven Edge browser workflows, with 86.86% statement coverage. Static checks, formatting checks, the 3.1 wheel/source build, and an isolated installed-wheel smoke check passed. The dependency locks are unchanged from the audited baseline.

The machine-readable [management validation record](evidence/management-validation.json) binds the tested source and packaged artifacts to their SHA-256 hashes. Supporting evidence includes [backend results](evidence/management-pytest-results.xml), [coverage](evidence/management-coverage.json), and [browser workflows](evidence/management-browser-results.json).

The controlled integration uses actual watchdog observers and authenticated HTTP against disposable roots. It pauses collection, proves events are not analyzed during the declared pause, changes directory scope while paused, resumes/provisions new canaries, detects an integrity event in the new root, restarts collectors, and rejects a stale-revision request. All tests prohibit real endpoint response kills.

The browser workflows cover incident review, export, locking, offline assets, mobile layout, direct-file opening, editable policy and monitoring controls, and typed response-mode confirmation. Remote CI and field deployment are not implied by local validation.

## Activation and remaining scope

An already-running 3.0 process must be restarted once to load the 3.1 backend and assets. Then policy and collector changes are available from **Settings & control** without restarting the console process. Runtime and development dependency lock contents are unchanged by this upgrade.

Native writer attribution, strong OS containment, service/installer isolation, protected recovery, independent security/accessibility review, and field efficacy qualification remain [release gates](../docs/RELEASE_GATES.md). The management plane is implemented; these separate capabilities are not claimed complete.
