# Management console

CryptoWarden 3.1 adds an authenticated management plane under **Settings & control**. The console remains available independently of file and process collectors. Stopping the whole Python process still closes the console; starting an offline process requires the CLI or a separately deployed service supervisor.

## Available controls

| Control | Actual behavior |
| --- | --- |
| Pause monitoring | Stops file and I/O collectors, rejects stale queued generations, and keeps incident review and settings available. Requires an operational reason and coverage acknowledgment. |
| Timed pause | Choose 1, 5, 15, or 60 minutes. The engine resumes automatically when due and records the action. In-process timing uses a monotonic deadline; restart recovery uses the saved wall-clock deadline. Failed resumes remain visible and retry at a bounded interval. |
| Manual pause | Choose “Until I resume manually.” Paused intent persists across process restarts. |
| Start monitoring | Validates the saved directory scope, provisions owned canaries if needed, starts new collector instances, and waits for readiness. |
| Restart collectors | Restarts collection using the saved policy without closing the authenticated console. |
| Policy review/apply | Edit protected directories, exclusions, process-context interval, detection thresholds, alert cooldown, manual response mode, and optional captured-descendant handling. Review normalized before/after values and warnings before applying. |
| Operator activity | Inspect recent commands and transition gaps, including reasons, results, duration, and time paused before a successful resume. |

The active mode applies to explicit operator requests. Automatic termination remains unavailable because watchdog does not authenticate file writers. An executable review record does not exempt canary alerts or establish writer causality.

## Policy persistence and concurrency

Managed settings are saved in the private SQLite workspace. Listener binding, access keys, runtime storage location, capacity settings, and essential-process protections are outside the editable policy scope. Saved managed settings override the startup file after the first console change. Unmanaged settings continue to come from startup configuration.

Each control operation supplies the revision the operator reviewed. Changes from another session produce a conflict; reload the saved policy and review again. Preview fingerprints bind the candidate policy, base revision, and operational reason. A changed policy cannot reuse another preview. Enabling manual termination requires the exact phrase **ENABLE MANUAL TERMINATION**, in addition to the review and coverage acknowledgment.

## Transitions and failure recovery

The engine durably records transition intent before stopping collectors. Event processing and policy replacement are serialized. New observers carry a new generation, so queued events from previous scope/policy cannot be reinterpreted under the new policy. Behavioral windows and entropy baselines reset when applying policy.

The policy revision is committed only after required collectors are ready. If a transition fails, the engine restores the previous settings and collectors. If restoration also fails, collection becomes faulted and the recovery marker remains durable. On restart, an unresolved transition starts paused; editing settings alone does not silently resume collection. Review the reported error and use **Start monitoring** when ready.

Removed roots stop being watched. Existing owned canaries remain recorded for reviewed cleanup; the console does not delete files when removing directory scope. Exclusions that would suppress an entire protected root are refused.

Directory availability, telemetry loss, and past coverage gaps are distinct. Resuming monitoring does not reconstruct file events that occurred while paused or dropped during overflow. Previously known canary integrity is labeled as stale while collection is inactive.

## Upgrade and configuration recovery

Restart an already-running 3.0 engine once to load the 3.1 code and assets. Afterward, use the console to manage collection and policy without restarting the console process.

To discard saved managed policy deliberately, stop the engine and run:

```powershell
.venv\Scripts\python -m src.main start --config C:\path\to\endpoint.yaml --reset-policy
```

A reset does not bypass an unresolved interrupted-transition marker; review and explicitly resume from the console. Demo workspaces keep their own policy and never start live collectors or enable live response actions.

## Typography

The console uses a 16px body/input scale, 14–15px labels and table text, larger headings, stronger text contrast, and 44px action targets. Desktop and mobile tests assert the effective font sizes and check page overflow. Formal accessibility review remains a product release gate.
