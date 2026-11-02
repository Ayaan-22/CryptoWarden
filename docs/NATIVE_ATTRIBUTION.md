# Windows native writer-attribution prototype

The native writer-attribution release gate remains **OPEN**. This is an opt-in, offline ETL replay experiment, not a live collector, a writer-verification authority, or an automatic response feature. The dashboard and monitoring runtime continue to use watchdog and preserve `unknown` actors. `AUTOMATIC_TERMINATION_AVAILABLE` remains false. Changing response mode or submitting an event dictionary claiming verified/native provenance cannot enable automatic termination.

## Run the experiment

Use x64 Windows with x64 Python and the repository environment:

```powershell
.venv/Scripts/python.exe tools/replay_native_attribution.py C:/evidence/finalized-kernel.etl
```

The command reads an existing, finalized ETL using Windows `OpenTraceW` / `ProcessTrace`, retrieves named properties with TDH, and prints a bounded JSON report. It does not create/attach to/stop an ETW session, request elevation, install a driver, inspect current processes, or invoke response. Collecting a suitable ETL is a separate native qualification task. The input must contain classic NT Kernel process/thread start/end and file create/write/close events, enabled from before the test writers start, with file-I/O initialization enabled. An arbitrary WPR profile or modern manifest-provider trace is not interchangeable with this schema.

Supported input is deliberately narrow: classic Process GUID `3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c`, Thread GUID `3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c`, and FileIo GUID `90cbdc39-4a3e-11d1-84f4-0000f80464e3`; event version 2 and 64-bit event headers. Relevant events with another version/architecture and unknown opcodes in these providers fail closed; only explicitly listed metadata/non-mutating operations are skipped. Modern process event versions are not implemented. Rundown events do not substitute for observed starts; writes by processes already running when capture began may remain UNKNOWN. Circular or unfinalized ETLs are rejected for attribution. Only one trace/clock/generation is supported per invocation.

Exit status is 0 for completed processing without reported loss/errors, 1 for an incomplete/tainted report, and 2 when the command cannot open/process the input or arguments. Status 0 does not mean qualified attribution, sufficient provider coverage, or absence of writes. Inspect `writes` and `issues`. An unsupported manifest provider may yield no write rows. A decoding failure can omit an undecodable row while tainting the entire report; absence of a row is never evidence that a write did not occur. `--max-entries` defaults to 10000 and bounds each live state table and the retained write history. Overflow taints the generation rather than silently evicting evidence. Reports can contain sensitive paths, PIDs and kernel object addresses; retain them with the source trace under the qualification evidence policy.

## Correlation contract

- A write event is an observed **write request**, using its payload `TTID` and `FileObject`. An open handle, read, file creator, header PID/TID, high I/O, or nearby filesystem notification never establishes a writer. Requested bytes do not establish successful completion or durable data changes.
- A process instance includes the replay generation, PID, kernel process key and observed start timestamp. A thread binds to that complete instance at its observed start. A process exit removes its live threads. Reusing a PID/TID requires fresh lifecycle evidence and cannot inherit the old actor. Historical write snapshots survive exits, so a short-lived process can be investigated without querying a replacement PID.
- A file-object address binds to its native `OpenPath` only between observed create and close. Cleanup/set-info/delete/rename invalidate the path binding; the prototype does not infer the destination. Reuse requires a fresh create. Paths stay in the trace's namespace; no device-to-drive, hard-link, alternate-stream or file-ID reconciliation is attempted.
- A write needs all these lifetimes and a timestamp strictly after their starts. Equal-clock exit/close/invalidation boundaries produce UNKNOWN. Overlapping/mismatched lifetimes, reversed timestamps and foreign-generation events taint the replay. The serialized consumer does not reorder or guess missing records.
- Finalized, loss-free correlation is labeled `native_correlated`, **never `verified`**. It describes an unqualified trace relationship, not verified attribution or detection confidence. A `TraceProcess` is intentionally not the responder's `ProcessIdentity`; raw trace ticks are not process creation wall time. The report always sets `qualified: false` and `automatic_termination: false`.
- The investigation-only `attribute_path(path, start, end)` API uses an explicit interval in raw trace ticks. Two writer instances, unresolved writes for the path, or writes with an unknown path in the interval return `unknown, None`. Independent writes to unrelated known paths cannot win a fallback ranking. This API is not connected to watchdog or incident actors.

## Event loss and recovery

Evidence is withheld as UNKNOWN until replay has finished and final loss checks run. The native adapter checks ETL header event/buffer loss and consumer event loss before processing, in buffer callbacks and after processing; it also recognizes native lost-event/buffer notifications. TDH decoding failures, unsupported relevant schemas, native processing/callback/close failures, internal state/history overflow, ordering failures and generation mismatches invalidate the entire generation. Earlier provisional correlations lose their writer too. There is no timer-based recovery or cache refill that restores trust in that generation.

This conservative whole-trace revocation is necessary because final loss totals do not locate the missing lifecycle record. Retrying a lossy ETL cannot repair it. Use a separately captured trace and a fresh replay generation after correcting the collection problem. Zero reported loss does not prove that all required providers were enabled, that an upstream controller retained every event, or that the trace was authentic. Native qualification must establish those facts independently.

## Evidence established in repository checks

`tests/test_native_attribution.py` exercises synthetic normalized events for PID/TID reuse, exited/short-lived writers, missing starts, file-object reuse, readers versus writers, multiple writers, unrelated concurrent I/O, equal-clock boundaries, unknown paths, loss before finalization, ordering/generation errors and bounded overflow. It also checks that prototype identities and response-shaped identities cannot trigger automatic response.

`tests/test_windows_etw.py` exercises the strict decoder with constructed native records and an injected API boundary, including contradictory header actors, invalid properties/paths, unsupported schemas, native loss notifications, late loss counters, callback failures and handle cleanup. On x64 Windows it checks the ctypes layouts and invokes real `OpenTraceW` against a missing file to verify a safe native failure. The runtime regression also rejects claimed native/verified provenance on incoming events.

These checks establish the fail-closed correlation contract for supplied records and the tested API boundary. They do **not** establish successful native ETL decoding, capture completeness, attribution accuracy on Windows workloads, or end-to-end prevention. No real process is terminated by this validation.

## Still required for native qualification

1. Implement/review a dedicated live collection controller and session lifecycle, privileges, buffering, startup/shutdown, loss telemetry, schema/version matrix and authenticated collector custody. Do not hijack another tool's kernel session. Qualify the native ABI/TDH paths against captured traces on each supported Windows/Python/architecture combination; extend the schema allowlist only with trace-backed tests.
2. Capture reproducible, ground-truth native fixtures for concurrent readers/writers, shared handles, PID/TID/file-object reuse, short-lived processes, process exit, preexisting lifetimes and late/cross-CPU delivery. Check against independently recorded writer activity. Include loss injection, truncated traces, malformed fields, unsupported schemas, restarts and counter timing; prove that no affected evidence becomes verified.
3. Define support or explicit UNKNOWN behavior for cached/lazy/system writes, memory-mapped I/O, async writes/completions, failed/cancelled I/O, renames, hard links, alternate streams, network/removable filesystems and namespace translation. A request's issuing process alone may not identify the application causally responsible for a later disk change.
4. Establish completeness/latency limits and measured CPU/RAM/queue behavior under burst/soak workloads, with thresholds and evidence retention. This bounded offline experiment does not qualify live event ordering, timely revocation or performance.
5. Review and implement an evidence-bound response policy and stable OS process-handle containment separately. Bind source, collector generation, qualified schema/workload scope, loss state, process instance and evidence freshness; reject UNKNOWN and stale/unqualified evidence. A trace process key is not an executable identity or an OS handle. Keep automatic response disabled until independently reviewed native and containment evidence closes the release gates.

## Native API/schema references

- [Microsoft: FileIo event types and lifecycle](https://learn.microsoft.com/en-us/windows/win32/etw/fileio), [write-request payload](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-readwrite), and [create/path payload](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create).
- [Microsoft: process v2](https://learn.microsoft.com/en-us/windows/win32/etw/process-v2-typegroup1) and [thread v2](https://learn.microsoft.com/en-us/windows/win32/etw/thread-v2-typegroup1) lifecycle schemas.
- [Microsoft: EVENT_TRACE_LOGFILEW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew), [TRACE_LOGFILE_HEADER loss fields](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header), and [TDH property retrieval](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetproperty).
