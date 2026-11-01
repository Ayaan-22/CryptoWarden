# Security boundaries

Report suspected vulnerabilities privately to the repository maintainer before opening an issue with exploit details. Do not include access keys, incident exports, personal file paths, or account credentials in public reports.

CryptoWarden 3.1 is a hardened local monitoring and operator-response release candidate. It is not a certified endpoint protection product. The shipped watchdog collector cannot authenticate a file writer, and automatic termination is unavailable. In terminate mode, authenticated operators can explicitly select a current process instance for review and request a guarded response. Operator selection is not evidence that the process caused a file change.

The dashboard binds only to a loopback IP, uses ephemeral access keys or an operator-supplied environment secret, HTTP-only SameSite cookies, exact Host/Origin checks, CSRF checks, bounded WebSocket delivery, command rate limits, and a durable idempotency journal. Do not publish this listener directly, proxy it to a network, or reuse its key for another service. Shared-device multi-user isolation is not a supported deployment model.

The runtime directory is private to the current Windows SID and SYSTEM (0700 on POSIX). It holds file paths, incident details, executable review fingerprints, logs, and canary ownership records. This protects against other ordinary accounts, not against the same user, local administrators, compromised kernel code, or offline disk access. A future service deployment needs a dedicated service identity and reviewed IPC/installer boundaries.

Canary cleanup previews by default and removes only manifest-owned, unchanged, identity-matching files. Existing legacy filename matches are never adopted. Changed or replaced canaries require operator review. No file rollback, backup, or recovery is supplied.

Process trees are a best-effort snapshot when explicitly enabled; workers created after enumeration, daemonized workers, kernel operations, and privileged tampering require stronger OS containment. Critical processes and processes whose identity or critical status cannot be checked are refused.

Runtime and development dependencies are pinned with release hashes. Review regenerated locks and run the dependency audit and Windows/browser checks. Hashes establish distribution identity, not publisher trust or a permanent absence of vulnerabilities.
