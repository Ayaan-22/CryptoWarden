"""Fail-closed response with stable process identity and confirmed exit outcomes."""

import os

import psutil

from src.config import config, normalize_path, normalize_process_name
from src.models import ActionResult, ProcessIdentity

# The shipped collector is watchdog; it cannot authenticate a file writer.
# Automatic termination stays disabled until a separately qualified native collector exists.
AUTOMATIC_TERMINATION_AVAILABLE = False
ESSENTIAL_PROCESSES = frozenset(
    {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
    }
)


def is_critical_process(pid):
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.IsProcessCritical.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return True  # Cannot query critical status: fail closed.
    try:
        critical = wintypes.BOOL()
        return not kernel.IsProcessCritical(handle, ctypes.byref(critical)) or bool(critical.value)
    finally:
        kernel.CloseHandle(handle)


class Responder:
    def __init__(
        self, settings=None, process_factory=psutil.Process, critical_check=is_critical_process
    ):
        self.settings = settings or config["response"]
        self.process_factory = process_factory
        self.critical_check = critical_check
        self._own_pid = os.getpid()
        self.protected = ESSENTIAL_PROCESSES | frozenset(
            map(normalize_process_name, self.settings["protected_processes"])
        )

    def _validate(self, process, identity):
        if identity.pid in {0, 4, self._own_pid}:
            return "Protected process"
        try:
            if (
                process.pid != identity.pid
                or abs(process.create_time() - identity.create_time) > 0.000001
            ):
                return "Process instance changed"
            if not process.is_running():
                return "Process already exited"
            if normalize_process_name(process.name()) in self.protected:
                return "Protected process"
            if normalize_path(process.exe()) != normalize_path(identity.executable):
                return "Executable identity changed"
            if self.critical_check(identity.pid):
                return "Process is critical or critical status is unavailable"
        except psutil.NoSuchProcess:
            return "Process already exited"
        except (psutil.Error, OSError):
            return "Process identity cannot be verified"
        return None

    def take_action(self, identity, reason, manual=False):
        mode = self.settings["mode"]
        if mode not in {"alert_only", "dry_run", "terminate"}:
            return ActionResult("refused", "Invalid response mode")
        if mode != "terminate":
            return ActionResult("alert_only", f"Response mode is {mode}")
        if not manual and not AUTOMATIC_TERMINATION_AVAILABLE:
            return ActionResult(
                "refused",
                "Automatic termination unavailable: native writer attribution is not qualified",
            )
        if (
            not isinstance(identity, ProcessIdentity)
            or type(identity.pid) is not int
            or identity.pid <= 0
            or not identity.executable
        ):
            return ActionResult("refused", "Verified process-instance identity required")
        try:
            root = self.process_factory(identity.pid)
            error = self._validate(root, identity)
            if error:
                return ActionResult(
                    "already_exited" if error == "Process already exited" else "refused", error
                )
            targets = [(root, identity)]
            if self.settings["terminate_tree"]:
                for child in root.children(recursive=True):
                    child_identity = ProcessIdentity(
                        child.pid, child.create_time(), child.name(), child.exe()
                    )
                    targets.append((child, child_identity))
            # Preflight every target; never blindly kill a protected descendant.
            for process, captured in targets:
                error = self._validate(process, captured)
                if error:
                    return ActionResult("refused", f"Containment preflight: {error}")
            outcomes = []
            for process, captured in reversed(targets):
                error = self._validate(process, captured)
                if error:
                    outcomes.append({"pid": captured.pid, "status": "refused", "reason": error})
                    continue
                try:
                    process.kill()
                    process.wait(timeout=3)
                    outcomes.append({"pid": captured.pid, "status": "terminated"})
                except psutil.NoSuchProcess:
                    outcomes.append({"pid": captured.pid, "status": "already_exited"})
                except (psutil.Error, OSError) as failure:
                    outcomes.append(
                        {"pid": captured.pid, "status": "failed", "reason": str(failure)}
                    )
            success = all(row["status"] == "terminated" for row in outcomes)
            return ActionResult(
                "terminated"
                if success
                else "partial"
                if any(row["status"] == "terminated" for row in outcomes)
                else "failed",
                "Exit confirmed"
                if success
                else "Containment incomplete; review individual outcomes",
                tuple(outcomes),
            )
        except psutil.NoSuchProcess:
            return ActionResult("already_exited", "Process exited before action")
        except (psutil.Error, OSError) as failure:
            return ActionResult("failed", str(failure))
