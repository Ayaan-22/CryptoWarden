"""Private runtime directory and OS-held single-instance ownership."""

import csv
import io
import os
import subprocess
from pathlib import Path


def secure_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    from src.monitoring.honey_pot import safe_root

    if not safe_root(path):
        raise ValueError("Runtime directory must be local and cannot traverse reparse points")
    if os.name == "nt":
        # SID-based ACL avoids locale-sensitive usernames; no shell or command interpolation.
        flags = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(
            [
                str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "whoami.exe"),
                "/user",
                "/fo",
                "csv",
                "/nh",
            ],
            capture_output=True,
            text=True,
            check=True,
            creationflags=flags,
        )
        sid = next(csv.reader(io.StringIO(result.stdout.strip())))[1]
        import ctypes
        from ctypes import wintypes

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        convert.restype = wintypes.BOOL
        get_dacl = advapi.GetSecurityDescriptorDacl
        get_dacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        get_dacl.restype = wintypes.BOOL
        set_security = advapi.SetNamedSecurityInfoW
        set_security.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        set_security.restype = wintypes.DWORD
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        descriptor = ctypes.c_void_p()
        # Replace the DACL rather than preserving potentially broad explicit grants.
        if not convert(
            f"D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)", 1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
            if not get_dacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            result = set_security(str(path), 1, 0x80000004, None, None, dacl, None)
            if result:
                raise ctypes.WinError(result)
        finally:
            kernel.LocalFree(descriptor)
    else:
        path.chmod(0o700)


class InstanceLock:
    def __init__(self, directory):
        self.path = Path(directory) / "engine.lock"
        self.stream = None

    def acquire(self):
        try:
            self.stream = open(self.path, "a+b")
            if os.fstat(self.stream.fileno()).st_size == 0:
                self.stream.write(b"0")
                self.stream.flush()
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if self.stream:
                self.stream.close()
            self.stream = None
            raise RuntimeError("Another CryptoWarden engine owns this runtime directory") from error

    def release(self):
        if self.stream:
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream, fcntl.LOCK_UN)
            self.stream.close()
            self.stream = None
