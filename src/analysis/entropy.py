"""Bounded sampling with explicit unreadable/too-small outcomes."""

import math
import os
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from src.config import ENTROPY_CHECK_SAMPLES, MIN_FILE_SIZE_FOR_ENTROPY
from src.monitoring.honey_pot import safe_root


@dataclass(frozen=True)
class EntropyResult:
    value: float | None
    status: str
    size: int = 0


def calculate_shannon_entropy(data):
    if not data:
        return 0.0
    size = len(data)
    return -sum((n / size) * math.log2(n / size) for n in Counter(data).values())


def sample_file_entropy(filepath, samples=ENTROPY_CHECK_SAMPLES, minimum=MIN_FILE_SIZE_FOR_ENTROPY):
    try:
        if not safe_root(Path(filepath).parent):
            return EntropyResult(None, "unsafe_parent")
        info = os.lstat(filepath)
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            return EntropyResult(None, "reparse_point")
        if not stat.S_ISREG(info.st_mode):
            return EntropyResult(None, "not_regular")
        with open(filepath, "rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            if size < minimum:
                return EntropyResult(None, "too_small", size)
            count = max(1, min(64, int(samples)))
            chunks = []
            for index in range(count):
                stream.seek(int(max(0, size - 1024) * index / max(1, count - 1)))
                chunks.append(stream.read(1024))
        return EntropyResult(calculate_shannon_entropy(b"".join(chunks)), "sampled", size)
    except OSError:
        return EntropyResult(None, "unreadable")


def calculate_file_entropy(filepath):
    """Compatibility scalar; the pipeline uses the richer result."""
    return sample_file_entropy(filepath).value or 0.0
