"""Explicit evidence and action contracts; a handle association is never writer proof."""

import time
from dataclasses import asdict, dataclass, field
from uuid import uuid4


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    create_time: float
    name: str
    executable: str

    @property
    def key(self):
        return f"{self.pid}:{self.create_time:.6f}"

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ActionResult:
    status: str
    reason: str
    targets: tuple = ()

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class DetectionResult:
    detected: bool
    score: int
    signals: tuple
    severity: str = "medium"

    @property
    def reason(self):
        return " · ".join(self.signals)


@dataclass
class Incident:
    reason: str
    severity: str
    path: str
    signals: list
    process: dict | None = None
    attribution: str = "unknown"
    action: dict = field(
        default_factory=lambda: ActionResult("alert_only", "No action requested").to_dict()
    )
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time.time)
    status: str = "open"
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
