"""采集器注册表。新增采集器只需在这里登记一行。"""
from __future__ import annotations

from typing import List

from .base import Collector
from .baseline import BaselineCollector
from .integrity import IntegrityCollector
from .logstream import LogStreamCollector
from .network import NetworkCollector
from .persistence import LoginItemCollector, PersistenceCollector
from .privileged import PrivilegedCollector
from .process import FilelessWatcher, ProcessCollector
from .session import AuthLogCollector, SessionCollector

REGISTRY = [
    ProcessCollector,
    NetworkCollector,
    SessionCollector,
    PersistenceCollector,
    IntegrityCollector,
    BaselineCollector,
    LogStreamCollector,
    PrivilegedCollector,
    AuthLogCollector,
    LoginItemCollector,
    FilelessWatcher,
]


def build(cfg, store) -> List[Collector]:
    out: List[Collector] = []
    for cls in REGISTRY:
        try:
            out.append(cls(cfg, store))
        except Exception:
            continue
    return out


__all__ = ["REGISTRY", "build", "Collector"]
