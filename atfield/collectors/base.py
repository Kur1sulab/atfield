"""采集器基类：统一「可用性自检 + 周期采集 + 状态上报」形状。"""
from __future__ import annotations

import time
import traceback
from typing import Any, Dict, List

from ..model import Event


class Collector:
    name = "base"
    interval = 5.0
    mode = "poll"          # poll | stream

    def __init__(self, cfg: Dict[str, Any], store):
        self.cfg = cfg
        self.store = store
        settings = (cfg.get("collectors") or {}).get(self.name) or {}
        self.settings = settings
        self.desired = bool(settings.get("enabled", True))
        self.interval = float(settings.get("interval", self.interval) or self.interval)
        self.error = ""
        self.available = True
        try:
            self.available = self.probe()
        except Exception as exc:  # 采集器探测失败不应影响整体
            self.available = False
            self.error = f"{type(exc).__name__}: {exc}"
        self.enabled = self.desired and self.available

    # 子类可覆盖：探测依赖是否具备（如命令是否存在、权限是否足够）
    def probe(self) -> bool:
        return True

    def collect(self) -> List[Event]:
        return []

    def close(self) -> None:
        return None

    def detail(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "interval": self.interval,
            "enabled": self.enabled,
            "available": self.available,
            "reason": self.error,
        }

    def run_once(self) -> List[Event]:
        t0 = time.time()
        try:
            events = self.collect() or []
            self.store.note_collector(self.name, True, (time.time() - t0) * 1000)
            return events
        except Exception as exc:
            self.store.note_collector(
                self.name, False, (time.time() - t0) * 1000,
                f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=2)}",
            )
            return []
