"""统一事件模型（UEM）：所有采集器输出同一形状，检测/关联/呈现只认这一层。

数据流：Collector -> Event -> Rule -> Finding -> Correlator -> Incident -> 态势/报告
"""
from __future__ import annotations

import socket
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_CN = {"info": "信息", "low": "低危", "medium": "中危", "high": "高危", "critical": "严重"}

STATUS_CN = {
    "pass": "通过",
    "warn": "关注",
    "fail": "不合格",
    "unknown": "未知",
}


def now() -> float:
    return time.time()


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def hhmmss(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def sev_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def sev_rank(s: str) -> int:
    return SEVERITY_ORDER.get(s, 0)


@dataclass
class Event:
    """一条归一化终端事件。"""

    kind: str
    source: str
    ts: float = field(default_factory=now)
    host: str = ""
    user: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process: str = ""
    cmdline: str = ""
    path: str = ""
    severity: str = "info"
    subject: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    eid: str = ""

    def __post_init__(self) -> None:
        if not self.eid:
            self.eid = uuid.uuid4().hex[:12]
        if self.severity not in SEVERITY_ORDER:
            self.severity = "info"
        if not self.host:
            try:
                self.host = socket.gethostname()
            except Exception:
                self.host = "localhost"

    # 搜索用的扁平文本（前端过滤 / 报告用）
    @property
    def text(self) -> str:
        parts = [self.kind, self.process, self.cmdline, self.path, self.user,
                 str(self.pid or ""), self.host]
        for v in self.subject.values():
            parts.append(str(v))
        return " ".join(p for p in parts if p)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["time"] = iso(self.ts)
        d["clock"] = hhmmss(self.ts)
        d["severity_cn"] = SEVERITY_CN.get(self.severity, self.severity)
        d["text"] = self.text
        return d


@dataclass
class Finding:
    """规则命中。"""

    rule_id: str
    name: str
    severity: str
    event: Event
    actor: str = ""                      # 关联键：根进程 pid / 主机
    tags: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    detail: str = ""
    advice: str = ""
    ts: float = field(default_factory=now)
    fid: str = ""

    def __post_init__(self) -> None:
        if not self.fid:
            self.fid = uuid.uuid4().hex[:10]
        if not self.ts:
            self.ts = self.event.ts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fid": self.fid,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "severity_cn": SEVERITY_CN.get(self.severity, self.severity),
            "actor": self.actor,
            "tags": list(self.tags),
            "mitre": list(self.mitre),
            "detail": self.detail,
            "advice": self.advice,
            "ts": self.ts,
            "time": iso(self.ts),
            "event": self.event.to_dict(),
        }


@dataclass
class Incident:
    """攻击链：多条 Finding 串成一条可解释的时序。"""

    title: str
    template_id: str
    severity: str
    stages: List[Dict[str, Any]] = field(default_factory=list)
    host: str = ""
    actor: str = ""
    first_seen: float = field(default_factory=now)
    last_seen: float = field(default_factory=now)
    score: float = 0.0
    summary: str = ""
    advice: str = ""
    iid: str = ""

    def __post_init__(self) -> None:
        if not self.iid:
            self.iid = uuid.uuid4().hex[:10]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iid": self.iid,
            "title": self.title,
            "template_id": self.template_id,
            "severity": self.severity,
            "severity_cn": SEVERITY_CN.get(self.severity, self.severity),
            "host": self.host,
            "actor": self.actor,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_time": iso(self.first_seen),
            "last_time": iso(self.last_seen),
            "duration": max(0, int(self.last_seen - self.first_seen)),
            "score": round(self.score, 1),
            "summary": self.summary,
            "advice": self.advice,
            "stages": self.stages,
        }


def finding_from_raw(d: Dict[str, Any]) -> Finding:
    """从持久化 dict 还原（用于重启后加载历史）。"""
    ev = Event(**{k: v for k, v in d.get("event", {}).items()
                  if k in Event.__dataclass_fields__})
    return Finding(
        rule_id=d.get("rule_id", "?"),
        name=d.get("name", "?"),
        severity=d.get("severity", "info"),
        event=ev,
        actor=d.get("actor", ""),
        tags=d.get("tags", []),
        mitre=d.get("mitre", []),
        detail=d.get("detail", ""),
        advice=d.get("advice", ""),
        ts=d.get("ts", ev.ts),
        fid=d.get("fid", ""),
    )
