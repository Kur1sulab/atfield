"""诱饵 / Canary Token：主动防御的最后一道「不可能误报」的告警源。

原理：正常业务永远不会去读这些文件。任何访问 = 有人在你机器上翻箱倒柜。
实现：非特权下用 atime/mtime + 内容哈希轮询（APFS 默认维护 atime）。
      有 root 时可叠加 eslogger 的 open 事件做到实时。
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import string
import time
from typing import Any, Dict, List

from .model import Event

HOME = os.path.expanduser("~")

# 诱饵模板：(相对路径, 内容生成器, 说明)
DECOY_TEMPLATES = [
    ("Documents/账号备份.txt",
     "=== 内网账号备份 ===\nVPN: 见邮件\n邮箱: ops@example.local\n"
     "数据库: 10.0.0.12:3306\n备注: 请勿外传\n",
     "看起来像凭据清单的文件"),
    ("Documents/工资表-2026.xlsx",
     "PK\x03\x04FAKE-XLSX-CANARY-CONTENT\n", "伪装成财务报表"),
    ("Desktop/运维记录.md",
     "# 服务器运维记录\n\n- 跳板机 10.0.0.5\n- 备份账号 backup\n", "伪装成运维笔记"),
    (".ssh/id_rsa_backup",
     "-----BEGIN FAKE PRIVATE KEY-----\nDECOY-CANARY-DO-NOT-TRUST\n"
     "-----END FAKE PRIVATE KEY-----\n", "伪装成私钥备份"),
    ("Library/Application Support/Notes/keychain-export.txt",
     "keychain export (canary)\n", "伪装成钥匙串导出"),
    ("Downloads/客户资料-合同.pdf",
     "%PDF-1.4\n% CANARY DECOY\n", "伪装成客户资料"),
]


def _digest(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


class Canary:
    def __init__(self, cfg: Dict[str, Any], store):
        self.cfg = cfg
        self.store = store
        self.dir = os.path.join(cfg.get("data_dir") or os.path.expanduser("~/.atfield"), "canary")
        os.makedirs(self.dir, exist_ok=True)
        self.index_path = os.path.join(self.dir, "index.json")
        self.items: Dict[str, dict] = {}
        self._load()
        store.set_state("canary", self.status())

    def _load(self) -> None:
        try:
            with open(self.index_path, "r", encoding="utf-8") as fh:
                self.items = json.load(fh) or {}
        except Exception:
            self.items = {}

    def _save(self) -> None:
        try:
            tmp = self.index_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.items, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.index_path)
        except Exception:
            pass

    # ---------- 部署 ----------
    def deploy(self, count: int = 0) -> Dict[str, Any]:
        """在用户家目录散布诱饵。只写「不存在」的路径，绝不覆盖真实文件。"""
        created: List[str] = []
        adopted: List[str] = []
        tpls = DECOY_TEMPLATES if not count else DECOY_TEMPLATES[:count]
        for rel, content, note in tpls:
            full = os.path.join(HOME, rel)
            if os.path.exists(full):
                # 已存在：只有「内容与模板一致」才认作自己以前部署的并登记（不重写）
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        cur = fh.read()
                except Exception:
                    cur = ""
                if cur.strip() and cur.strip() == content.strip() and full not in self.items:
                    digest = _digest(full)
                    st = os.stat(full)
                    self.items[full] = {
                        "path": full, "note": note, "size": st.st_size,
                        "digest": digest, "atime": st.st_atime,
                        "mtime": st.st_mtime, "deployed": time.time(),
                        "trips": 0, "adopted": True,
                    }
                    adopted.append(full)
                continue                      # 绝不覆盖真实文件（安全红线）
            try:
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w", encoding="utf-8") as fh:
                    fh.write(content)
                # 先算哈希再取 stat：读文件会推进 atime，顺序反了会让首次轮询误判「被读取」
                digest = _digest(full)
                st = os.stat(full)
                self.items[full] = {
                    "path": full, "note": note, "size": st.st_size,
                    "digest": digest, "atime": st.st_atime,
                    "mtime": st.st_mtime, "deployed": time.time(),
                    "trips": 0,
                }
                created.append(full)
            except Exception:
                continue
        self._save()
        self.store.set_state("canary", self.status())
        if created:
            self.store.log_action("analyst", "canary:deploy", f"{len(created)} 个诱饵",
                                  ", ".join(os.path.basename(c) for c in created))
        if adopted:
            self.store.log_action("analyst", "canary:adopt", f"{len(adopted)} 个遗留诱饵",
                                  ", ".join(os.path.basename(c) for c in adopted))
        parts = []
        if created:
            parts.append(f"已部署 {len(created)} 个诱饵文件")
        if adopted:
            parts.append(f"接管 {len(adopted)} 个此前部署的诱饵")
        return {"ok": True, "created": created, "adopted": adopted,
                "detail": "；".join(parts) if parts else "没有新增（目标路径已存在真实文件）"}

    def undeploy(self) -> Dict[str, Any]:
        removed = 0
        for path in list(self.items):
            try:
                if os.path.exists(path):
                    os.remove(path)
                    removed += 1
            except Exception:
                pass
            self.items.pop(path, None)
        self._save()
        self.store.set_state("canary", self.status())
        return {"ok": True, "detail": f"已移除 {removed} 个诱饵"}

    # ---------- 监控 ----------
    def poll(self) -> List[Event]:
        now = time.time()
        events: List[Event] = []
        for path, rec in list(self.items.items()):
            if not os.path.exists(path):
                events.append(Event(
                    kind="canary.trip", source="canary", ts=now, path=path,
                    process=os.path.basename(path), severity="high",
                    subject={"reason": "诱饵文件被删除/移走", "note": rec.get("note", "")},
                ))
                self.items.pop(path, None)
                self._save()
                continue
            try:
                st = os.stat(path)
            except Exception:
                continue
            tripped = ""
            sev = "medium"
            grace = (now - float(rec.get("deployed") or 0)) < 300
            if st.st_size != rec.get("size"):
                tripped = "诱饵内容被改写（大小变化）"
                sev = "critical"
            elif not grace and st.st_atime - (rec.get("atime") or 0) > 2.0:
                tripped = "诱饵文件被读取（atime 前进；索引器/备份也会读取，需结合进程判断）"
                sev = "medium"
            elif _digest(path) != rec.get("digest"):
                tripped = "诱饵内容哈希变化"
                sev = "critical"

            if tripped:
                rec["trips"] = int(rec.get("trips") or 0) + 1
                rec["atime"] = st.st_atime
                rec["mtime"] = st.st_mtime
                rec["size"] = st.st_size
                rec["digest"] = _digest(path)
                rec["last_trip"] = now
                self.items[path] = rec
                self._save()
                events.append(Event(
                    kind="canary.trip", source="canary", ts=now, path=path,
                    process=os.path.basename(path), severity=sev,
                    subject={"reason": tripped, "note": rec.get("note", ""),
                             "trips": rec["trips"]},
                ))
        self.store.set_state("canary", self.status())
        return events

    # ---------- 状态 ----------
    def status(self) -> Dict[str, Any]:
        items = sorted(self.items.values(), key=lambda r: -(r.get("trips") or 0))
        return {
            "count": len(items),
            "trips": sum(1 for i in items if (i.get("trips") or 0) > 0),
            "items": items,
            "ts": time.time(),
        }
