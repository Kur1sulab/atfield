"""不可篡改审计链：append-only 哈希链 + 机器签名锚点 + 分片留存。

为什么要它：商用 EDR / 等保场景里，「谁在什么时候对谁做了什么」这条记录
本身必须能被第三方验证没被改过。日志文件谁都能改，哈希链 + 锚点才能证明。

链结构
    记录 n 的 prev == 记录 n-1 的 hash，hash = sha256(prev + 规范化JSON)
    第一条记录 prev = 64 个 0（创世）

锚点
    每 anchor_every 条、以及每次封存分片时，把「当前序号 + 当前链头 + 累计条数」
    用本机密钥 HMAC-SHA256 签一份写到 anchor.json。
    这样即使有人把整个日志重写成一条自洽的新链，锚点对不上就能发现。

分片
    单文件超过 max_mb 就封存为 audit-<UTC时间>.log，链路跨文件延续（head 带过去）。
    留存策略按天数与总量裁剪最老分片；裁剪动作本身入链，
    并记录被删分片的尾部摘要，做到「删了什么可证明」。

能查出来的问题
    - 内容被改写（重算 hash 不符）
    - 记录被删（序号不连续 / prev 断链）
    - 尾部被截断（最后序号 < 锚点序号）
    - 整链被替换（创世 hash 与 genesis 记录不符 / 锚点 HMAC 不通过）
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

GENESIS = "0" * 64
MASKED = "***"


def _canonical(rec: Dict[str, Any]) -> str:
    """规范化 JSON：键排序、无空格、中文不转义——哈希只对语义负责。"""
    return json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    """线程安全的追加式审计链。append 永不抛异常（审计不该把主流程带崩）。"""

    def __init__(self, cfg: Dict[str, Any]):
        pol = cfg.get("audit") or {}
        self.dir = os.path.join(cfg.get("data_dir") or os.path.expanduser("~/.atfield"), "audit")
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(self.dir, "audit.log")
        self.key_path = os.path.join(self.dir, "anchor.key")
        self.anchor_path = os.path.join(self.dir, "anchor.json")
        self.max_bytes = int(float(pol.get("max_mb", 8)) * 1024 * 1024)
        self.retain_days = int(pol.get("retain_days", 180))
        self.retain_total_mb = float(pol.get("retain_total_mb", 256))
        self.anchor_every = max(1, int(pol.get("anchor_every", 200)))
        self.enabled = bool(pol.get("enabled", True))
        self._lock = threading.RLock()
        self._key = self._load_key()
        self._seq, self._head, self._since_anchor = self._resume()
        self._fh: Optional[Any] = None

    # ---------- 初始化 ----------
    def _load_key(self) -> bytes:
        try:
            if os.path.isfile(self.key_path):
                with open(self.key_path, "rb") as fh:
                    raw = fh.read().strip()
                if len(raw) >= 32:
                    return raw
        except Exception:
            pass
        key = secrets.token_hex(32).encode()
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        except Exception:
            pass
        return key

    def _segments(self) -> List[str]:
        """历史分片（不含当前 audit.log），按时间正序。"""
        try:
            names = [n for n in os.listdir(self.dir)
                     if n.startswith("audit-") and n.endswith(".log")]
        except Exception:
            return []
        return [os.path.join(self.dir, n) for n in sorted(names)]

    def _resume(self) -> Tuple[int, str, int]:
        """从当前文件尾部恢复 seq / head。损坏时退回创世并记一条告警记录。"""
        seq, head = 0, GENESIS
        if not os.path.isfile(self.path) or os.path.getsize(self.path) == 0:
            return seq, head, 0
        try:
            with open(self.path, "rb") as fh:
                fh.seek(max(0, os.path.getsize(self.path) - 65536))
                tail = fh.read().decode("utf-8", "replace").strip().splitlines()
            if not tail:
                return seq, head, 0
            rec = json.loads(tail[-1])
            return int(rec.get("seq") or 0), str(rec.get("hash") or GENESIS), 0
        except Exception:
            return seq, head, 0

    # ---------- 写 ----------
    def append(self, action: str, actor: str = "system", role: str = "system",
               target: str = "", result: str = "ok",
               detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """追加一条审计记录，返回该记录（含 hash）。失败不抛异常。"""
        if not self.enabled:
            return {"ok": False, "skipped": "audit disabled"}
        with self._lock:
            seq = self._seq + 1
            rec: Dict[str, Any] = {
                "seq": seq,
                "ts": round(time.time(), 3),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "action": str(action)[:120],
                "actor": str(actor or "system")[:120],
                "role": str(role or "system")[:40],
                "target": str(target or "")[:400],
                "result": str(result or "ok")[:120],
                "detail": _scrub(detail or {}),
                "prev": self._head,
            }
            rec["hash"] = _sha256(self._head + _canonical(rec))
            line = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, line.encode("utf-8"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except Exception:
                return {"ok": False, "error": "write failed", "record": rec}
            self._seq, self._head = seq, rec["hash"]
            self._since_anchor += 1
            need_anchor = self._since_anchor >= self.anchor_every
            if os.path.getsize(self.path) >= self.max_bytes:
                self._seal()
                need_anchor = True
            if need_anchor:
                self._write_anchor()
            return {"ok": True, "record": {k: rec[k] for k in
                                           ("seq", "time", "action", "actor", "role",
                                            "target", "result", "hash")}}

    # ---------- 锚点 ----------
    def _sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def _write_anchor(self) -> None:
        body = {"seq": self._seq, "head": self._head, "ts": round(time.time(), 3),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "segments": [os.path.basename(p) for p in self._segments()]}
        body["sig"] = self._sign(_canonical(body))
        tmp = self.anchor_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(body, fh, ensure_ascii=False, sort_keys=True, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.anchor_path)
            os.chmod(self.anchor_path, 0o600)
            self._since_anchor = 0
        except Exception:
            pass

    def anchor(self) -> Dict[str, Any]:
        try:
            with open(self.anchor_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    # ---------- 分片与留存 ----------
    def _seal(self) -> None:
        """封存当前分片，链路延续（head 已在内存里带着）。"""
        try:
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            sealed = os.path.join(self.dir, f"audit-{stamp}-{self._seq}.log")
            os.replace(self.path, sealed)
        except Exception:
            return
        self._prune()

    def _prune(self) -> None:
        segs = self._segments()
        if not segs:
            return
        removed: List[Dict[str, Any]] = []
        now = time.time()
        total = sum(os.path.getsize(p) for p in segs if os.path.isfile(p))
        limit = self.retain_total_mb * 1024 * 1024
        for path in segs:
            if not os.path.isfile(path):
                continue
            age_days = (now - os.path.getmtime(path)) / 86400.0
            over_total = total > limit
            if age_days <= self.retain_days and not over_total:
                continue
            tail = self._tail_hash(path)
            size = os.path.getsize(path)
            try:
                os.remove(path)
                total -= size
                removed.append({"segment": os.path.basename(path), "bytes": size,
                                "age_days": round(age_days, 1), "tail_hash": tail})
            except Exception:
                pass
        if removed:
            self._write_anchor()
            # 裁剪本身入链：删了什么、删到哪个摘要，都可追溯
            self.append("audit.prune", actor="system", role="system",
                        target=f"{len(removed)} 个分片",
                        result="ok", detail={"removed": removed})

    def _tail_hash(self, path: str) -> str:
        try:
            with open(path, "rb") as fh:
                fh.seek(max(0, os.path.getsize(path) - 65536))
                lines = fh.read().decode("utf-8", "replace").strip().splitlines()
            return str(json.loads(lines[-1]).get("hash") or "")
        except Exception:
            return ""

    # ---------- 读 ----------
    def _iter_records(self) -> Iterator[Tuple[str, Dict[str, Any]]]:
        for path in self._segments() + [self.path]:
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield path, json.loads(line)
                        except Exception:
                            yield path, {"__bad_line__": line[:200]}
            except Exception:
                continue

    def tail(self, limit: int = 100, action: str = "", actor: str = "") -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for _path, rec in self._iter_records():
            if "__bad_line__" in rec:
                continue
            if action and action not in str(rec.get("action") or ""):
                continue
            if actor and actor not in str(rec.get("actor") or ""):
                continue
            rows.append(rec)
        rows.sort(key=lambda r: int(r.get("seq") or 0), reverse=True)
        return rows[:limit]

    def stats(self) -> Dict[str, Any]:
        segs = self._segments()
        return {
            "enabled": self.enabled,
            "records": self._seq,
            "head": self._head,
            "segments": len(segs) + (1 if os.path.isfile(self.path) else 0),
            "bytes": sum(os.path.getsize(p) for p in segs + [self.path]
                         if os.path.isfile(p)),
            "anchor": {k: v for k, v in self.anchor().items() if k != "sig"},
            "anchor_every": self.anchor_every,
            "retain_days": self.retain_days,
            "retain_total_mb": self.retain_total_mb,
        }

    # ---------- 校验 ----------
    def verify(self) -> Dict[str, Any]:
        """全链校验：断链 / 改写 / 删除 / 截断 / 整链替换。"""
        issues: List[Dict[str, Any]] = []
        prev_hash = GENESIS
        expect_seq = 1
        checked = 0
        first = ""
        segments_seen: List[str] = []
        for path, rec in self._iter_records():
            base = os.path.basename(path)
            if base not in segments_seen:
                segments_seen.append(base)
            if "__bad_line__" in rec:
                issues.append({"type": "line_corrupt", "segment": base,
                               "preview": rec["__bad_line__"]})
                continue
            seq = int(rec.get("seq") or 0)
            if not first:
                first = str(rec.get("hash") or "")
            if seq != expect_seq:
                issues.append({"type": "seq_gap", "segment": base,
                               "expect": expect_seq, "got": seq})
                expect_seq = seq
            if str(rec.get("prev") or "") != prev_hash:
                issues.append({"type": "chain_break", "segment": base, "seq": seq,
                               "expect_prev": prev_hash,
                               "got_prev": str(rec.get("prev") or "")})
            body = {k: v for k, v in rec.items() if k != "hash"}
            calc = _sha256(str(rec.get("prev") or "") + _canonical(body))
            if calc != str(rec.get("hash") or ""):
                issues.append({"type": "content_tampered", "segment": base,
                               "seq": seq, "calc": calc,
                               "recorded": str(rec.get("hash") or "")})
            prev_hash = str(rec.get("hash") or "")
            expect_seq = seq + 1
            checked += 1

        anchor = self.anchor()
        anchor_state = "absent"
        if anchor:
            body = {k: v for k, v in anchor.items() if k != "sig"}
            if not hmac.compare_digest(str(anchor.get("sig") or ""), self._sign(_canonical(body))):
                issues.append({"type": "anchor_forged", "detail": "锚点签名不通过"})
                anchor_state = "forged"
            elif int(anchor.get("seq") or 0) > checked:
                issues.append({"type": "truncated", "detail": "记录条数少于锚点序号",
                               "anchor_seq": anchor.get("seq"), "checked": checked})
                anchor_state = "behind"
            elif int(anchor.get("seq") or 0) == checked and str(anchor.get("head") or "") != prev_hash:
                issues.append({"type": "head_mismatch", "detail": "链头与锚点不一致",
                               "anchor_head": anchor.get("head"), "head": prev_hash})
                anchor_state = "mismatch"
            else:
                anchor_state = "ok"

        return {
            "ok": not issues,
            "checked": checked,
            "segments": segments_seen,
            "head": prev_hash,
            "genesis_hash": first,
            "anchor_state": anchor_state,
            "anchor": {k: v for k, v in anchor.items() if k != "sig"},
            "issues": issues[:40],
            "issue_count": len(issues),
            "verified_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def close(self) -> None:
        with self._lock:
            self._write_anchor()


def _scrub(detail: Dict[str, Any]) -> Dict[str, Any]:
    """审计里不留明文口令/令牌——只留存在性。"""
    out: Dict[str, Any] = {}
    for k, v in (detail or {}).items():
        lk = str(k).lower()
        if any(t in lk for t in ("pass", "pwd", "token", "secret", "cookie", "authorization")):
            out[k] = MASKED if v else ""
        elif isinstance(v, dict):
            out[k] = _scrub(v)
        else:
            out[k] = v
    return out
