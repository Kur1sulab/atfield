"""规则/剧本更新通道：推得出去、验得回来、坏了自己退。

商用产品不能只有「发版让客户重装」这一条路：
检测规则要能按通道推、推送必须可验真、验真失败要能自动回到上一个好版本。

四道闸
    1. 签名     manifest 用更新密钥 HMAC-SHA256 签名，改一个字节就对不上
    2. 完整性   每个文件声明 sha256 + size，逐个核对
    3. 路径    只允许落在 rules/ 与 playbooks/ 下，禁 `..`、禁绝对路径
    4. 健康探针 应用后解析全部规则包 + 剧本；任一项不可用即回滚

熔断
    记录最近尝试；连续 failure_threshold 次失败（或健康探针不过）→ 打开熔断，
    在 cooldown 秒内拒绝任何新应用，并把当前资产回滚到 last-known-good。
    熔断状态可查、可手工复位（--update-reset），但复位本身入审计链。

状态文件  ~/.atfield/update/state.json
备份归档  ~/.atfield/update/lkg/<version>-<ts>.tar.gz
签名密钥  ~/.atfield/update/update.key（0600；正式发布时用厂商私钥，本机仅演示）
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__, rules_ext

MANAGED_ROOTS = ("rules", "playbooks")
SCHEMA = 1


def _canonical(rec: Dict[str, Any]) -> str:
    return json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(rel: str) -> bool:
    """只允许 rules/… 或 playbooks/…，且不含 .. 与绝对路径。"""
    if not rel or rel.startswith("/") or "\\" in rel:
        return False
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    return parts[0] in MANAGED_ROOTS and rel.endswith((".yaml", ".yml"))


class Updates:
    def __init__(self, cfg: Dict[str, Any]):
        ucfg = cfg.get("updates") or {}
        self.cfg = cfg
        self.data_dir = cfg.get("data_dir") or os.path.expanduser("~/.atfield")
        self.root = os.path.join(self.data_dir, "update")
        self.lkg_dir = os.path.join(self.root, "lkg")
        os.makedirs(self.lkg_dir, mode=0o700, exist_ok=True)
        self.state_path = os.path.join(self.root, "state.json")
        self.key_path = os.path.join(self.root, "update.key")
        self.channel = str(ucfg.get("channel") or "stable")
        self.failure_threshold = int(ucfg.get("failure_threshold", 2))
        self.cooldown = int(ucfg.get("cooldown_seconds", 6 * 3600))
        self.min_rules = int(ucfg.get("min_rules", 1))
        self.require_sig = bool(ucfg.get("require_signature", True))
        self._lock = threading.RLock()
        self._key = self._load_key()
        self._state = self._load_state()
        self._probes: List[Callable[[], Dict[str, Any]]] = []
        self.audit = None

    # ---------- 基础 ----------
    def set_audit(self, audit) -> None:
        self.audit = audit

    def register_probe(self, fn: Callable[[], Dict[str, Any]]) -> None:
        """健康探针：应用后跑一遍，任何一个探针不过就回滚。"""
        self._probes.append(fn)

    def _audit(self, action: str, actor: str, role: str, target: str, result: str,
               detail: Optional[Dict[str, Any]] = None) -> None:
        if self.audit is not None:
            try:
                self.audit.append(action, actor=actor, role=role, target=target,
                                  result=result, detail=detail or {})
            except Exception:
                pass

    def _load_key(self) -> bytes:
        try:
            if os.path.isfile(self.key_path):
                with open(self.key_path, "rb") as fh:
                    raw = fh.read().strip()
                if len(raw) >= 32:
                    return raw
        except Exception:
            pass
        key = hashlib.sha256(os.urandom(64) + b"atfield-update-key").hexdigest().encode()
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        except Exception:
            pass
        return key

    def key_fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()[:16]

    def sign(self, manifest: Dict[str, Any]) -> str:
        body = {k: v for k, v in manifest.items() if k != "sig"}
        return hmac.new(self._key, _canonical(body).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _load_state(self) -> Dict[str, Any]:
        base = {"channel": self.channel, "schema": SCHEMA,
                "installed_version": __version__, "installed_at": 0.0,
                "installed_cn": "", "files": [], "attempts": [],
                "fail_count": 0, "open_until": 0.0,
                "lkg_version": "", "lkg_archive": ""}
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                base.update(data)
        except Exception:
            pass
        return base

    def _save_state(self) -> None:
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._state, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)
        try:
            os.chmod(self.state_path, 0o600)
        except Exception:
            pass

    # ---------- 查询 ----------
    def breaker(self) -> Dict[str, Any]:
        left = max(0, int(float(self._state.get("open_until") or 0) - time.time()))
        return {"open": left > 0, "seconds_left": left,
                "fail_count": int(self._state.get("fail_count") or 0),
                "threshold": self.failure_threshold,
                "cooldown_seconds": self.cooldown}

    def status(self) -> Dict[str, Any]:
        st = self._state
        attempts = list(st.get("attempts") or [])
        return {
            "channel": st.get("channel") or self.channel,
            "current_version": __version__,
            "installed_version": st.get("installed_version") or __version__,
            "installed_cn": st.get("installed_cn") or "",
            "managed_files": len(st.get("files") or []),
            "lkg_version": st.get("lkg_version") or "",
            "lkg_archive": os.path.basename(st.get("lkg_archive") or ""),
            "breaker": self.breaker(),
            "require_signature": self.require_sig,
            "key_fingerprint": self.key_fingerprint(),
            "probes": len(self._probes) + 2,
            "recent": attempts[-8:][::-1],
            "roots": list(MANAGED_ROOTS),
        }

    # ---------- 应用 ----------
    def apply(self, bundle_dir: str, actor: str = "system", role: str = "system",
              force: bool = False) -> Dict[str, Any]:
        """应用一个更新包目录（含 manifest.json 与按相对路径放置的文件）。"""
        with self._lock:
            br = self.breaker()
            if br["open"] and not force:
                self._audit("update.apply", actor=actor, role=role,
                            target=bundle_dir, result="blocked",
                            detail={"理由": "熔断中", "剩余秒": br["seconds_left"]})
                return {"ok": False, "error": f"更新通道熔断中，还需 {br['seconds_left']} 秒",
                        "breaker": br}
            try:
                manifest = self._read_manifest(bundle_dir)
            except Exception as exc:
                return self._fail(bundle_dir, actor, role, f"manifest 不可用: {exc}")
            bad = self._verify_manifest(bundle_dir, manifest, force)
            if bad:
                return self._fail(bundle_dir, actor, role, bad, version=manifest.get("version"))
            version = str(manifest.get("version") or "")
            files: List[Dict[str, Any]] = manifest.get("files") or []
            archive = self._backup(version)
            prev_files = list(self._state.get("files") or [])
            applied: List[str] = []
            try:
                for item in files:
                    rel = str(item.get("path") or "")
                    src = os.path.join(bundle_dir, rel)
                    dst = os.path.join(self.data_dir, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), prefix=".upd-")
                    os.close(fd)
                    shutil.copyfile(src, tmp)
                    os.chmod(tmp, 0o644)
                    os.replace(tmp, dst)
                    applied.append(rel)
                # 上一版托管、这一版不再提供的文件要清掉，否则残留规则继续生效
                stale = [f for f in prev_files if f not in applied]
                for rel in stale:
                    if not _safe_rel(rel):
                        continue
                    path = os.path.join(self.data_dir, rel)
                    if os.path.isfile(path):
                        try:
                            os.remove(path)
                        except Exception:
                            pass
            except Exception as exc:
                self._restore(archive)
                return self._fail(bundle_dir, actor, role, f"写入失败已回滚: {exc}",
                                  version=version)

            probe = self._probe()
            if not probe.get("ok"):
                self._restore(archive)
                detail = {"探针": probe.get("checks"), "已回滚到": self._state.get("lkg_version")}
                self._state["files"] = prev_files
                self._save_state()
                return self._fail(bundle_dir, actor, role,
                                  f"健康探针未通过，已回滚：{probe.get('reason') or ''}".strip(),
                                  version=version, detail=detail)

            self._state.update({
                "installed_version": version,
                "installed_at": time.time(),
                "installed_cn": time.strftime("%Y-%m-%d %H:%M:%S"),
                "files": applied,
                "fail_count": 0,
                "open_until": 0.0,
            })
            self._push_attempt({"version": version, "ts": time.time(),
                                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "result": "ok", "reason": "", "files": len(applied)})
            self._save_state()
            self._audit("update.apply", actor=actor, role=role,
                        target=f"{version}（{len(applied)} 个文件）", result="ok",
                        detail={"通道": self._state.get("channel"),
                                "签名指纹": self.key_fingerprint(),
                                "探针": probe.get("checks")})
            return {"ok": True, "version": version, "files": applied,
                    "rolled_back_stale": [f for f in prev_files if f not in applied],
                    "probe": probe, "breaker": self.breaker(),
                    "backup": os.path.basename(archive)}

    def _read_manifest(self, bundle_dir: str) -> Dict[str, Any]:
        path = os.path.join(bundle_dir, "manifest.json")
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("manifest 顶层不是对象")
        return data

    def _verify_manifest(self, bundle_dir: str, manifest: Dict[str, Any],
                         force: bool) -> str:
        if int(manifest.get("schema") or 0) != SCHEMA:
            return f"manifest schema 不支持：{manifest.get('schema')}"
        version = str(manifest.get("version") or "")
        if not version:
            return "manifest 缺少 version"
        if self.require_sig:
            sig = str(manifest.get("sig") or "")
            if not sig:
                return "manifest 未签名（require_signature=true）"
            if not hmac.compare_digest(sig, self.sign(manifest)):
                return "manifest 签名不通过（包被改过，或不是同一个发布密钥）"
        mchannel = str(manifest.get("channel") or "stable")
        if mchannel != self.channel and not force:
            return f"通道不匹配：包是 {mchannel}，本机订阅 {self.channel}"
        min_version = str(manifest.get("min_version") or "")
        if min_version and __version__ < min_version and not force:
            return f"要求宿主版本 ≥ {min_version}，当前 {__version__}"
        if version == str(self._state.get("installed_version") or "") and not force:
            return f"版本 {version} 已安装（如需重装加 --force）"
        files = manifest.get("files")
        if not isinstance(files, list) or not files:
            return "manifest 没有文件清单"
        for item in files:
            if not isinstance(item, dict):
                return "文件清单格式错误"
            rel = str(item.get("path") or "")
            if not _safe_rel(rel):
                return f"非法路径（只允许 rules/ 与 playbooks/ 下的 yaml）：{rel}"
            src = os.path.join(bundle_dir, rel)
            if not os.path.isfile(src):
                return f"包内缺少文件：{rel}"
            size = os.path.getsize(src)
            if int(item.get("size") or -1) != size:
                return f"大小不符：{rel}（声明 {item.get('size')}，实际 {size}）"
            if str(item.get("sha256") or "") != _sha256_file(src):
                return f"哈希不符：{rel}"
        return ""

    # ---------- 备份 / 还原 ----------
    def _backup(self, new_version: str) -> str:
        stamp = time.strftime("%Y%m%dT%H%M%S")
        path = os.path.join(self.lkg_dir, f"{self._state.get('installed_version') or 'init'}-{stamp}.tar.gz")
        with tarfile.open(path, "w:gz") as tar:
            for rel in self._state.get("files") or []:
                if not _safe_rel(rel):
                    continue
                full = os.path.join(self.data_dir, rel)
                if os.path.isfile(full):
                    tar.add(full, arcname=rel)
            meta = os.path.join(self.root, "lkg-meta.json")
            with open(meta, "w", encoding="utf-8") as fh:
                json.dump({"version": self._state.get("installed_version") or "",
                           "files": self._state.get("files") or [],
                           "created": time.strftime("%Y-%m-%d %H:%M:%S")},
                          fh, ensure_ascii=False, indent=2)
            tar.add(meta, arcname="lkg-meta.json")
        self._state["lkg_version"] = self._state.get("installed_version") or ""
        self._state["lkg_archive"] = path
        self._save_state()
        # 只留最近 10 份 LKG，避免长跑占盘
        olds = sorted((p for p in os.listdir(self.lkg_dir) if p.endswith(".tar.gz")))
        for name in olds[:-10]:
            try:
                os.remove(os.path.join(self.lkg_dir, name))
            except Exception:
                pass
        return path

    def _restore(self, archive: str) -> bool:
        if not archive or not os.path.isfile(archive):
            return False
        try:
            with tarfile.open(archive, "r:gz") as tar:
                meta: Dict[str, Any] = {}
                for member in tar.getmembers():
                    if member.name == "lkg-meta.json":
                        fh = tar.extractfile(member)
                        if fh:
                            meta = json.loads(fh.read().decode("utf-8"))
                        continue
                    if not _safe_rel(member.name):
                        continue
                    dst = os.path.join(self.data_dir, member.name)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    src = tar.extractfile(member)
                    if not src:
                        continue
                    data = src.read()
                    tmp = dst + ".restore"
                    with open(tmp, "wb") as out:
                        out.write(data)
                    os.chmod(tmp, 0o644)
                    os.replace(tmp, dst)
            if meta:
                self._state["files"] = [f for f in (meta.get("files") or []) if _safe_rel(f)]
                self._state["installed_version"] = meta.get("version") or self._state.get(
                    "installed_version")
            self._save_state()
            return True
        except Exception:
            return False

    def rollback(self, actor: str = "system", role: str = "system",
                 reason: str = "手工回滚") -> Dict[str, Any]:
        with self._lock:
            archive = str(self._state.get("lkg_archive") or "")
            if not archive or not os.path.isfile(archive):
                return {"ok": False, "error": "没有可用的 last-known-good 备份"}
            ok = self._restore(archive)
            if not ok:
                return {"ok": False, "error": "备份解包失败（归档可能已损坏）"}
            self._state["open_until"] = 0.0
            self._state["fail_count"] = 0
            self._push_attempt({"version": self._state.get("installed_version") or "",
                                "ts": time.time(),
                                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "result": "rollback", "reason": reason, "files": 0})
            self._save_state()
            self._audit("update.rollback", actor=actor, role=role,
                        target=self._state.get("installed_version") or "", result="ok",
                        detail={"理由": reason, "归档": os.path.basename(archive)})
            probe = self._probe()
            return {"ok": True, "version": self._state.get("installed_version") or "",
                    "from": os.path.basename(archive), "probe": probe,
                    "breaker": self.breaker()}

    def reset_breaker(self, actor: str = "system", role: str = "system") -> Dict[str, Any]:
        with self._lock:
            self._state["fail_count"] = 0
            self._state["open_until"] = 0.0
            self._save_state()
        self._audit("update.reset", actor=actor, role=role, target="熔断", result="ok")
        return {"ok": True, "breaker": self.breaker()}

    # ---------- 失败与熔断 ----------
    def _fail(self, target: str, actor: str, role: str, reason: str,
              version: Any = None, detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        fc = int(self._state.get("fail_count") or 0) + 1
        self._state["fail_count"] = fc
        opened = False
        if fc >= self.failure_threshold:
            self._state["open_until"] = time.time() + self.cooldown
            self._state["fail_count"] = 0
            opened = True
        self._push_attempt({"version": str(version or ""), "ts": time.time(),
                            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "result": "fail", "reason": reason, "files": 0})
        self._save_state()
        payload = {"理由": reason, "连续失败": fc, "熔断打开": opened}
        payload.update(detail or {})
        self._audit("update.apply", actor=actor, role=role, target=str(target),
                    result="fail", detail=payload)
        return {"ok": False, "error": reason, "breaker": self.breaker(),
                "tripped": opened}

    def _push_attempt(self, rec: Dict[str, Any]) -> None:
        attempts = list(self._state.get("attempts") or [])
        attempts.append(rec)
        self._state["attempts"] = attempts[-40:]

    # ---------- 健康探针 ----------
    def _probe(self) -> Dict[str, Any]:
        checks: List[Dict[str, Any]] = []
        ok = True
        # 1) 规则包能否解析、规则数是否够
        try:
            rules, index = rules_ext.load_packs(self.cfg)
            bad = [p for p in index if p.get("error")]
            enough = len(rules) >= self.min_rules
            checks.append({"name": "规则包解析", "ok": not bad and enough,
                           "detail": f"{len(rules)} 条规则 / {len(index)} 个包"
                                     + ("；坏包: " + ", ".join(p['file'] for p in bad) if bad else "")
                                     + ("" if enough else f"；不足 {self.min_rules} 条")})
            ok = ok and not bad and enough
        except Exception as exc:
            checks.append({"name": "规则包解析", "ok": False, "detail": f"异常: {exc}"})
            ok = False
        # 2) 剧本能否解析（坏剧本会让 SOAR 静默不干活）
        try:
            from . import playbook as pb_mod
            pdir = os.path.join(self.data_dir, "playbooks")
            count, broken = 0, []
            for name in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
                if not name.endswith((".yaml", ".yml")):
                    continue
                count += 1
                try:
                    with open(os.path.join(pdir, name), "r", encoding="utf-8",
                              errors="replace") as fh:
                        data = pb_mod._parse(fh.read()) or {}
                    items = data if isinstance(data, list) else [data]
                    if not isinstance(data, (dict, list)) or not items:
                        raise ValueError("顶层既不是映射也不是列表")
                    for item in items:
                        if not isinstance(item, dict):
                            raise ValueError("剧本条目不是映射")
                        if not any(k in item for k in ("actions", "steps", "when", "triggers")):
                            raise ValueError("条目缺少 when/actions")
                except Exception as exc:
                    broken.append(f"{name}({exc})")
            checks.append({"name": "剧本解析", "ok": not broken,
                           "detail": f"{count} 个剧本" + (f"；坏剧本: {broken}" if broken else "")})
            ok = ok and not broken
        except Exception as exc:
            checks.append({"name": "剧本解析", "ok": False, "detail": f"异常: {exc}"})
            ok = False
        # 3) 业务探针（由 Core 注册：检测流水线是否还能出告警）
        for fn in self._probes:
            try:
                res = fn() or {}
                passed = bool(res.get("ok"))
                checks.append({"name": str(res.get("name") or "业务探针"), "ok": passed,
                               "detail": str(res.get("detail") or "")})
                ok = ok and passed
            except Exception as exc:
                checks.append({"name": "业务探针", "ok": False, "detail": f"异常: {exc}"})
                ok = False
        reason = "" if ok else "；".join(c["name"] for c in checks if not c["ok"])
        return {"ok": ok, "checks": checks, "reason": reason,
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    # ---------- 导出当前基线（用于本地演练整条通道） ----------
    def export_baseline(self, dest: str, version: Optional[str] = None,
                        notes: str = "当前规则与剧本基线") -> Dict[str, Any]:
        dest = os.path.abspath(dest or os.path.join(self.root, "bundle"))
        os.makedirs(dest, exist_ok=True)
        version = version or (__version__ + "-baseline." + time.strftime("%Y%m%d%H%M%S"))
        files: List[Dict[str, Any]] = []
        for root in MANAGED_ROOTS:
            base = os.path.join(self.data_dir, root)
            if not os.path.isdir(base):
                continue
            for name in sorted(os.listdir(base)):
                if not name.endswith((".yaml", ".yml")):
                    continue
                rel = f"{root}/{name}"
                if not _safe_rel(rel):
                    continue
                src = os.path.join(base, name)
                dst = os.path.join(dest, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(src, dst)
                files.append({"path": rel, "sha256": _sha256_file(dst),
                              "size": os.path.getsize(dst)})
        manifest: Dict[str, Any] = {
            "schema": SCHEMA, "channel": self.channel, "version": version,
            "released": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "min_version": "", "files": files, "notes": notes,
        }
        manifest["sig"] = self.sign(manifest)
        with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
        self._audit("update.export", actor="system", role="system", target=dest,
                    result="ok", detail={"version": version, "files": len(files)})
        return {"ok": True, "dir": dest, "version": version, "files": files,
                "manifest": os.path.join(dest, "manifest.json"),
                "sig_fingerprint": self.key_fingerprint()}
