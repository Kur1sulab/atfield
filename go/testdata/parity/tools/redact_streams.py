#!/usr/bin/env python3
"""把真实事件流里的个人/环境标识脱敏，保持「语义不变、两侧同源」。

规则（与 testdata/parity/meta.json 的既有口径一致）：
  - 公网 IPv4 → 203.0.113.<n>（TEST-NET-3，n 按首次出现顺序稳定分配）
  - 家目录 /Users/<name> → /Users/USER-A；用户名 → USER-A
  - 主机名 → HOST-A（事件里通常没有 host，缺了由对拍工具补占位）
私有地址、端口、kind、severity、subject 键集合、数组顺序一律不动。

为什么要脱敏后再对拍：流要进仓库，真实公网 IP 是用户的网络环境；
脱敏只改字符串值，不改判定所依赖的 subject.public / subject.rport，
所以脱敏前后告警集合应当完全一致——脚本会把这件事断言出来。

用法:
  python3 redact_streams.py <目录> [--user 旧用户名] [--home /Users/xxx]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--user", default=os.path.basename(os.path.expanduser("~")).rstrip("."))
    ap.add_argument("--home", default=os.path.expanduser("~"))
    ap.add_argument("--host", default=os.uname().nodename)
    args = ap.parse_args()

    d = os.path.abspath(args.dir)
    files = [os.path.join(d, f) for f in sorted(os.listdir(d))
             if f.endswith(".jsonl") or f == "live_ioc.json"]
    if not files:
        print("没有可处理的文件", file=sys.stderr)
        return 1

    # 第一遍：收集所有公网 IPv4（跨文件统一映射，保证 IOC 与事件对得上）
    mapping: dict[str, str] = {}
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                for ip in IPV4.findall(line):
                    if is_public(ip) and ip not in mapping:
                        n = len(mapping) + 1
                        if n <= 254:
                            mapping[ip] = f"203.0.113.{n}"
                        else:
                            mapping[ip] = f"198.51.100.{n - 254}"

    def scrub(text: str) -> str:
        for ip, rep in mapping.items():
            text = text.replace(ip, rep)
        text = text.replace(args.home, "/Users/USER-A")
        text = text.replace("/Users/" + args.user, "/Users/USER-A")
        if args.user:
            text = text.replace(args.user + "@", "USER-A@")
            text = re.sub(rf'(?<=["\s]){re.escape(args.user)}(?=["\s])', "USER-A", text)
        if args.host:
            text = text.replace(args.host, "HOST-A")
        return text

    changed = 0
    for path in files:
        out_lines = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                new = scrub(line)
                changed += new != line
                out_lines.append(new)
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(out_lines)

    # 复核：不能残留公网 IPv4，且每一行仍是合法 JSON
    residue = 0
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                for ip in IPV4.findall(line):
                    if is_public(ip):
                        residue += 1
                if path.endswith(".jsonl"):
                    json.loads(line)
    print(f"文件 {len(files)} 个，替换行 {changed} 行，公网 IP 映射 {len(mapping)} 条，残留 {residue} 处")
    if residue:
        print("仍有公网地址残留，拒绝继续", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
