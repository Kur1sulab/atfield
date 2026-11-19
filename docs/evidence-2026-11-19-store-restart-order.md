# 证据：Store 重启后攻击链顺序反转修复（2026-11-19）

缺口：`atfield/store.py` `_load_history` 用 `reversed()` 读回 incidents.jsonl，
重启后顺序与在线语义（`add_incident` remove+appendleft，最近更新在前，store.py:89-102）相反。
影响：core.py:325-326 威胁指数取 snapshot_incidents(50)、core.py:386 总览
recent_incidents[:6]（web/app.js:240「攻击链叙事」面板）、/api/incidents?limit=50
（app.js:306）重启后全部拿到「最不活跃」子集；唯一 iid 超 max_incidents 时最新链被整条淘汰。

修复：store.py:300 `for d in reversed(list(by_iid.values())):` → store.py:304 `for d in by_iid.values():`
（by_iid 键序=各链最后出现旧→新，逐条 appendleft 后最新在前，与在线一致）。

## 0. 修复前基线的真实状态（回归门禁本身是坏的）

命令：`cd /Users/xu./aegis && python3 -m unittest discover -s tests -v`
真实退出码 = 1（任务交接所说的「29 通过 / 0 失败 / 1 跳过」只是 test_firewall
脚本自己的计数行；discover 本身 FAILED，且 governance/monthly 两套从未被执行）：

```text
  [32m✓[0m 带结束标记
  [32m✓[0m 每条目标两个方向各一条test_ai_api (unittest.loader._FailedTest.test_ai_api) ... ERROR
test_ai_layer (unittest.loader._FailedTest.test_ai_layer) ... ERROR
test_firewall (unittest.loader._FailedTest.test_firewall) ... ERROR

======================================================================
ERROR: test_ai_api (unittest.loader._FailedTest.test_ai_api)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_ai_api
Traceback (most recent call last):
  File "/Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/unittest/loader.py", line 396, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/unittest/loader.py", line 339, in _get_module_from_name
    __import__(name)
  File "/Users/xu./aegis/tests/test_ai_api.py", line 422, in <module>
    sys.exit(0 if FAIL == 0 else 1)
SystemExit: 0


======================================================================
ERROR: test_ai_layer (unittest.loader._FailedTest.test_ai_layer)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_ai_layer
Traceback (most recent call last):
  File "/Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/unittest/loader.py", line 396, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/unittest/loader.py", line 339, in _get_module_from_name
    __import__(name)
  File "/Users/xu./aegis/tests/test_ai_layer.py", line 237, in <module>
    sys.exit(0 if FAIL == 0 else 1)
SystemExit: 0


======================================================================
ERROR: test_firewall (unittest.loader._FailedTest.test_firewall)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_firewall
Traceback (most recent call last):
  File "/Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/unittest/loader.py", line 396, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/unittest/loader.py", line 339, in _get_module_from_name
    __import__(name)
  File "/Users/xu./aegis/tests/test_firewall.py", line 237, in <module>
    sys.exit(0 if FAIL == 0 else 1)
SystemExit: 0


----------------------------------------------------------------------
Ran 3 tests in 0.000s

FAILED (errors=3)

```

## 1. 修复前行为复现（Store 级，临时目录，未起服务）

命令：`python3 /Users/xu./.hermes/cache/scratch/repro_incident_order.py`（修复前运行）

```text
在线顺序(新→旧): [('C', '链C-v1'), ('A', '链A-v2'), ('B', '链B-v1')]
重启后顺序     : [('B', '链B-v1'), ('A', '链A-v2'), ('C', '链C-v1')]
顺序一致? False
```

逐步追踪（trace_incident_order.py，修复前）确认在线语义=最近更新在前：

```text
add A(链A-v1) -> ['A']
add B(链B-v1) -> ['B', 'A']
add A(链A-v2) -> ['A', 'B']      ← 更新的链前移
add C(链C-v1) -> ['C', 'A', 'B']

溢出 在线(5条入, maxlen=3): ['I4', 'I3', 'I2']
溢出 重启后: ['I0', 'I1', 'I2']   ← 重启后反而保留最旧的三条
```

## 2. 新增回归测试先红（证明测试能抓住 bug）

命令：`python3 -m unittest tests.test_store_restart -v`（修复前）
结果：Ran 5 tests — FAILED (failures=3)，失败项与缺口一一对应：

```text
FAIL: test_restart_preserves_live_order
AssertionError: Lists differ:
  [('B', '链B-v1', 2.0), ('A', '链A-v2', 9.0), ('C', '链C-v1', 3.0)]
!= [('C', '链C-v1', 3.0), ('A', '链A-v2', 9.0), ('B', '链B-v1', 2.0)]
 : 重启后攻击链顺序/状态与在线不一致

FAIL: test_restart_overflow_keeps_most_recent
- ['I0', 'I1', 'I2']
+ ['I4', 'I3', 'I2']
 : 重启后溢出淘汰方向反了：最新的链被丢出内存

FAIL: test_readded_after_eviction_survives_restart（同类顺序断言失败）
```

## 3. 修复后全绿

命令：`cd /Users/xu./aegis && python3 -m unittest discover -s tests -v`
真实退出码 = 0，Ran 10 tests — OK（5 套件全部真正执行）：

```text
  [32m✓[0m 带结束标记test_all_checks_passed (test_ai_api.load_tests.<locals>._ScriptChecks.test_all_checks_passed) ... ok
test_all_checks_passed (test_ai_layer.load_tests.<locals>._ScriptChecks.test_all_checks_passed) ... ok
test_all_checks_passed (test_firewall.load_tests.<locals>._ScriptChecks.test_all_checks_passed) ... ok
test_all_suites (test_governance.load_tests.<locals>._Governance.test_all_suites) ... /Users/xu./aegis/tests/test_governance.py:76: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-audit-fxz8_gxq/audit/audit.log' mode='r' encoding='utf-8'>
  lines = open(path, encoding="utf-8").read().splitlines()
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:80: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-audit-fxz8_gxq/audit/audit.log' mode='w' encoding='utf-8'>
  open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:89: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-audit-fxz8_gxq/b/audit/audit.log' mode='r' encoding='utf-8'>
  lines = open(al2.path, encoding="utf-8").read().splitlines()
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:90: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-audit-fxz8_gxq/b/audit/audit.log' mode='w' encoding='utf-8'>
  open(al2.path, "w", encoding="utf-8").write("\n".join(lines[:1] + lines[3:]) + "\n")
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:103: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-audit-fxz8_gxq/c/audit/audit.log' mode='r' encoding='utf-8'>
  lines = open(al3.path, encoding="utf-8").read().splitlines()
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:105: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-audit-fxz8_gxq/c/audit/audit.log' mode='w' encoding='utf-8'>
  open(al3.path, "w", encoding="utf-8").write("\n".join(lines[:4]) + "\n")
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:181: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/rules/demo.yaml' mode='w' encoding='utf-8'>
  open(os.path.join(tmp, "rules", "demo.yaml"), "w", encoding="utf-8").write(rule)
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:182: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/playbooks/default.yaml' mode='w' encoding='utf-8'>
  open(os.path.join(tmp, "playbooks", "default.yaml"), "w", encoding="utf-8").write(
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:243: ResourceWarning: unclosed file <_io.BufferedReader name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/rules/demo.yaml'>
  data = open(os.path.join(src_dir, name), "rb").read()
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:246: ResourceWarning: unclosed file <_io.BufferedWriter name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/bundle/rules/demo.yaml'>
  open(out, "wb").write(data)
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:243: ResourceWarning: unclosed file <_io.BufferedReader name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/playbooks/default.yaml'>
  data = open(os.path.join(src_dir, name), "rb").read()
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:246: ResourceWarning: unclosed file <_io.BufferedWriter name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/bundle/playbooks/default.yaml'>
  open(out, "wb").write(data)
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:254: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/bundle/manifest.json' mode='w' encoding='utf-8'>
  json.dump(manifest, open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8"),
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:189: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/bundle/manifest.json' mode='r' encoding='utf-8'>
  manifest = json.load(open(os.path.join(bundle, "manifest.json"), encoding="utf-8"))
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:227: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-update-z9s2z7kv/evilb/manifest.json' mode='w' encoding='utf-8'>
  json.dump(evil, open(os.path.join(tmp, "evilb", "manifest.json"), "w"), ensure_ascii=False)
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./aegis/tests/test_governance.py:351: ResourceWarning: unclosed <socket.socket fd=4, family=2, type=1, proto=0, laddr=('127.0.0.1', 60060)>
  SUITES[n]()
ResourceWarning: Enable tracemalloc to get the object allocation traceback
ok
test_all (test_monthly_smtp.load_tests.<locals>._MonthlySmtp.test_all) ... /Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/socketserver.py:362: ResourceWarning: unclosed <ssl.SSLSocket fd=8, family=2, type=1, proto=0, laddr=('127.0.0.1', 60091), raddr=('127.0.0.1', 60093)>
  self.RequestHandlerClass(request, client_address, self)
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./.local/share/uv/python/cpython-3.12.16-macos-aarch64-none/lib/python3.12/socketserver.py:362: ResourceWarning: unclosed <ssl.SSLSocket fd=8, family=2, type=1, proto=0, laddr=('127.0.0.1', 60094), raddr=('127.0.0.1', 60096)>
  self.RequestHandlerClass(request, client_address, self)
ResourceWarning: Enable tracemalloc to get the object allocation traceback
/Users/xu./.hermes/installs/ed9617536b3eeece/environments/57a0b8cf800843a1811f576872f966a2/venv/lib/python3.14/site-packages/yaml/scanner.py:286: ResourceWarning: unclosed file <_io.TextIOWrapper name='/var/folders/19/4z2zy6q92zz4xy06jzxb6kgr0000gn/T/atfield-http-ky_pn8pd/events.jsonl' mode='a' encoding='utf-8'>
  for level in list(self.possible_simple_keys):
ResourceWarning: Enable tracemalloc to get the object allocation traceback
ok
test_dedupe_keeps_latest_state (test_store_restart.StoreRestartOrder.test_dedupe_keeps_latest_state)
同 iid 多次更新：重启后只留一条，且是最新状态（t15 的 Store 级守卫）。 ... ok
test_findings_restart_newest_first (test_store_restart.StoreRestartOrder.test_findings_restart_newest_first)
相邻路径守卫：findings 重启后仍须最新在前（与在线一致）。 ... ok
test_readded_after_eviction_survives_restart (test_store_restart.StoreRestartOrder.test_readded_after_eviction_survives_restart)
已被淘汰的 iid 再次更新（重新入列）：重启后仍须在最前。 ... ok
test_restart_overflow_keeps_most_recent (test_store_restart.StoreRestartOrder.test_restart_overflow_keeps_most_recent)
超过 max_incidents：重启后保留的必须是最近活跃的链，不是最旧的。 ... ok
test_restart_preserves_live_order (test_store_restart.StoreRestartOrder.test_restart_preserves_live_order)
多 iid + 中途更新：重启后顺序必须与在线完全一致。 ... ok

----------------------------------------------------------------------
Ran 10 tests in 7.585s

OK

  [32m✓[0m 每条目标两个方向各一条
  [32m✓[0m 排除回环 on ! lo0
```

各套件计数（同一日志内）：ai_api 34/0、ai_layer 52/0、firewall 29/0/1跳过、
governance 合计 PASS=55 FAIL=0、monthly 79/0、store_restart 5/5。

## 4. 直接脚本运行方式不受影响（load_tests 钩子只加不改）

```text
$ python3 tests/test_governance.py   # exit 0
65|合计 PASS=55 FAIL=0　耗时 1.4s

$ python3 tests/test_monthly_smtp.py # exit 0（store 修复后重跑）
112|结果：79 通过 / 0 失败 / 0 跳过

$ python3 tests/test_firewall.py     # exit 0（门禁修改后重跑）
==========================================================================
结果：29 通过 / 0 失败 / 1 跳过
==========================================================================

$ python3 tests/test_monthly_smtp.py # exit 0（门禁修改后重跑）
  ok   t15: 重启加载按 iid 去重且保留最新

结果：79 通过 / 0 失败 / 0 跳过
```

## 改动清单

- atfield/store.py:300-305 —— 去掉 reversed()，重启加载与在线顺序语义一致（产品修复）
- tests/test_store_restart.py —— 新增 5 项 unittest 回归（顺序/溢出/淘汰后复活/去重/findings 守卫）
- tests/test_ai_api.py、test_ai_layer.py、test_firewall.py —— 模块级 sys.exit 改为
  __main__ 守卫 + load_tests 钩子（discover 不再记为导入错误）
- tests/test_governance.py、test_monthly_smtp.py —— 增加 load_tests 钩子
  （此前 discover 从不执行这两套共 134 项断言）

未动：README「已知限制」各条边界声明；/etc/pf.conf 与系统配置；未新增任何攻击能力。
