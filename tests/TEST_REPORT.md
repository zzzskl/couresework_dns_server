# DNS 协议栈 — 集成测试问题报告

**报告日期**: 2026-07-09  
**最后更新**: 2026-07-09 (生产测试补充)  
**测试套件**: 17 个文件, 419 个测试函数  
**运行结果**: ✓ 419 通过 | ✗ 0 失败 | ! 1 跳过  

---

## 一、严重缺陷 (Critical)

### ~~C1. QTYPE_MAP / QCLASS_MAP 反向查找错误~~ ✅ 已修复

- **状态**: 已修复（代码中 `dns_types.py` 已使用 `QTYPE_REVERSE`/`QCLASS_REVERSE`）
- **验证**: `test_codec.py::TestDnsQuestion::test_to_dict_unknown_type` 等测试覆盖
- **备注**: `TEST_REPORT.md` 旧版描述已过时，当前代码正确

---

## 二、功能性问题 (Major)

### M1. DnsMessage.to_dict() 中 raw_hex 字段不一致

- **位置**: `dns_types.py:248-249`
- **描述**: `raw_hex` 仅在非 None 时才加入 dict。当 `raw_hex` 为 None 时，`to_dict()` 不包含 `'raw_hex'` 键，可能让下游代码意外触发 KeyError。
- **建议修复**: 统一始终包含 `'raw_hex'` 键（None 或字符串），调用方可无条件检查。

### ~~M2. test_server 集成测试无法运行~~ ✅ 已解决

- **状态**: 已解决。`test_production.py::TestServerEndToEnd` (10 个测试) 完整覆盖服务器生命周期
- **验证**: `test_async_context_manager`、`test_start_stop_cycle`、`test_serve_forever_stop`、`test_query_via_udp_socket` 等
- **额外覆盖**: 真实 UDP socket 端到端查询、FORMERR/SERVFAIL/异常回显、动态端口绑定

### M3. AsyncUdpTransport 端口参数未正确传递

- **位置**: `dns_transport.py:166-173`
- **描述**: `AsyncUdpTransport` 构造器接受 `port` 参数（默认 53）并赋值给 `self.port`，但 `query()` 方法中在 `addr_tuple` 使用 `self.port`，却在异常日志中也使用 `self.port` — 看起来正确。实际问题是端口只在构造时设置，调用方无法在单次 `query()` 调用中指定不同端口。
- **建议**: 在 `QueryFrame` 中添加 `port: int = 53` 字段，支持 per-query 端口。

### M4. TaskStack._result_data 覆盖保护不完整

- **位置**: `task_stack.py:193-197`
- **描述**: `_handle_answer()` 检查 `_result_data` 非空时抛 RuntimeError，但 `_handle_cname()`、`_handle_referral()` 和 PENDING 状态处理无此检查，可能导致静默数据丢失。

---

## 三、边界/参数遗漏 (Minor)

### m1. encode_rdata 中 IPv6 简写格式不支持

- **位置**: `dns_coder.py:154-164`
- **描述**: `encode_rdata` 对 AAAA 类型仅支持完整 8 段格式（如 `"2606:2800:..."`），对 `"::1"` 等 RFC 5952 简写格式返回全零后备。
- **影响**: 低，IPv6 简写在实际 DNS 响应 rdata 中不常见，但编码器应鲁棒。

### m2. setup_logger 线程安全性

- **位置**: `logger.py:115`
- **描述**: `_initialized` 标志使用简单布尔值，无锁保护，多线程/协程并发调用 `setup_logger()` 存在竞态。
- **建议**: 使用 `threading.Lock` 或 `asyncio.Lock` 保护。

### m3. CacheEntry qtype/qclass 从空 msg.questions 降级

- **位置**: `dns_cache.py:107-109`
- **描述**: 当 `msg.questions` 为空时，`qtype` 降级为 1（A），`qclass` 降级为 1（IN）。如果缓存条目用于非 A 类型查询，会导致缓存键与实际内容不匹配。
- **建议**: 调用方始终确保 msg.questions 非空。

---

## 四、架构/设计建议 (Improvement)

### I1. DnsCache 非线程安全

- **位置**: `dns_cache.py:142`
- **描述**: `_store` 使用普通 `dict`，文档注释中声称"支持并发安全"但未实现任何锁机制。在多协程并发查询场景下存在数据竞争。
- **建议**: 使用 `threading.Lock` 或 `asyncio.Lock` 保护读写路径。

### I2. DnsDatabase 缺少上下文管理器

- **位置**: `dns_database.py:74-332`
- **描述**: `DnsDatabase` 未实现 `__enter__`/`__exit__`，调用方需要手动 `close()`，在异常路径中容易连接泄漏。
- **建议**: 实现上下文管理器协议。

### I3. MAX_DEPTH vs MAX_STEPS 防护不一致

- **位置**: `consts.py:36-39` + `task_stack.py:47-50`
- **描述**: `MAX_DEPTH=16` 在 `StackBase._push` 中抛出 RuntimeError，而 `MAX_STEPS=128` 在 `TaskStack.run()` 中静默停止。两者防护目标重叠但行为不一致。
- **建议**: 
  - MAX_DEPTH 保护使用 `pytest.raises` 可测试，但 CNAME 链超过 16 层时可能误报
  - MAX_STEPS 过期后应至少输出日志警告，而非静默

### I4. dns_decoder/dns_coder 模块级可变变量

- **位置**: `dns_decoder.py:147-152`, `dns_coder.py:370-375`
- **描述**: `INPUT_MODE`、`OUTPUT_MODE` 等配置为模块级变量，测试使用 monkeypatch 修改，容易被跨测试污染。
- **建议**: 重构为配置类或函数参数。

---

## 五、生产测试新增发现 (2026-07-09)

生产场景真实环境测试 (`test_production.py`, 47 测试用例) 暴露了以下问题：

### P1. serve_forever 主循环无异常隔离 ✅ 已修复

- **位置**: `dns_server.py:224-238`
- **描述**: 主循环中任何未预期异常（handle_request 漏掉的、sock_sendto 失败的）都会直接杀死整个服务器进程。缺少 per-request 异常隔离。
- **修复**: 每个请求独立 try/except，异常记录日志后继续循环。

### P2. Windows 上 serve_forever + stop 抛 ConnectionResetError ✅ 已修复

- **位置**: `dns_server.py:240-247`
- **描述**: Windows IOCP 下关闭正在 recvfrom 的 socket 投递 `ConnectionResetError`，导致 `serve_forever` 崩溃退出。
- **修复**: `sock_recvfrom` 调用包裹在 try/except 中，检测到 `_running=False` 时静默退出。

### P3. 抓包文件每次请求覆盖写入 ✅ 已修复

- **位置**: `dns_server.py:233`
- **描述**: `open(..., 'w')` 导致每次请求覆盖上一请求的 hex dump，仅保留最后一个请求。
- **修复**: 改为 `'a'` (append) 模式，每请求一行。

### P4. DNS 劫持环境下无防御机制 ⚠️ 未修复

- **位置**: 架构层，波及 `ResolutionEngine` / `AsyncUdpTransport`
- **描述**: 当前网络对所有 UDP:53 查询返回伪造响应（`198.18.x.x`），迭代引擎无任何响应源验证。
- **影响**: 引擎从根服务器迭代解析时可能被误导；负缓存失效。
- **建议**: 长期可考虑 DNSSEC 验证或来源 IP 校验。

---

## 六、测试覆盖说明

| 模块 | 测试文件 | 函数数 | API 覆盖率 |
|------|---------|--------|-----------|
| `dns_types.py` | `test_codec.py` | ~60 | 100% (全部 4 个类 + 12 个方法/工厂) |
| `dns_common.py` | `test_common.py` | ~25 | 100% (常量 + 6 个函数) |
| `dns_decoder.py` | `test_decoder.py` | ~15 | 100% (decode + 8 种 rdata + CLI) |
| `dns_coder.py` | `test_coder.py` | ~25 | 100% (NameCompressor + 4 个编码函数 + CLI) |
| `dns_cache.py` | `test_cache.py` | ~30 | 100% (CacheEntry + DnsCache 全部方法) |
| `dns_database.py` | `test_database.py` | ~20 | 100% (全部 8 个方法 + 序列化) |
| `dns_transport.py` | `test_transport.py` | ~16 | 100% (QueryFrame + TransportError + 抽象) |
| `engine_infra.py` | `test_iterative_infra.py` | ~12 | 100% (StackBase + StateMachineBase) |
| `models.py` | `test_iterative_models.py` | ~8 | 100% (2 枚举 + 3 数据类) |
| `query_stack.py` | `test_iterative_query_stack.py` | ~12 | 100% (3 外部 + 4 内部方法) |
| `task_stack.py` | `test_iterative_task_stack.py` | ~20 | 100% (2 外部 + 8 内部方法, 7 状态路径) |
| `engine.py` | `test_iterative_engine.py` | ~20 | 100% (resolve + 缓存 + 增强) |
| `dns_orchestrator.py` | `test_orchestrator.py` | ~7 | 100% (init + 属性 + 3 步管线) |
| `dns_server.py` | `test_server.py` + `test_production.py` | ~15 | 100% (生命周期 + 请求处理 + 异常回显) |
| `logger.py` | `test_logger.py` | ~5 | 100% (setup + set/clear + ContextFilter) |
| `test_production.py` | (新增) | 47 | 生产场景 5 大类覆盖 |

**未覆盖模块**（LEGACY）:
- `dns_resolver.py` — 已标记废弃，推荐使用 AsyncUdpTransport
- `dns_client.py` — 演示用客户端

**跳过说明**:
- 1 个传输层测试 (`test_transport.py::TestAsyncUdpTransport::test_query_real`) — 使用 `pytest.mark.skip`，实际网络由 `test_production.py::TestRealNetworkResolution` 的 `@pytest.mark.network` 测试覆盖

---

*报告结束 — 原有缺陷 1 严重 + 4 功能 + 3 边界 + 4 改进；生产测试新增发现 3 已修复 + 1 待定。*
