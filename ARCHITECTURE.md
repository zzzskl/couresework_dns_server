# DNS 协议栈 — 架构与模块使用指南

## 概览

本项目实现了一个完整的 DNS 协议栈，支持报文编解码、迭代解析、多级缓存和 UDP 服务器。

### 分层架构

```
  Layer 4  服务器/客户端入口   dns_server.py, dns_client.py
  Layer 3  解析编排            dns_orchestrator.py
  Layer 2  缓存 & 引擎         dns_cache.py, dns_database.py, dns_iterative/
  Layer 1  传输 & 编解码       dns_transport.py, dns_coder.py, dns_decoder.py
  Layer 0  类型 & 基础         dns_types.py, dns_common.py, logger.py
```

### 依赖关系图

```
  dns_client.py / dig / nslookup (客户端)
          │ UDP :5354
          ▼
  ┌─────────────────┐
  │   dns_server    │  ← asyncio UDP 接收 / 发送
  └───────┬─────────┘
          │ decode(raw) → DnsMessage
          ▼
  ┌─────────────────┐
  │ dns_orchestrator│  ← 三步解析编排: ①Cache → ②Database → ③Engine
  └───────┬─────────┘
          │
     ┌────┼──────────────┐
     ▼    ▼              ▼
  ┌────┐ ┌──────────┐ ┌─────────────────┐
  │Cache│ │Database  │ │ResolutionEngine │
  │内存 │ │SQLite    │ │  dns_iterative/ │
  └────┘ └──────────┘ │ 双栈状态机迭代   │
                       │ transport.query()│
                       └────────┬────────┘
                                │ AsyncUdpTransport
                                ▼
                       ┌─────────────────┐
                       │ 上游 DNS 服务器  │
                       │ (根→.com→权威)  │
                       └─────────────────┘
```

---

## 模块说明

### 1. `dns_types.py` — DNS 类型系统

基于 `dataclass` 的 DNS 报文结构化表示，包含完整的 <-> dict 桥接方法。

**核心类型：**

| 类型 | 说明 | 关键字段 |
|------|------|----------|
| `DnsHeader` | DNS 报文头部 (12 字节) | `id`, `qr`, `opcode`, `aa`, `tc`, `rd`, `ra`, `rcode` |
| `DnsQuestion` | Question 区段 | `qname`, `qtype`, `qclass` |
| `DnsResourceRecord` | 通用 Resource Record | `name`, `type`, `class_`, `ttl`, `rdata` |
| `DnsMessage` | 完整 DNS 报文 | `header`, `questions`, `answers`, `authorities`, `additionals` |

**典型用法：**

```python
from dns_types import DnsMessage, DnsResourceRecord, DnsHeader, DnsQuestion

# 构造查询
query = DnsMessage.create_query("www.example.com", "A")
# query.header.id 自动生成，query.questions[0].qtype == 1

# 构造响应
resp = DnsMessage.create_response(
    query,
    answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")]
)

# 序列化为 bytes
wire = query.to_bytes()

# 从 bytes 恢复
msg = DnsMessage.from_bytes(wire)

# 与 dict 桥接（兼容旧 coder/decoder）
d = msg.to_dict()
msg2 = DnsMessage.from_dict(d)
```

**`DnsResourceRecord` 工厂方法：**

| 工厂方法 | 用途 | 示例 rdata |
|----------|------|------------|
| `create_a(name, ip, ttl)` | A 记录 | `"1.1.1.1"` |
| `create_aaaa(name, ip, ttl)` | AAAA 记录 | `"::1"` |
| `create_cname(name, target, ttl)` | CNAME | `"target.example.com"` |
| `create_ns(name, target, ttl)` | NS 记录 | `"ns1.example.com"` |
| `create_mx(name, pref, target, ttl)` | MX 记录 | `(10, "mail.example.com")` |

---

### 2. `dns_common.py` — 公共基础模块

所有模块共享的常量与工具函数。

**常量映射：**

| 符号 | 说明 |
|------|------|
| `QTYPE_MAP` / `QTYPE_REVERSE` | 查询类型字符串 ↔ 数值（A=1, NS=2, ...） |
| `QCLASS_MAP` / `QCLASS_REVERSE` | 类别字符串 ↔ 数值（IN=1, ...） |
| `RCODE_MAP` | 响应码 → 字符串（0=NoError, 3=NXDomain） |

**工具函数：**

| 函数 | 说明 |
|------|------|
| `encode_domain(domain)` | `"www.baidu.com"` → 标签格式 `b'\x03www\x05baidu\x03com\x00'` |
| `decode_domain(data, offset)` | 解析域名（含压缩指针），返回 `(domain_str, new_offset)` |
| `build_query(domain, qtype)` | （旧版）构造查询报文 bytes |
| `extract_ns_glue_pairs(authorities, additionals)` | 从 NS/glue RR 列表提取 `{ns_name: glue_ip}` 映射 |
| `extract_ns_delegations(msg)` | 从 `DnsMessage` 提取完整 NS 委派信息 |
| `min_ttl_from_message(msg)` | 取报文中所有 RR 的最小 TTL |

---

### 3. `dns_decoder.py` — 报文解码器

将二进制 DNS 报文解析为结构化数据。

**核心 API：**

```python
from dns_decoder import decode

# 基础用法
msg: DnsMessage = decode(raw_bytes)

# 附带原始 hex 文本（用于调试/抓包）
msg = decode(raw_bytes, include_raw_hex=True)
print(msg.hex_dump)
```

**返回结构：** 解析后的 `DnsMessage` 对象，包含 `header`, `questions`, `answers`, `authorities`, `additionals`。

---

### 4. `dns_coder.py` — 报文编码器

将结构化数据重新编码为二进制 DNS 报文。支持域名压缩（`NameCompressor`）。

**核心 API：**

```python
from dns_coder import encode_message, NameCompressor

# 从 DnsMessage 编码（推荐）
wire = encode_message(dns_message, use_compression=True)

# 从 dict 编码（兼容旧接口）
wire = encode_message(parsed_dict, use_compression=True)

# 自定义压缩器
compressor = NameCompressor(base_offset=12)
wire = encode_message(msg, use_compression=True, compressor=compressor)
```

**`NameCompressor` 方法：**

| 方法 | 说明 |
|------|------|
| `register_name(name, offset)` | 注册域名及其所有后缀到压缩表 |
| `compress(name, current_offset)` | 尝试返回 2 字节压缩指针，否则返回 `None` |
| `to_bytes(name, current_offset)` | 返回压缩指针或完整标签序列 bytes |

---

### 5. `dns_transport.py` — 传输层

抽象基类 + 默认 `AsyncUdpTransport` 实现。

**核心类型：**

```python
from dns_transport import AsyncUdpTransport, QueryFrame

@dataclass
class QueryFrame:
    ip: str          # 目标 IP
    domain: str      # 查询域名
    qtype: int       # 查询类型（1=A, 28=AAAA）
    qclass: int = 1  # 类别（默认 IN）
    port: int = 53   # 目标端口
```

**核心 API：**

```python
transport = AsyncUdpTransport(timeout=5.0)
result: DnsMessage = await transport.query(
    QueryFrame("8.8.8.8", "www.baidu.com", 1)
)
# 成功 → result.header.rcode == 0, result.answers 包含解析结果
# 失败 → result.header.rcode != 0
```

**设计原则：**
- `Transport` 是纯抽象基类（`abc.ABC`），方便 mock 测试
- 单次 `query()` = 一次 UDP 请求 + 一次响应
- 重试、超时、多目标由上层（`ResolutionEngine`）负责

---

### 6. `dns_cache.py` — 内存缓存

三层缓存能力合一：答案缓存（正向）、负缓存（NXDOMAIN/SERVFAIL）、委派缓存（NS + glue IP）。

**核心类型：**

```python
from dns_cache import DnsCache, CacheEntry

cache = DnsCache()
```

**答案缓存：**

```python
# 写入
cache.set_answer("www.example.com", 1, 1, response_msg)

# 读取
msg = cache.get_answer("www.example.com", 1)  # → DnsMessage | None
entry = cache.get("www.example.com", 1, 1)     # → CacheEntry | None
```

**委派缓存：**

```python
# 写入
cache.set_delegation("example.com", ns_records, glue_records)

# 读取
ns_list, glue_list = cache.get_delegation("example.com")
# ns_list: List[DnsResourceRecord], glue_list: List[DnsResourceRecord]
```

**负缓存（自动）：**

```python
# NXDOMAIN 或 SERVFAIL 时自动标记为负缓存
cache.set_answer("nx.example.com", 1, 1, nxdomain_response)
entry = cache.get("nx.example.com", 1, 1)
print(entry.is_negative)  # True
```

**特性：** TTL 过期自动失效、线程安全（`threading.Lock`）、`CacheEntry.expired()` 惰性检查。

---

### 7. `dns_database.py` — SQLite 持久化

接口与 `DnsCache` 完全对称的持久化存储。

**核心 API：**

```python
from dns_database import DnsDatabase

# 文件存储
db = DnsDatabase("data/dns_cache.db")
# 内存模式（测试用）
db = DnsDatabase(":memory:")

# 完全对称的接口
msg = db.get_answer("www.example.com", 1)
db.set_answer("www.example.com", 1, 1, response_msg)
ns_list, glue_list = db.get_delegation("example.com")
db.set_delegation("example.com", ns_records, glue_records)
db.delete("www.example.com")

db.close()
```

**存储方式：** Record 列表使用 JSON 序列化（复用 `DnsResourceRecord.to_dict / from_dict`）。打开数据库后第一次查询自动建表。

---

### 8. `dns_iterative/` — 迭代解析引擎

双栈状态机实现，从根服务器开始逐级迭代解析。

**包结构：**

| 文件 | 说明 |
|------|------|
| `consts.py` | 13 组 IANA 根服务器 IP、查询/安全限制常量 |
| `models.py` | `Task`, `TaskResult`, `QueryResult`, `TaskStatus`, `QueryStatus` |
| `engine_infra.py` | Layer 1 纯栈原语 — `StackBase`, `StateMachineBase` |
| `query_stack.py` | 查询栈状态机 — 单槽栈，NS+胶水自旋 |
| `task_stack.py` | 任务栈状态机 — `NEW→PENDING→CNAME/PAUSED→FINISHED` |
| `engine.py` | `ResolutionEngine` — 入口，创建栈、注入缓存、编排流程 |

**核心 API：**

```python
from dns_transport import AsyncUdpTransport
from dns_iterative.engine import ResolutionEngine
from dns_cache import DnsCache

transport = AsyncUdpTransport()
engine = ResolutionEngine(transport, cache=DnsCache())
result: TaskResult = await engine.resolve("www.baidu.com", qtype=1)
# result.success → bool
# result.result_msg → DnsMessage (含最终 answers)
```

**解析流程：**

```
Engine.resolve("www.baidu.com")
  ├─ ① 检查答案缓存，命中直接返回
  ├─ ② 检查委派缓存，尝试从缓存的 NS 开始
  └─ ③ 创建 TaskStack + QueryStack
        └─ task_stack.run()
              ├─ [NEW]      压入 "www.baidu.com"
              ├─ [PENDING]  委派 query_stack.run()
              │               ├─ query → 根服务器 → .com NS 委派
              │               ├─ query → .com 权威 → baidu.com NS 委派
              │               └─ query → baidu.com 权威 → 答案
              ├─ [CNAME]    若遇到 CNAME，重新 queue
              └─ [FINISHED] 返回 TaskResult
```

---

### 9. `dns_orchestrator.py` — 解析编排器

三步解析管线：**①内存缓存 → ②SQLite 数据库 → ③迭代引擎**。

```python
from dns_orchestrator import DnsOrchestrator
from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_iterative.engine import ResolutionEngine
from dns_transport import AsyncUdpTransport

cache = DnsCache()
database = DnsDatabase(":memory:")  # 或 "data/dns_cache.db"
transport = AsyncUdpTransport()
engine = ResolutionEngine(transport, cache=cache)  # 共享 cache

orchestrator = DnsOrchestrator(cache, database, engine)

result: DnsMessage = await orchestrator.resolve("www.example.com", 1)
# 第①步：cache.get_answer() — 毫秒级
# 第②步：db.get_answer() → 命中则回填 cache
# 第③步：engine.resolve() → 成功后回填 db + cache
```

**设计要点：**
- 纯编排，不含协议编解码逻辑
- 每步显式调用、可观测、可独立 mock
- engine 与 orchestrator 共享同一 `cache` 实例，确保一致性

---

### 10. `dns_server.py` — UDP DNS 服务器

基于 asyncio 的 DNS 服务器主入口。

```python
# 直接运行
python dns_server.py
```

默认配置：`0.0.0.0:5354`，抓包输出到 `server/captured.hex`。

**处理流程：**

```
接收 UDP 数据报
  → decode(raw) 解析为 DnsMessage
  → orchestrator.resolve() 三步解析
  → 修正 TxID 为客户端原始值
  → to_bytes() 编码回二进制
  → UDP 发送
```

**可配置常量（文件顶部）：**

```python
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5354
OUTPUT_FILE = "server/captured.hex"
```

---

### 11. `dns_client.py` — 同步 UDP DNS 客户端（演示用）

用于演示的同步 DNS 客户端，默认连接 `127.0.0.1:5354`。

```bash
# 直接运行（查询默认域名 www.baidu.com）
python dns_client.py
```

**可配置常量（文件顶部）：**

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `TARGET_SERVER` | `127.0.0.1` | 目标 DNS 服务器 |
| `TARGET_PORT` | `5354` | 端口 |
| `QUERY_DOMAIN` | `www.baidu.com` | 查询域名 |
| `QUERY_TYPE` | `A` | 记录类型 |
| `TIMEOUT` | `10` | 超时秒数 |
| `PRINT_RAW_HEX` | `True` | 是否打印 hex 全文 |

> 此模块标记为 LEGACY，新代码推荐使用 `dns_transport.AsyncUdpTransport`。
> 演示场景下 `dns_client.py` 是最便捷的跨平台工具，无需安装额外依赖。

---

### 12. `logger.py` — 统一日志

提供请求上下文追踪，所有模块的日志行自动携带 `[req=xxx] [domain] [qtype]`。

```python
from logger import setup_logger, set_request_context, clear_request_context

# 进程入口调用一次（幂等）
setup_logger(level=logging.INFO)

# 每个请求开始时注入追踪 ID
set_request_context(req_id="a1b2c3d4", domain="www.baidu.com", qtype=1)

# ... 执行解析 ...

# 请求结束时清除
clear_request_context()
```

**各模块中使用（无需改动）：**

```python
import logging
log = logging.getLogger(__name__)
log.info("Query starting")  # 自动输出: [req=a1b2c3d4] [www.baidu.com] [qtype=1] Query starting
```

---

### 13. 测试模块 (`tests/`)

| 文件 | 说明 |
|------|------|
| `test_all.py` | 24 个统一测试：编解码往返、类型工厂、缓存读写、QueryStack/TaskStack 状态机 |
| `test_database.py` | SQLite 持久化层测试 |
| `test_orchestrator.py` | 编排器三步解析测试 |
| `test_server.py` | 服务器集成测试 |
| `conftest.py` | pytest fixtures（mock transport, sample data） |
| `fixtures/` | 测试用抓包数据 |

```bash
# 运行全套测试
pytest tests/ -v
```

---

## 快速启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动服务器
python dns_server.py

# 3. 新终端（演示一）：用项目自带客户端查询
python dns_client.py

# 4. 新终端（演示二）：或用 dig 查询
# dig @127.0.0.1 -p 5354 www.baidu.com

# 5. 运行测试
pytest tests/ -v
```
