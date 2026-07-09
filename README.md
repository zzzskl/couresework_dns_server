# DNS 协议栈

基于 Python asyncio 的完整 DNS 协议栈实现，支持报文编解码、迭代解析、多级缓存和 UDP 服务器。

## 环境要求

- Python 3.10+
- 依赖：`pip install -r requirements.txt`

## 快速演示：完整 DNS 迭代解析

演示使用项目自带的 `dns_client.py` 向本地 `dns_server.py` 发起查询，
观察服务器如何通过 **Cache → Database → Engine** 三步管线完成迭代解析。

### 步骤 1：启动 DNS 服务器

```bash
python dns_server.py
```

输出：

```
2026-07-09 12:33:33 [INFO ] [dns_database] DnsDatabase opened: ...\data\dns_cache.db
2026-07-09 12:33:33 [INFO ] [__main__   ] DNS server starting on 0.0.0.0:5354
2026-07-09 12:33:33 [INFO ] [__main__   ] Resolution pipeline: Cache → Database → Engine (iterative)
```

服务器默认监听 `127.0.0.1:5354`。

### 步骤 2：使用 dns_client.py 发起查询

**新开一个终端**，运行：

```bash
python dns_client.py
```

客户端输出（真实抓取）：

```
[*] 客户端启动，目标: 127.0.0.1:5354
[*] 查询域名: www.baidu.com (类型: A)
[*] 查询报文: 31 字节
[*] Hex 预览: 12 34 01 00 00 01 00 00 00 00 00 00 03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01...
[*] 已发送，等待响应...
[+] 收到来自 127.0.0.1:5354 的响应，大小: 47 字节，耗时: 17.61 ms

============================================================
  DNS 响应解析结果
============================================================
  ID: 0x1234  QR=Response  OPCODE=0  RCODE=0 (NoError)
  Questions: 1  Answers: 1  Authority: 0  Additional: 0
  Q[0]: www.baidu.com  (A)
  A[0]: www.baidu.com  A  198.18.0.157  TTL=1

[响应 Hex 全文]
12 34 81 80 00 01 00 01 00 00 00 00 03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 00 01 00 04 c6 12 00 9d
```

> `dns_client.py` 是项目自带的同步 UDP DNS 客户端，默认配置在文件顶部的常量区，可修改 `TARGET_SERVER`、`TARGET_PORT`、`QUERY_DOMAIN`、`QUERY_TYPE` 等参数。

### 步骤 3：观察服务器日志

切回服务器终端，可以看到完整的迭代解析日志：

```
RECV from 127.0.0.1:57161, 31 bytes
QUERY www.baidu.com qtype=1
Step ③ Resolving www.baidu.com (qtype=1) via iterative engine
Queue task: www.baidu.com
TaskStack.run() start
Query → 198.41.0.4 www.baidu.com   ← 向根服务器发起查询
QueryStack.run() start
QueryStack done: 1 answers from www.baidu.com
TaskStack.run() done: 1 answers
Resolved www.baidu.com -> 1 answers, written to DB
SEND 47 bytes, 1 answers, rcode=0, elapsed=0.01s
```

解析流程：
1. **Orchestrator** 接收到查询，检查缓存未命中
2. 走 **Step ③**，交给 `ResolutionEngine` 执行迭代解析
3. **Engine** 从根服务器 `198.41.0.4` 开始查询
4. 收到回答后回填数据库和内存缓存
5. 返回结果给客户端

> 日志中的 `[req=xxxxxxxx]` 是每次请求的唯一追踪 ID，可按 ID grep 还原单条请求的完整处理链路。

### 步骤 4：验证缓存加速

紧接着再次运行客户端：

```bash
python dns_client.py
```

服务器日志显示缓存命中：

```
RECV from 127.0.0.1:57163, 31 bytes
QUERY www.baidu.com qtype=1
Step ① Cache HIT for www.baidu.com (qtype=1)
SEND 47 bytes, 1 answers, rcode=0, elapsed=0.02s
```

第一次查询走 Engine 迭代解析（十几毫秒），第二次查询直接命中内存缓存（微秒级返回），无需再次访问上游服务器。

### 步骤 5：使用 nslookup / dig（备选）

如果系统安装了 `nslookup` 或 `dig`，也可以作为客户端使用：

```bash
# dig（跨平台）
dig @127.0.0.1 -p 5354 www.baidu.com

# nslookup（Linux / macOS）
nslookup -port=5354 www.baidu.com 127.0.0.1

# nslookup（Windows — 不支持自定义 DNS 端口，建议使用 dns_client.py 或 dig）
```

> Windows 版 nslookup 不支持 `-port` 参数，只能使用默认 53 端口。跨平台演示建议用 `dns_client.py` 或 `dig`。

### 步骤 6：运行测试

```bash
pytest tests/ -v
```

测试覆盖：编解码往返、类型工厂、缓存读写、QueryStack/TaskStack 状态机、ResolutionEngine 端到端流程。

## 模块概览

| 模块 | 层级 | 职责 |
|------|------|------|
| `dns_types.py` | Layer 0 | 基于 dataclass 的 DNS 报文结构化类型 |
| `dns_common.py` | Layer 0 | 共享常量、域名编解码、NS 委派提取 |
| `dns_decoder.py` | Layer 1 | 二进制报文 → 结构化数据 |
| `dns_coder.py` | Layer 1 | 结构化数据 → 二进制报文（含域名压缩） |
| `dns_transport.py` | Layer 1 | 传输层抽象 + AsyncUdpTransport |
| `dns_cache.py` | Layer 2 | 内存缓存（答案/负缓存/委派缓存） |
| `dns_database.py` | Layer 2 | SQLite 持久化缓存 |
| `dns_iterative/` | Layer 2 | 双栈状态机迭代解析引擎 |
| `dns_orchestrator.py` | Layer 3 | 三步解析编排器 |
| `dns_server.py` | Layer 4 | asyncio UDP DNS 服务器 |
| `dns_client.py` | — | 同步 UDP DNS 客户端（演示用） |
| `logger.py` | — | 统一日志 + 请求上下文追踪 |

详细模块 API 请参阅 [`ARCHITECTURE.md`](ARCHITECTURE.md)。

## 依赖关系图

```
dns_client.py / dig / nslookup (客户端)
        │ UDP :5354
        ▼
┌─────────────────┐
│   dns_server    │  ← asyncio UDP 接收
└───────┬─────────┘
        │ decode(data) → DnsMessage
        ▼
┌─────────────────┐
│ dns_orchestrator│  ← 三步解析编排
│  Cache→DB→Engine│
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

## 许可证

参见 [LICENSE](LICENSE)。
