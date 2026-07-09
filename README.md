# DNS 协议栈

基于 Python asyncio 的完整 DNS 协议栈实现，支持报文编解码、迭代解析、多级缓存和 UDP 服务器。

## 环境要求

- Python 3.10+
- 依赖：`pip install -r requirements.txt`

## 快速演示：从 nslookup 到服务器完整 DNS 解析

本演示使用 `nslookup` 作为客户端，向本项目 DNS 服务器发起查询，观察服务器如何通过 **Cache → Database → Engine** 三步管线完成迭代解析。

### 步骤 1：启动 DNS 服务器

```bash
python dns_server.py
```

输出示例：

```
2025-01-01 00:00:00 [INFO ] [dns_server] DNS server starting on 0.0.0.0:5354
2025-01-01 00:00:00 [INFO ] [dns_server] Resolution pipeline: Cache → Database → Engine
```

服务器默认监听 `0.0.0.0:5354`。

### 步骤 2：发起查询

**新开一个终端**，使用 `nslookup`（或 `dig`）查询：

```bash
nslookup www.baidu.com 127.0.0.1 -port=5354
```

### 步骤 3：观察服务器日志

服务器日志完整展示三步解析过程：

```
[req=a1b2c3d4] [www.baidu.com] [qtype=1] RECV from 127.0.0.1:xxxxx, 32 bytes
[req=a1b2c3d4] [www.baidu.com] [qtype=1] QUERY www.baidu.com qtype=1
[req=a1b2c3d4] [www.baidu.com] [qtype=1] Step ③ Resolving www.baidu.com via iterative engine
[req=a1b2c3d4] [www.baidu.com] [qtype=1] Queue task: www.baidu.com
[req=a1b2c3d4] [www.baidu.com] [qtype=1] Query → 198.41.0.4 www.baidu.com
                    ↓ (根服务器返回 .com NS 委派)
[req=a1b2c3d4] [www.baidu.com] [qtype=1] Query → 192.5.6.30 www.baidu.com
                    ↓ (.com 权威返回 baidu.com NS 委派)
[req=a1b2c3d4] [www.baidu.com] [qtype=1] Query → ns1.baidu.com www.baidu.com
                    ↓ (baidu.com 权威返回最终 A 记录)
[req=a1b2c3d4] [www.baidu.com] [qtype=1] SEND 58 bytes, 1 answers, rcode=0, elapsed=1.23s
```

> **说明：** 迭代解析需要网络连接以访问上游 DNS 服务器。日志中的 `[req=xxx]` 是每次请求的唯一追踪 ID，可通过 `grep req=a1b2c3d4` 还原整条请求链路。

### 步骤 4：验证缓存加速

再次执行相同的查询，观察缓存命中的效果：

```bash
nslookup www.baidu.com 127.0.0.1 -port=5354
```

日志输出：

```
[req=e5f6g7h8] [www.baidu.com] [qtype=1] Step ① Cache HIT for www.baidu.com (qtype=1)
[req=e5f6g7h8] [www.baidu.com] [qtype=1] SEND 58 bytes, 1 answers, rcode=0, elapsed=0.00s
```

第一次查询耗时约 1.23 秒（迭代解析），第二次只需 0.00 秒（内存缓存命中）。

### 步骤 5：运行测试

```bash
pytest tests/ -v
```

24 个测试覆盖：编解码往返、类型工厂、缓存读写、QueryStack/TaskStack 状态机、ResolutionEngine 端到端。

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
| `logger.py` | — | 统一日志 + 请求上下文追踪 |

详细模块 API 请参阅 [`ARCHITECTURE.md`](ARCHITECTURE.md)。

## 依赖关系图

```
nslookup/dig (客户端)
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
