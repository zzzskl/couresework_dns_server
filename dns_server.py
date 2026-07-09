#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 服务器 — 基于 asyncio 的 UDP DNS 服务器。

通过 DnsOrchestrator 执行完整三步解析（Cache → Database → Engine）:
    ① 内存缓存（DnsCache）— 毫秒级
    ② SQLite 数据库（DnsDatabase）— 毫秒级
    ③ 迭代解析（ResolutionEngine）— 秒级，从根服务器开始递归

收到客户端查询后：
    1. decode() 解析二进制报文为 DnsMessage
    2. orchestrator.resolve() 执行三步解析
    3. create_response() 修正 TxID 为客户端原始值
    4. to_bytes() 编码回二进制 → 发送

日志通过 logger.set_request_context() 注入 [req=xxx] [domain] [qtype]，
所有模块的日志自动携带请求上下文，可通过 `grep req=xxx` 还原请求链路。

用法: 直接运行
"""

# ======================== 服务器配置区域 ========================
LISTEN_IP = "0.0.0.0"            # 监听地址
LISTEN_PORT = 5354               # 监听端口
OUTPUT_FILE = "server/captured.hex"   # 抓包保存文件
# ================================================================

import asyncio
import logging
import os
import socket
import time
import uuid

from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_decoder import decode
from dns_iterative.engine import ResolutionEngine
from dns_orchestrator import DnsOrchestrator
from dns_transport import AsyncUdpTransport
from dns_types import DnsMessage
from logger import (
    clear_request_context,
    set_request_context,
    setup_logger,
)

log = logging.getLogger(__name__)

# ── 启动时一次性日志 ─────────────────────────────
_log_started = False


def _log_startup(database_path: str) -> None:
    """记录服务器启动信息（仅在首次调用时输出一次）。"""
    global _log_started
    if _log_started:
        return
    log.info("DNS server starting on %s:%d", LISTEN_IP, LISTEN_PORT)
    log.info("Resolution pipeline: Cache → Database → Engine (iterative)")
    log.info("Database: %s", database_path)
    _log_started = True


def _build_response(query: DnsMessage, result: DnsMessage) -> DnsMessage:
    """
    根据原始查询和解析结果构造合法 DNS 响应。

    关键作用：
        复制客户端的 TxID（header.id）、question section 到响应中，
        确保客户端不会因为 TxID 不匹配而丢弃响应。
        同时也复制 opcode、rd 等 flag。
    """
    return DnsMessage.create_response(
        query,
        answers=result.answers,
        authorities=result.authorities,
        additionals=result.additionals,
        rcode=result.header.rcode,
    )


async def main():
    """启动 DNS 服务器。"""
    # ── 初始化日志（入口处仅调用一次） ────────────────
    setup_logger(level=logging.INFO)

    # ── 初始化各层 ──────────────────────────────────────
    cache = DnsCache()
    database = DnsDatabase()
    transport = AsyncUdpTransport()
    engine = ResolutionEngine(transport, cache=cache)
    orchestrator = DnsOrchestrator(
        cache=cache,
        database=database,
        engine=engine,
    )

    # ── 创建非阻塞 UDP Socket ──────────────────────────
    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    _log_startup(database.path)

    try:
        while True:
            # ── 接收 ──────────────────────────────────
            data, addr = await loop.sock_recvfrom(sock, 4096)

            # ── 保存原始 hex（抓包） ─────────────────
            hex_str = ' '.join(f'{b:02x}' for b in data)
            out_dir = os.path.dirname(OUTPUT_FILE)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(hex_str)

            # ── 每个请求的独立上下文 ──────────────────
            request_id = uuid.uuid4().hex[:8]
            t0 = time.monotonic()
            set_request_context(request_id, "-", "-")

            try:
                log.info(
                    "RECV from %s:%d, %d bytes",
                    addr[0], addr[1], len(data),
                )

                query = decode(data)

                # 空 questions 节 → 返回 FORMERR
                if not query.questions:
                    log.warning(
                        "Empty questions section → FORMERR",
                    )
                    response = DnsMessage.create_response(query, rcode=1)
                    response_bytes = response.to_bytes()
                    await loop.sock_sendto(sock, response_bytes, addr)
                    elapsed = time.monotonic() - t0
                    log.info(
                        "SEND %d bytes, rcode=1 (FORMERR), "
                        "elapsed=%.2fs",
                        len(response_bytes), elapsed,
                    )
                else:
                    domain = query.questions[0].qname
                    qtype = query.questions[0].qtype

                    # 设置请求上下文（后续所有模块的日志自动带上）
                    set_request_context(request_id, domain, qtype)

                    log.info("QUERY %s qtype=%d", domain, qtype)

                    result = await orchestrator.resolve(domain, qtype)

                    if result is not None:
                        response = _build_response(query, result)
                        n_answers = len(result.answers)
                        rcode = result.header.rcode
                    else:
                        response = DnsMessage.create_response(
                            query,
                            rcode=2,  # SERVFAIL
                        )
                        n_answers = 0
                        rcode = 2

                    response_bytes = response.to_bytes()
                    await loop.sock_sendto(sock, response_bytes, addr)

                    elapsed = time.monotonic() - t0
                    log.info(
                        "SEND %d bytes, %d answers, rcode=%d, "
                        "elapsed=%.2fs",
                        len(response_bytes), n_answers, rcode, elapsed,
                    )

            except Exception as e:
                log.exception(
                    "Request handling failed: %s", e,
                )
                # 回显原始数据（至少让客户端不超时）
                try:
                    await loop.sock_sendto(sock, data, addr)
                except Exception:
                    pass
            finally:
                clear_request_context()

    except KeyboardInterrupt:
        log.info("DNS server stopped (interrupted)")
    finally:
        sock.close()
        database.close()


if __name__ == "__main__":
    asyncio.run(main())
