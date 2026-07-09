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
from dns_transport import AsyncUdpTransport, Transport
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


class DnsServer:
    """
    DNS 服务器 — 封装完整生命周期和请求处理。

    通过 DnsOrchestrator 执行完整三步解析（Cache → Database → Engine）。
    支持上下文管理器协议，方便测试生命周期管理。
    """

    def __init__(
        self,
        host: str = LISTEN_IP,
        port: int = LISTEN_PORT,
        output_file: str = OUTPUT_FILE,
        *,
        database_path: str | None = None,
        transport: Transport | None = None,
    ):
        self._host = host
        self._port = port
        self._output_file = output_file

        self._cache = DnsCache()
        self._database = DnsDatabase(database_path)
        self._transport = transport if transport is not None else AsyncUdpTransport()
        self._engine = ResolutionEngine(self._transport, cache=self._cache)
        self._orchestrator = DnsOrchestrator(
            cache=self._cache,
            database=self._database,
            engine=self._engine,
        )
        self._sock: socket.socket | None = None
        self._running: bool = False

    @property
    def orchestrator(self) -> DnsOrchestrator:
        """公开编排器实例，供测试访问组件状态。"""
        return self._orchestrator

    async def start(self) -> None:
        """初始化各层、创建 UDP socket 并绑定。"""
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._port))
        self._sock = sock

        _log_startup(self._database.path)
        self._running = True

    async def handle_request(self, data: bytes, addr: tuple[str, int]) -> bytes:
        """
        处理单一 DNS 查询请求。

        完整管线: decode → resolve → build_response → encode
        异常时回显原始 data 以免客户端超时。

        Args:
            data: 客户端发来的原始 UDP 载荷。
            addr: 客户端地址 (ip, port)，用于日志。

        Returns:
            响应字节串。
        """
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
                elapsed = time.monotonic() - t0
                log.info(
                    "SEND %d bytes, rcode=1 (FORMERR), "
                    "elapsed=%.2fs",
                    len(response_bytes), elapsed,
                )
                return response_bytes

            domain = query.questions[0].qname
            qtype = query.questions[0].qtype

            # 设置请求上下文（后续所有模块的日志自动带上）
            set_request_context(request_id, domain, qtype)

            log.info("QUERY %s qtype=%d", domain, qtype)

            result = await self._orchestrator.resolve(domain, qtype)

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
            return data
        finally:
            clear_request_context()

        return response_bytes

    async def serve_forever(self) -> None:
        """主循环：接收 → 处理 → 发送。

        异常隔离：
            - 每个请求独立 try/except，单个请求异常不会导致整个服务器退出
            - Windows 上 socket 关闭时（stop()）的 ConnectionResetError 被静默捕获
            - 其他不可恢复的异常（如 assert 失败）会传播给调用方
        """
        assert self._sock is not None, "call start() before serve_forever()"
        loop = asyncio.get_event_loop()
        sock = self._sock

        while self._running:
            try:
                # 接收
                data, addr = await loop.sock_recvfrom(sock, 4096)
            except (ConnectionResetError, OSError) as e:
                # Windows IOCP 下 stop() 关闭 socket 时投递此异常
                # 检查 _running 标志：如果是正常停止则静默退出
                if not self._running:
                    break
                log.warning("serve_forever recvfrom error: %s", e)
                continue

            try:
                # 保存原始 hex（抓包）
                hex_str = ' '.join(f'{b:02x}' for b in data)
                out_dir = os.path.dirname(self._output_file)
                if out_dir:
                    os.makedirs(out_dir, exist_ok=True)
                with open(self._output_file, 'a', encoding='utf-8') as f:
                    f.write(hex_str + '\n')

                # 处理并发送
                response_bytes = await self.handle_request(data, addr)
                await loop.sock_sendto(sock, response_bytes, addr)
            except Exception as e:
                log.exception("serve_forever request handling failed: %s", e)
                # 单个请求异常不中断主循环

    async def stop(self) -> None:
        """关闭 socket 和数据库连接。"""
        self._running = False
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        self._database.close()
        log.info("DNS server stopped")

    async def __aenter__(self) -> 'DnsServer':
        await self.start()
        return self

    async def __aexit__(self, *args) -> None:
        await self.stop()


async def main():
    """启动 DNS 服务器。"""
    setup_logger(level=logging.INFO)
    server = DnsServer()
    await server.start()
    try:
        await server.serve_forever()
    except KeyboardInterrupt:
        log.info("DNS server stopped (interrupted)")
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
