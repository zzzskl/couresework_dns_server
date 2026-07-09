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

from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_decoder import decode
from dns_iterative.engine import ResolutionEngine
from dns_orchestrator import DnsOrchestrator
from dns_transport import AsyncUdpTransport
from dns_types import DnsMessage

log = logging.getLogger(__name__)


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
    # ── 初始化各层 ──────────────────────────────────────────────
    cache = DnsCache()
    database = DnsDatabase()
    transport = AsyncUdpTransport()
    engine = ResolutionEngine(transport, cache=cache)
    orchestrator = DnsOrchestrator(
        cache=cache,
        database=database,
        engine=engine,
    )

    # ── 创建非阻塞 UDP Socket ──────────────────────────────────
    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(f"[*] DNS 服务器已启动，监听 {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[*] 解析流程: Cache → Database → Engine (iterative)")
    print(f"[*] 数据库: {database.path}")
    print("[*] 等待客户端请求... (按 Ctrl+C 退出)\n")

    try:
        while True:
            # ── 接收 ──────────────────────────────────────────
            data, addr = await loop.sock_recvfrom(sock, 4096)
            print(f"[>] 收到来自 {addr[0]}:{addr[1]} 的请求，"
                  f"大小: {len(data)} 字节")

            # ── 保存原始 hex（抓包） ─────────────────────────
            hex_str = ' '.join(f'{b:02x}' for b in data)
            out_dir = os.path.dirname(OUTPUT_FILE)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(hex_str)

            # ── 解析并处理 ────────────────────────────────────
            try:
                query = decode(data)

                # 空 questions 节 → 返回 FORMERR（不访问 questions[0]）
                if not query.questions:
                    print(f"    Warning: empty questions section")
                    response = DnsMessage.create_response(query, rcode=1)  # FORMERR
                    response_bytes = response.to_bytes()
                    await loop.sock_sendto(sock, response_bytes, addr)
                    print(f"[<] 已返回 FORMERR ({len(response_bytes)} 字节)")
                else:
                    domain = query.questions[0].qname
                    qtype = query.questions[0].qtype
                    print(f"    Query: {domain} (type={qtype})")

                    result = await orchestrator.resolve(domain, qtype)

                    if result is not None:
                        response = _build_response(query, result)
                        n_answers = len(result.answers)
                    else:
                        # 解析失败：返回 SERVFAIL
                        response = DnsMessage.create_response(
                            query,
                            rcode=2,  # SERVFAIL
                        )
                        n_answers = 0

                    response_bytes = response.to_bytes()
                    await loop.sock_sendto(sock, response_bytes, addr)
                    print(f"[<] 已返回 DNS 响应 ({len(response_bytes)} 字节, "
                          f"{n_answers} 条 Answer)")

            except Exception as e:
                # 解码/处理失败时回显原始数据（至少让客户端不超时）
                try:
                    await loop.sock_sendto(sock, data, addr)
                except Exception:
                    pass
                print(f"[!] 处理失败 ({e})，已回显原始数据")

            print("[*] 继续等待下一个请求...\n")

    except KeyboardInterrupt:
        print("\n[*] 用户中断，服务器已关闭")
    finally:
        sock.close()
        database.close()


if __name__ == "__main__":
    asyncio.run(main())
