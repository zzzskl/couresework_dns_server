"""
DNS 服务器集成测试 — mock DnsOrchestrator 后的完整链路验证。

覆盖:
  1. 收到合法 DNS 查询 → decode → orchestrator.resolve() → encode → 响应
  2. 响应 TxID 与查询一致（create_response 修复）
  3. 空 questions 查询 → FORMERR
  4. orchestrator 返回 None → SERVFAIL
  5. 无效报文 → echo fallback

所有测试均为同步函数（使用 asyncio.run 包装内部协程），
不依赖 pytest-asyncio 插件。
"""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import ANY, AsyncMock, patch

import pytest

from dns_decoder import decode
from dns_types import DnsMessage, DnsResourceRecord, DnsHeader

# 使用高端口避免与本地已有服务冲突
TEST_PORT = 53540


def _make_response(domain: str, ip: str, qtype: int = 1) -> DnsMessage:
    """构造一个测试用 DNS 响应。"""
    q = DnsMessage.create_query(domain, "A" if qtype == 1 else "AAAA")
    return DnsMessage.create_response(
        q,
        answers=[
            DnsResourceRecord.create_a(domain, ip)
            if qtype == 1
            else DnsResourceRecord.create_aaaa(domain, ip)
        ],
    )


def _run_server_test(
    orch_return_value,
    client_action,
    *,
    port: int = TEST_PORT,
):
    """
    在单一事件循环中并行运行服务器 + 客户端测试逻辑。

    Args:
        orch_return_value: orchestrator.resolve() 的返回值（或 None）
        client_action:     异步回调 (loop, sock) -> bytes，接收服务器响应并验证
    """
    async def _run():
        with patch("dns_server.LISTEN_PORT", port), \
             patch("dns_server.DnsOrchestrator") as mock_orch_cls:
            mock_orch = AsyncMock()
            mock_orch.resolve.return_value = orch_return_value
            mock_orch_cls.return_value = mock_orch

            # 动态导入避免模块级 side effects
            import dns_server as _ds

            server_task = asyncio.create_task(_ds.main())
            await asyncio.sleep(0.3)  # 等待服务器就绪

            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                result = await client_action(loop, sock)
                return result
            finally:
                server_task.cancel()
                try:
                    await server_task
                except (asyncio.CancelledError, Exception):
                    pass
                sock.close()

    return asyncio.run(_run())


# ══════════════════════════════════════════════════════════════════
# 测试用例
# ══════════════════════════════════════════════════════════════════


def test_server_returns_response_with_correct_txid():
    """合法查询 → 服务器调用 orchestrator.resolve() → 返回响应，
    且响应 TxID 与查询一致。"""
    query = DnsMessage.create_query("test.example.com", "A")
    expected_resp = _make_response("test.example.com", "1.2.3.4")

    async def client(loop, sock):
        await loop.sock_sendto(
            sock, query.to_bytes(), ("127.0.0.1", TEST_PORT)
        )
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 1024), timeout=3.0,
        )
        return data

    data = _run_server_test(expected_resp, client)

    response = decode(data)
    assert response.header.qr == 1, "必须是响应报文"
    assert len(response.answers) == 1
    assert response.answers[0].rdata == "1.2.3.4"
    assert response.header.id == query.header.id, "TxID 应与查询一致"


def test_server_empty_questions_returns_formerr():
    """空 questions 节 → 返回 FORMERR (rcode=1)。"""
    async def client(loop, sock):
        # 构造无 questions 的 DNS 报文（qdcount=0）
        hdr_bytes = (
            (0xABCD).to_bytes(2, "big")      # id
            + (0x0100).to_bytes(2, "big")     # flags: rd=1
            + (0).to_bytes(2, "big")          # qdcount=0
            + (0).to_bytes(2, "big")          # ancount=0
            + (0).to_bytes(2, "big")          # nscount=0
            + (0).to_bytes(2, "big")          # arcount=0
        )
        await loop.sock_sendto(
            sock, hdr_bytes, ("127.0.0.1", TEST_PORT)
        )
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 1024), timeout=3.0,
        )
        return data

    data = _run_server_test(None, client)  # orchestrator 不应被调用

    response = decode(data)
    assert response.header.qr == 1, "必须是响应报文"
    assert response.header.rcode == 1, "空查询应返回 FORMERR"


def test_server_orchestrator_none_returns_servfail():
    """orchestrator 返回 None → 服务器返回 SERVFAIL (rcode=2)。"""
    query = DnsMessage.create_query("unknown.example.com", "A")

    async def client(loop, sock):
        await loop.sock_sendto(
            sock, query.to_bytes(), ("127.0.0.1", TEST_PORT)
        )
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 1024), timeout=3.0,
        )
        return data

    # orchestrator.resolve() 返回 None
    data = _run_server_test(None, client)

    response = decode(data)
    assert response.header.qr == 1, "必须是响应报文"
    assert response.header.rcode == 2, "解析失败应返回 SERVFAIL"
    assert len(response.answers) == 0
    assert response.header.id == query.header.id


def test_server_garbage_data_echoes_back():
    """无效二进制数据 → decode 失败 → 回显原始数据（不崩溃）。"""
    garbage = b"\x00" * 11  # 短于 12 字节，decode 会抛 ValueError

    async def client(loop, sock):
        await loop.sock_sendto(
            sock, garbage, ("127.0.0.1", TEST_PORT)
        )
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 1024), timeout=3.0,
        )
        return data

    data = _run_server_test(None, client)

    assert data == garbage, "无效数据应被回显"
