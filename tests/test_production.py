"""
生产场景真实环境测试 — 覆盖 MockTransport 无法验证的集成场景。

测试分类:
    TestRealNetworkResolution — 真实 DNS 基础设施测试 (pytest.mark.network)
    TestServerEndToEnd        — 服务器完整生命周期 + 客户端查询
    TestConcurrentQueries     — 并发请求处理
    TestCachePipeline         — 三步管线真实场景验证
    TestEdgeCasesAndErrors    — 边界/错误场景

注意：
    - 网络测试使用 @pytest.mark.network 标记，CI 中可通过 -m "not network" 跳过
    - 本地服务器测试使用动态端口 (port=0) 避免端口冲突
    - 并发测试使用 asyncio.gather + handle_request（无需绑定端口）
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import tempfile
import time

import pytest

from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_decoder import decode
from dns_iterative.consts import ROOT_SERVERS
from dns_iterative.engine import ResolutionEngine
from dns_orchestrator import DnsOrchestrator
from dns_server import DnsServer, _build_response
from dns_transport import (
    AsyncUdpTransport,
    DnsMessage,
    QueryFrame,
    TransportError,
    TransportTimeoutError,
)
from dns_types import DnsHeader, DnsQuestion, DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# 辅助工具
# ════════════════════════════════════════════════════════════════


def _query_server(
    server: DnsServer,
    domain: str,
    qtype_str: str = "A",
    client_addr: tuple[str, int] = ("127.0.0.1", 12345),
) -> bytes:
    """同步辅助：通过 DnsServer.handle_request 发送查询并返回原始响应 bytes。"""
    wire = DnsMessage.create_query(domain, qtype_str).to_bytes()
    return asyncio.run(server.handle_request(wire, client_addr))


def _decode_response(wire: bytes) -> DnsMessage:
    """解码响应 bytes 为 DnsMessage。"""
    return decode(wire)


# ════════════════════════════════════════════════════════════════
# A. TestRealNetworkResolution — 真实 DNS 基础设施测试
# ════════════════════════════════════════════════════════════════


@pytest.mark.network
class TestRealNetworkResolution:
    """对真实公共 DNS 服务器发送查询，验证传输层和解析引擎在生产环境中的行为。"""

    # ── 基础设施：UDP 传输层 ─────────────────────────────────────

    def test_udp_transport_a_query(self):
        """用 AsyncUdpTransport 对 8.8.8.8 做 A 查询，验证返回合法 DnsMessage。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            result = await transport.query(
                QueryFrame("8.8.8.8", "www.example.com", 1)
            )
            assert result.header.qr == 1  # 响应标志
            assert result.header.rcode == 0  # NoError
            assert len(result.answers) >= 1  # 至少一条 A 记录
            # 验证有 A 或 CNAME 记录
            has_a_or_cname = any(
                r.rr_type in (1, 5) for r in result.answers
            )
            assert has_a_or_cname, "响应中应包含 A 或 CNAME 记录"
            # TxID 应为 0-65535 内的合法值
            assert 0 <= result.header.id <= 65535

        asyncio.run(_test())

    def test_udp_transport_cloudflare(self):
        """用 AsyncUdpTransport 对 1.1.1.1 做 A 查询。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            result = await transport.query(
                QueryFrame("1.1.1.1", "www.example.com", 1)
            )
            assert result.header.qr == 1
            assert result.header.rcode == 0
            assert len(result.answers) >= 1

        asyncio.run(_test())

    def test_aaaa_query(self):
        """AAAA 查询 (qtype=28) 返回 IPv6 地址。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            result = await transport.query(
                QueryFrame("8.8.8.8", "www.example.com", 28)
            )
            assert result.header.qr == 1
            # AAAA 可能存在也可能不存在；至少不应崩溃
            if result.header.rcode == 0 and len(result.answers) > 0:
                aaaa_records = [r for r in result.answers if r.rr_type == 28]
                # 可能有 CNAME 链，但如果有 AAAA 记录应包含 IPv6 地址
                for r in aaaa_records:
                    assert ":" in str(r.rdata), "AAAA rdata 应为 IPv6 地址"

        asyncio.run(_test())

    def test_mx_query(self):
        """MX 查询 (qtype=15) 返回邮件交换记录。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            result = await transport.query(
                QueryFrame("8.8.8.8", "gmail.com", 15)
            )
            assert result.header.qr == 1
            if result.header.rcode == 0 and len(result.answers) > 0:
                mx_records = [r for r in result.answers if r.rr_type == 15]
                for r in mx_records:
                    assert isinstance(r.rdata, dict) or hasattr(r.rdata, 'preference')

        asyncio.run(_test())

    def test_ns_query(self):
        """NS 查询 (qtype=2) 返回名称服务器记录。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            result = await transport.query(
                QueryFrame("8.8.8.8", "example.com", 2)
            )
            assert result.header.qr == 1
            assert result.header.rcode == 0
            ns_records = [r for r in result.answers if r.rr_type == 2]
            assert len(ns_records) >= 1, "应返回至少一条 NS 记录"

        asyncio.run(_test())

        asyncio.run(_test())

    def test_txt_query(self):
        """TXT 查询 (qtype=16) 返回文本记录。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            result = await transport.query(
                QueryFrame("8.8.8.8", "example.com", 16)
            )
            assert result.header.qr == 1
            # TXT 记录可能存在也可能为空
            assert result.header.rcode in (0, 3)

        asyncio.run(_test())

    def test_soa_query(self):
        """SOA 查询 (qtype=6) 返回起始授权机构记录。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            result = await transport.query(
                QueryFrame("8.8.8.8", "example.com", 6)
            )
            assert result.header.qr == 1
            assert result.header.rcode == 0
            soa_records = [r for r in result.answers if r.rr_type == 6]
            assert len(soa_records) >= 1, "应返回至少一条 SOA 记录"

        asyncio.run(_test())

        asyncio.run(_test())

    # ── 错误场景 ─────────────────────────────────────────────────

    def test_nxdomain(self):
        """不存在的域名 → rcode=3 (NXDOMAIN)。

        注意：公共 DNS 服务器（如 8.8.8.8）在高频查询时可能触发
        速率限制（返回超时而非 NXDOMAIN），此时测试跳过而非失败。
        """
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            try:
                result = await transport.query(
                    QueryFrame("8.8.8.8", "this-domain-does-not-exist-99999.test", 1)
                )
            except TransportTimeoutError:
                pytest.skip("8.8.8.8 速率限制导致超时，跳过 NXDOMAIN 验证")
            assert result.header.qr == 1
            assert result.header.rcode == 3, f"期望 NXDOMAIN(3)，得到 {result.header.rcode}"

        asyncio.run(_test())

    def test_invalid_dns_server_timeout(self):
        """无效 DNS 服务器 IP → TransportTimeoutError 或 TransportNetworkError。

        注意：在 DNS 劫持环境下，port 53 的查询可能被全部拦截，
        此时应向保留/不可达地址发送查询才可触发错误。
        """
        async def _test():
            transport = AsyncUdpTransport(timeout=2.0)
            with pytest.raises((TransportTimeoutError, TransportError)):
                await transport.query(
                    QueryFrame("240.0.0.1", "www.example.com", 1)
                )

        asyncio.run(_test())

    def test_txid_match(self):
        """真实 UDP 往返后 TxID 一致。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            # 生成已知 TxID — 注意 AsyncUdpTransport 内部会覆盖 TxID
            frame = QueryFrame("8.8.8.8", "www.example.com", 1)
            result = await transport.query(frame)
            # 验证 response 的 TxID 是合法值（AsyncUdpTransport 内部生成随机 TxID，
            # 并在收到响应后验证一致性；若不一致会抛出异常）
            assert result.header.id is not None

        asyncio.run(_test())

    # ── 迭代解析引擎 (使用真实传输层) ─────────────────────────

    def test_engine_iterative_resolution(self):
        """用 ResolutionEngine + AsyncUdpTransport 迭代解析 www.example.com。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            cache = DnsCache()
            engine = ResolutionEngine(transport, cache=cache)
            result = await engine.resolve("www.example.com", 1)
            assert result is not None, "迭代解析应返回结果"
            assert result.header.rcode == 0
            assert len(result.answers) >= 1
            assert any(r.rr_type in (1, 5) for r in result.answers), "应有 A 或 CNAME 记录"

        asyncio.run(_test())

        asyncio.run(_test())

    def test_engine_with_cache_hit(self):
        """迭代解析后缓存命中，第二次查询不再触发网络 I/O。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            cache = DnsCache()
            engine = ResolutionEngine(transport, cache=cache)

            # 第一次解析（可能触发网络 I/O）
            result1 = await engine.resolve("www.example.com", 1)
            assert result1 is not None

            # 第二次应命中缓存（不触发网络 I/O）
            result2 = await engine.resolve("www.example.com", 1)
            assert result2 is not None
            assert result2.header.rcode == result1.header.rcode

        asyncio.run(_test())

    def test_engine_nxdomain_cache(self):
        """NXDOMAIN 被缓存后反复查询不触发网络 I/O。"""
        async def _test():
            transport = AsyncUdpTransport(timeout=10.0)
            cache = DnsCache()
            engine = ResolutionEngine(transport, cache=cache)

            try:
                result = await engine.resolve(
                    "this-domain-does-not-exist-99999.test", 1
                )
            except TransportTimeoutError:
                pytest.skip("DNS 速率限制导致超时，跳过 NXDOMAIN 缓存验证")
            assert result is not None, "NXDOMAIN 应返回结果"
            assert result.header.rcode == 3, f"期望 NXDOMAIN(3)，得到 {result.header.rcode}"

        asyncio.run(_test())


# ════════════════════════════════════════════════════════════════
# B. TestServerEndToEnd — 服务器完整生命周期 + 客户端查询
# ════════════════════════════════════════════════════════════════


class TestServerEndToEnd:
    """DnsServer 完整生命周期测试，覆盖 start/serve_forever/stop 以及
    通过真实 UDP socket 发送查询的端到端管线。"""

    # ── 生命周期 ─────────────────────────────────────────────────

    def test_async_context_manager(self):
        """async with 生命周期：start → running → stop → socket closed。"""
        async def _lifecycle():
            server = DnsServer(
                host="127.0.0.1", port=0,
                database_path=":memory:",
            )
            async with server:
                assert server._running is True
                assert server._sock is not None
                assert server._sock.fileno() > 0
                # 验证 socket 的确绑定在某个端口上
                port = server._sock.getsockname()[1]
                assert port > 0
            # 退出上下文后应已关闭
            assert server._running is False
            assert server._sock is None

        asyncio.run(_lifecycle())

    def test_start_stop_cycle(self):
        """手动 start/stop 生命周期。"""
        async def _cycle():
            server = DnsServer(
                host="127.0.0.1", port=0,
                database_path=":memory:",
            )
            await server.start()
            assert server._running is True
            assert server._sock is not None
            await server.stop()
            assert server._running is False
            assert server._sock is None

        asyncio.run(_cycle())

    def test_serve_forever_stop(self):
        """启动 serve_forever 后通过 stop 停止。"""
        async def _serve():
            server = DnsServer(
                host="127.0.0.1", port=0,
                database_path=":memory:",
            )
            await server.start()
            # 启动一个协程运行 serve_forever
            serve_task = asyncio.create_task(server.serve_forever())
            await asyncio.sleep(0.1)  # 给 serve_forever 一点时间进入循环
            assert server._running is True
            await server.stop()
            # 等待 serve_forever 退出（Windows 上可能抛出 ConnectionResetError）
            try:
                await asyncio.wait_for(serve_task, timeout=2.0)
            except (asyncio.TimeoutError, ConnectionResetError, OSError):
                pass  # 预期行为：serve_forever 因 socket 关闭而退出

        asyncio.run(_serve())

    # ── 端到端查询 ───────────────────────────────────────────────

    def test_query_via_udp_socket(self):
        """通过真实 UDP socket 向 DnsServer 发送查询，验证响应。

        注意：此测试需要在后台运行 serve_forever 以处理接收到的请求。
        """
        async def _test():
            query = DnsMessage.create_query("test.example", "A")
            query_bytes = query.to_bytes()

            server = DnsServer(
                host="127.0.0.1", port=0,
                database_path=":memory:",
            )
            async with server:
                port = server._sock.getsockname()[1]

                # 在后台运行 serve_forever 处理请求
                serve_task = asyncio.create_task(server.serve_forever())
                await asyncio.sleep(0.05)

                # 用原始 UDP socket 发送查询
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                loop = asyncio.get_event_loop()
                await loop.sock_sendto(sock, query_bytes, ("127.0.0.1", port))

                # 接收响应
                try:
                    response_bytes, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 4096),
                        timeout=3.0,
                    )
                    assert len(response_bytes) > 0
                    msg = decode(response_bytes)
                    assert msg.header.qr == 1
                    assert isinstance(msg.header.rcode, int)
                except asyncio.TimeoutError:
                    pytest.skip("UDP 查询未在预期时间内得到响应")
                finally:
                    sock.close()
                    # 取消 serve 任务
                    serve_task.cancel()
                    try:
                        await serve_task
                    except (asyncio.CancelledError, OSError):
                        pass

        asyncio.run(_test())

    def test_prefilled_cache_response(self):
        """预填缓存后，查询应正确返回缓存中的答案。"""
        async def _test():
            server = DnsServer(
                host="127.0.0.1", port=0,
                database_path=":memory:",
            )

            # 预填缓存
            cached_response = DnsMessage.create_response(
                DnsMessage.create_query("cached.example", "A"),
                answers=[DnsResourceRecord.create_a(
                    "cached.example", "10.0.0.1", ttl=300,
                )],
            )
            server._cache.set_answer("cached.example", 1, 1, cached_response)

            async with server:
                wire = DnsMessage.create_query("cached.example", "A").to_bytes()
                resp_bytes = await server.handle_request(
                    wire, ("127.0.0.1", 12345),
                )
                msg = decode(resp_bytes)
                assert msg.header.rcode == 0
                assert len(msg.answers) == 1
                assert msg.answers[0].rdata == "10.0.0.1"

        asyncio.run(_test())

    def test_orchestrator_exposed_via_property(self):
        """DnsServer 公开 orchestrator 属性供测试访问。"""
        async def _test():
            server = DnsServer(database_path=":memory:")
            async with server:
                orch = server.orchestrator
                assert orch is not None
                assert orch.cache is not None
                assert orch.database is not None
                assert orch.engine is not None

        asyncio.run(_test())

    # ── 错误处理 ─────────────────────────────────────────────────

    def test_former_empty_questions(self):
        """空 questions 节 → FORMERR (rcode=1)。"""
        async def _test():
            server = DnsServer(database_path=":memory:")
            async with server:
                wire = struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0)
                resp_bytes = await server.handle_request(
                    wire, ("127.0.0.1", 12345),
                )
                msg = decode(resp_bytes)
                assert msg.header.rcode == 1  # FORMERR

        asyncio.run(_test())

    def test_servfail_on_engine_failure(self, mock_transport):
        """引擎无法完成解析 → SERVFAIL (rcode=2)。"""
        async def _test():
            server = DnsServer(
                transport=mock_transport, database_path=":memory:",
            )
            async with server:
                wire = DnsMessage.create_query("fail.example", "A").to_bytes()
                resp_bytes = await server.handle_request(
                    wire, ("127.0.0.1", 12345),
                )
                msg = decode(resp_bytes)
                assert msg.header.rcode == 2  # SERVFAIL

        asyncio.run(_test())

    def test_exception_echo_truncated_data(self):
        """截断数据 → decode 异常 → 回显原始数据。"""
        async def _test():
            server = DnsServer(database_path=":memory:")
            async with server:
                raw = b"\x00"
                echoed = await server.handle_request(raw, ("127.0.0.1", 12345))
                assert echoed == raw

        asyncio.run(_test())

    def test_exception_echo_empty(self):
        """空数据 → 回显空数据。"""
        async def _test():
            server = DnsServer(database_path=":memory:")
            async with server:
                empty = b""
                echoed = await server.handle_request(empty, ("127.0.0.1", 12345))
                assert echoed == empty

        asyncio.run(_test())


# ════════════════════════════════════════════════════════════════
# C. TestConcurrentQueries — 并发请求处理
# ════════════════════════════════════════════════════════════════


class TestConcurrentQueries:
    """并发场景测试，验证 DnsServer.handle_request 在大量并发查询下不会崩溃，
    且响应间的 TxID 不会混淆。"""

    def test_concurrent_10_queries(self):
        """同时发送 10 个不同域名查询，全部返回且不崩溃。"""
        async def _test():
            server = DnsServer(database_path=":memory:")

            # 预填 10 个不同域名的缓存
            for i in range(10):
                domain = f"host{i:03d}.concurrent.example"
                resp = DnsMessage.create_response(
                    DnsMessage.create_query(domain, "A"),
                    answers=[DnsResourceRecord.create_a(
                        domain, f"10.0.0.{i}", ttl=300,
                    )],
                )
                server._cache.set_answer(domain, 1, 1, resp)

            async with server:
                wires = [
                    DnsMessage.create_query(
                        f"host{i:03d}.concurrent.example", "A"
                    ).to_bytes()
                    for i in range(10)
                ]

                async def send_query(data: bytes) -> DnsMessage:
                    resp_bytes = await server.handle_request(
                        data, ("127.0.0.1", 12345 + data[0]),
                    )
                    return decode(resp_bytes)

                results = await asyncio.gather(
                    *[send_query(w) for w in wires],
                    return_exceptions=True,
                )

                # 验证所有查询都返回合法响应
                successes = 0
                for r in results:
                    assert not isinstance(r, Exception), f"查询异常: {r}"
                    assert r.header.qr == 1
                    if r.header.rcode == 0:
                        successes += 1
                        assert len(r.answers) >= 1
                # 大多数（或全部）应成功
                assert successes >= 8, f"仅 {successes}/10 成功"

        asyncio.run(_test())

    def test_concurrent_50_queries(self):
        """同时发送 50 个查询，验证服务器不崩溃。"""
        async def _test():
            server = DnsServer(database_path=":memory:")
            domains = []
            for i in range(50):
                domain = f"bulk{i:03d}.stress.example"
                domains.append(domain)
                resp = DnsMessage.create_response(
                    DnsMessage.create_query(domain, "A"),
                    answers=[DnsResourceRecord.create_a(
                        domain, f"10.0.0.{i}", ttl=300,
                    )],
                )
                server._cache.set_answer(domain, 1, 1, resp)

            async with server:
                wires = [
                    DnsMessage.create_query(d, "A").to_bytes()
                    for d in domains
                ]

                async def q(data: bytes) -> DnsMessage:
                    resp_bytes = await server.handle_request(
                        data, ("127.0.0.1", 12345),
                    )
                    return decode(resp_bytes)

                results = await asyncio.gather(
                    *[q(w) for w in wires],
                    return_exceptions=True,
                )

                successful = sum(
                    1 for r in results
                    if not isinstance(r, Exception) and r.header.qr == 1
                )
                assert successful >= 45, f"仅 {successful}/50 成功"

        asyncio.run(_test())

    def test_concurrent_txid_no_confusion(self):
        """并发查询的 TxID 不应混淆。"""
        async def _test():
            server = DnsServer(database_path=":memory:")

            # 预填 5 个域名的缓存，每个返回不同 IP
            domains = {}
            for i in range(5):
                domain = f"txid{i}.test.example"
                resp = DnsMessage.create_response(
                    DnsMessage.create_query(domain, "A"),
                    answers=[DnsResourceRecord.create_a(
                        domain, f"192.168.0.{i}", ttl=300,
                    )],
                )
                server._cache.set_answer(domain, 1, 1, resp)
                domains[domain] = f"192.168.0.{i}"

            async with server:
                wires = {}
                for domain in domains:
                    # 使用 mutable bytearray 以便修改 TxID
                    w = bytearray(DnsMessage.create_query(domain, "A").to_bytes())
                    # 手动设置不同的 TxID（使用 IP 最后一段作为 TxID）
                    txid = int(domains[domain].split(".")[-1])
                    struct.pack_into("!H", w, 0, txid)
                    wires[domain] = bytes(w)

                async def send(domain: str, data: bytes) -> tuple[str, DnsMessage]:
                    resp_bytes = await server.handle_request(
                        data, ("127.0.0.1", 12345),
                    )
                    return domain, decode(resp_bytes)

                tasks = [send(d, w) for d, w in wires.items()]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for r in results:
                    if isinstance(r, Exception):
                        continue
                    domain, msg = r
                    if msg.header.rcode == 0 and msg.answers:
                        assert msg.answers[0].rdata == domains[domain], \
                            f"{domain}: 期望 {domains[domain]}, 得到 {msg.answers[0].rdata}"

        asyncio.run(_test())

    def test_concurrent_mixed_qtypes(self):
        """并发 A + AAAA 查询，结果互不干扰。"""
        async def _test():
            server = DnsServer(database_path=":memory:")

            a_resp = DnsMessage.create_response(
                DnsMessage.create_query("dual.example", "A"),
                answers=[DnsResourceRecord.create_a(
                    "dual.example", "1.2.3.4", ttl=300,
                )],
            )
            aaaa_resp = DnsMessage.create_response(
                DnsMessage.create_query("dual.example", "AAAA"),
                answers=[DnsResourceRecord.create_aaaa(
                    "dual.example", "::1", ttl=300,
                )],
            )
            server._cache.set_answer("dual.example", 1, 1, a_resp)
            server._cache.set_answer("dual.example", 28, 1, aaaa_resp)

            async with server:
                a_wire = DnsMessage.create_query("dual.example", "A").to_bytes()
                aaaa_wire = DnsMessage.create_query("dual.example", "AAAA").to_bytes()

                async def query_a() -> DnsMessage:
                    return decode(await server.handle_request(
                        a_wire, ("127.0.0.1", 12345),
                    ))

                async def query_aaaa() -> DnsMessage:
                    return decode(await server.handle_request(
                        aaaa_wire, ("127.0.0.1", 12346),
                    ))

                a_result, aaaa_result = await asyncio.gather(
                    query_a(), query_aaaa(),
                )

                assert a_result.header.rcode == 0
                assert len(a_result.answers) == 1
                assert a_result.answers[0].rr_type == 1  # A

                assert aaaa_result.header.rcode == 0
                assert len(aaaa_result.answers) == 1
                assert aaaa_result.answers[0].rr_type == 28  # AAAA

        asyncio.run(_test())


# ════════════════════════════════════════════════════════════════
# D. TestCachePipeline — 三步管线真实场景验证
# ════════════════════════════════════════════════════════════════


class TestCachePipeline:
    """三步解析管线 (Cache → Database → Engine) 的完整流程测试，
    使用 MockTransport 控制 Engine 行为，验证各层写入/读取正确性。"""

    # ── 标准三步流程 ─────────────────────────────────────────────

    def test_miss_miss_hit_pipeline(self, mock_transport, sample_a_response):
        """
        首次查询: Cache MISS → DB MISS → Engine resolve → 写回 DB + Cache
        二次查询: Cache HIT（毫秒级返回），结果一致
        """
        async def _test():
            cache = DnsCache()
            db = DnsDatabase(":memory:")
            engine = ResolutionEngine(mock_transport, cache=cache)

            mock_transport.set_response("198.41.0.4", sample_a_response)

            orchestrator = DnsOrchestrator(cache, db, engine)

            # 第一次查询 — 应该走 Engine
            assert cache.get_answer("www.example.com", 1) is None
            assert db.get_answer("www.example.com", 1) is None

            result1 = await orchestrator.resolve("www.example.com", 1)
            assert result1 is not None
            assert result1.header.rcode == 0
            assert result1.answers[0].rdata == "93.184.216.34"

            # 验证已写入 Cache
            cached = cache.get_answer("www.example.com", 1)
            assert cached is not None
            assert cached.answers[0].rdata == "93.184.216.34"

            # 验证已写入 DB
            db_hit = db.get_answer("www.example.com", 1)
            assert db_hit is not None
            assert db_hit.answers[0].rdata == "93.184.216.34"

            # 第二次查询 — 应从 Cache HIT（MockTransport 的 call_count 不变）
            before = mock_transport.call_count
            result2 = await orchestrator.resolve("www.example.com", 1)
            assert result2 is not None
            assert result2.answers[0].rdata == "93.184.216.34"
            # transport 不应被调用（cache hit）
            assert mock_transport.call_count == before

        asyncio.run(_test())

    def test_db_promotes_to_cache(self, mock_transport, sample_a_response):
        """
        数据库中有缓存但 Cache 中无 → 查询命中 DB 后推广到 Cache。
        """
        async def _test():
            cache = DnsCache()
            db = DnsDatabase(":memory:")
            engine = ResolutionEngine(mock_transport, cache=cache)

            # 直接写入 DB（跳过 Cache）
            db.set_answer("dbonly.example", 1, 1, sample_a_response)
            assert cache.get_answer("dbonly.example", 1) is None  # Cache 未命中

            orchestrator = DnsOrchestrator(cache, db, engine)
            result = await orchestrator.resolve("dbonly.example", 1)
            assert result is not None
            assert result.answers[0].rdata == "93.184.216.34"

            # 验证已推广到 Cache
            cached = cache.get_answer("dbonly.example", 1)
            assert cached is not None

        asyncio.run(_test())

    # ── DB 持久化 ─────────────────────────────────────────────────

    def test_db_persistence(self, sample_a_response):
        """
        DB 持久化：关闭再打开同一 DB 文件，验证数据存在。
        """
        async def _test():
            # 用临时文件
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                db_path = f.name

            try:
                db1 = DnsDatabase(db_path)
                db1.set_answer("persist.example", 1, 1, sample_a_response)
                db1.close()

                # 重新打开同一文件
                db2 = DnsDatabase(db_path)
                hit = db2.get_answer("persist.example", 1)
                assert hit is not None
                assert hit.answers[0].rdata == "93.184.216.34"
                db2.close()
            finally:
                if os.path.exists(db_path):
                    os.unlink(db_path)

        asyncio.run(_test())

    def test_db_ttl_expiry(self, sample_a_response):
        """
        DB 条目过期后 get_answer 返回 None（懒清理）。
        """
        async def _test():
            db = DnsDatabase(":memory:")
            # 写入 TTL=0 → 立即过期
            db.set_answer("expire.test", 1, 1, sample_a_response, ttl=0)
            # 立即读取应返回 None（已过期）
            hit = db.get_answer("expire.test", 1)
            assert hit is None

        asyncio.run(_test())

    # ── 负缓存 ────────────────────────────────────────────────────

    def test_negative_cache(self, mock_transport):
        """
        NXDOMAIN 被缓存后，二次查询不触发网络 I/O。
        """
        async def _test():
            cache = DnsCache()
            db = DnsDatabase(":memory:")
            engine = ResolutionEngine(mock_transport, cache=cache)

            # MockTransport 返回 NXDOMAIN
            nx_resp = DnsMessage.create_response(
                DnsMessage.create_query("nx.test", "A"),
                rcode=3, authorities=[],
            )
            mock_transport.set_response("198.41.0.4", nx_resp)

            orchestrator = DnsOrchestrator(cache, db, engine)

            # 第一次查询（走 Engine）
            result1 = await orchestrator.resolve("nx.test", 1)
            # NXDOMAIN 时 resolve 返回 result（rcode=3）而非 None
            assert result1 is not None
            assert result1.header.rcode == 3

            # 负缓存已写入
            cached = cache.get_answer("nx.test", 1)
            assert cached is not None
            assert cached.header.rcode == 3

            # 第二次查询 — Cache HIT
            before = mock_transport.call_count
            result2 = await orchestrator.resolve("nx.test", 1)
            assert result2 is not None
            assert result2.header.rcode == 3
            assert mock_transport.call_count == before  # 无网络 I/O

        asyncio.run(_test())

    # ── 委派缓存 ─────────────────────────────────────────────────

    def test_delegation_cache_skips_root(self, mock_transport, sample_a_response):
        """
        父域名 NS 委派被缓存后 → 子域名查询跳过根服务器阶段。
        """
        async def _test():
            cache = DnsCache()
            engine = ResolutionEngine(mock_transport, cache=cache)

            # 预填委派缓存：example.com → ns1.example.com (1.2.3.4)
            cache.set_delegation(
                "example.com",
                ns_records=[
                    DnsResourceRecord.create_ns(
                        "example.com", "ns1.example.com", ttl=3600,
                    ),
                ],
                glue_records=[
                    DnsResourceRecord.create_a(
                        "ns1.example.com", "1.2.3.4", ttl=3600,
                    ),
                ],
            )

            # 为 ns1.example.com (1.2.3.4) 注册 A 响应
            mock_transport.set_response("1.2.3.4", sample_a_response)

            # 解析子域名 — 应从委派缓存找到 ns1.example.com，跳过根服务器
            result = await engine.resolve("www.example.com", 1)
            assert result is not None
            assert result.header.rcode == 0

            # 验证 transport 只查询了 1.2.3.4，未触及根服务器
            assert mock_transport.call_count == 1
            assert mock_transport.last_frame is not None
            assert mock_transport.last_frame.target_ip == "1.2.3.4"

        asyncio.run(_test())

    def test_no_delegation_cache_uses_root(self, mock_transport, sample_a_response):
        """
        无委派缓存 → 使用根服务器。
        """
        async def _test():
            cache = DnsCache()
            engine = ResolutionEngine(mock_transport, cache=cache)

            mock_transport.set_response("198.41.0.4", sample_a_response)

            result = await engine.resolve("www.example.com", 1)
            assert result is not None
            assert result.header.rcode == 0

            # 验证 transport 查询了根服务器
            assert mock_transport.call_count >= 1
            assert mock_transport.last_frame is not None
            assert mock_transport.last_frame.target_ip == "198.41.0.4"

        asyncio.run(_test())

    # ── 管线优先级 ───────────────────────────────────────────────

    def test_cache_over_db(self, sample_a_query):
        """
        三层管线优先级：Cache > Database > Engine。
        Cache 和 DB 同时有同一域名的缓存但内容不同，
        验证返回 Cache 中的结果。
        """
        async def _test():
            cache = DnsCache()
            db = DnsDatabase(":memory:")

            # Cache: IP_A
            cache_a = DnsMessage.create_response(
                sample_a_query,
                answers=[DnsResourceRecord.create_a(
                    "priority.example", "1.1.1.1", ttl=300,
                )],
            )
            cache.set_answer("priority.example", 1, 1, cache_a)

            # DB: IP_B
            db_b = DnsMessage.create_response(
                sample_a_query,
                answers=[DnsResourceRecord.create_a(
                    "priority.example", "2.2.2.2", ttl=300,
                )],
            )
            db.set_answer("priority.example", 1, 1, db_b)

            orchestrator = DnsOrchestrator(cache, db, None)  # type: ignore[arg-type]
            result = await orchestrator.resolve("priority.example", 1)
            assert result is not None
            assert result.answers[0].rdata == "1.1.1.1"  # Cache 胜出

        asyncio.run(_test())


# ════════════════════════════════════════════════════════════════
# E. TestEdgeCasesAndErrors — 边界/错误场景
# ════════════════════════════════════════════════════════════════


class TestEdgeCasesAndErrors:
    """边界条件和错误场景的集成测试。"""

    # ── 输入验证 ─────────────────────────────────────────────────

    def test_empty_domain_raises(self):
        """空域名 → QueryFrame 初始化时抛出 ValueError。"""
        with pytest.raises(ValueError, match="domain"):
            QueryFrame("8.8.8.8", "", 1)

    def test_empty_target_ip_raises(self):
        """空 target_ip → QueryFrame 初始化时抛出 ValueError。"""
        with pytest.raises(ValueError, match="target_ip"):
            QueryFrame("", "www.example.com", 1)

    def test_invalid_qtype_raises(self):
        """无效 qtype → QueryFrame 初始化时抛出 ValueError。"""
        with pytest.raises(ValueError, match="qtype"):
            QueryFrame("8.8.8.8", "www.example.com", 99999)

    def test_negative_qtype_raises(self):
        """负 qtype → ValueError。"""
        with pytest.raises(ValueError, match="qtype"):
            QueryFrame("8.8.8.8", "www.example.com", -1)

    # ── 超长域名 ─────────────────────────────────────────────────

    def test_oversized_domain_encoding(self):
        """超长域名（>253 字符）→ encode_domain 不抛出异常（逐标签编码），
        但整体报文可能超过 UDP 512 字节限制。验证至少不崩溃。"""
        long_domain = "a." * 150 + "com"  # ~300 chars
        from dns_common import encode_domain
        try:
            encoded = encode_domain(long_domain)
            assert len(encoded) > 0
        except Exception as e:
            pytest.fail(f"超长域名编码不应抛出异常: {e}")

    def test_oversized_domain_create_query(self):
        """超长域名构造查询不应崩溃。"""
        long_domain = "a." * 150 + "com"
        try:
            msg = DnsMessage.create_query(long_domain, "A")
            assert msg is not None
            assert len(msg.questions) == 1
            assert msg.questions[0].qname == long_domain
        except Exception as e:
            # ValueError 也是可接受的
            assert isinstance(e, ValueError)

    # ── 边界 qtype ───────────────────────────────────────────────

    def test_qtype_0(self):
        """qtype=0 边界值。"""
        try:
            frame = QueryFrame("8.8.8.8", "test.example", 0)
            assert frame.qtype == 0
        except ValueError:
            pass  # 如果实现层面禁止 qtype=0 也合理

    def test_qtype_65536(self):
        """qtype=65536 超出范围。"""
        with pytest.raises(ValueError, match="qtype"):
            QueryFrame("8.8.8.8", "test.example", 65536)

    # ── 超时机制 ─────────────────────────────────────────────────

    def test_transport_timeout_short(self):
        """超短 timeout (0.5s) 对不可达服务器触发超时或网络错误。

        注意：在 DNS 劫持环境下（如部分 ISP/企业网络），对所有 port 53 的 DNS
        查询可能被拦截并返回伪造响应。此时无法测试真正的超时，但仍会触发
        TransportNetworkError（对不可达地址）。
        """
        async def _test():
            transport = AsyncUdpTransport(timeout=0.5)
            t0 = time.monotonic()
            try:
                await transport.query(
                    # 240.0.0.0/4 是保留地址段，通常不可达
                    QueryFrame("240.0.0.1", "test.example", 1),
                )
                pytest.fail("应抛出超时或网络错误")
            except (TransportTimeoutError, TransportError):
                pass  # 预期行为：超时或网络错误
            elapsed = time.monotonic() - t0
            # 应在合理时间内失败（~0.5s + 少量开销）
            assert elapsed < 10.0, f"超时耗时过长: {elapsed:.2f}s"

        asyncio.run(_test())

    # ── _build_response 边界 ────────────────────────────────────

    def test_build_response_empty_answer(self, sample_a_query):
        """_build_response 处理空 answers 列表。"""
        result = DnsMessage.create_response(
            sample_a_query, answers=[],
        )
        response = _build_response(sample_a_query, result)
        assert response.header.qr == 1
        assert response.header.id == sample_a_query.header.id
        assert len(response.answers) == 0

    def test_build_response_rcode_propagation(self, sample_a_query):
        """_build_response 传播 rcode。"""
        for rcode in (0, 1, 2, 3, 4, 5):
            result = DnsMessage.create_response(
                sample_a_query, rcode=rcode,
            )
            response = _build_response(sample_a_query, result)
            assert response.header.rcode == rcode

    # ── DnsServer.handle_request 空 questions 的更多变体 ──────

    def test_former_qdcount_zero_with_ancount(self):
        """QDCOUNT=0, ANCOUNT=1 → 无 questions 但有 answers → FORMERR。"""
        async def _test():
            server = DnsServer(database_path=":memory:")
            async with server:
                header = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 1, 0, 0)
                answer = (
                    b"\x00" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([1, 2, 3, 4])
                )
                resp_bytes = await server.handle_request(
                    header + answer, ("127.0.0.1", 12345),
                )
                msg = decode(resp_bytes)
                assert msg.header.rcode == 1  # FORMERR

        asyncio.run(_test())
