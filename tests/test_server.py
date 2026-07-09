"""
dns_server.py — DnsServer 完整集成测试。

覆盖: _build_response / _log_startup / DnsServer.handle_request
"""

from __future__ import annotations

import struct

import pytest

from dns_cache import DnsCache
from dns_decoder import decode
from dns_server import DnsServer, _build_response, _log_startup
from dns_transport import TransportError, TransportTimeoutError
from dns_types import DnsMessage, DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# _build_response
# ════════════════════════════════════════════════════════════════


class TestBuildResponse:
    def test_basic(self, sample_a_query, sample_a_response):
        """TxID 和 question 节一致."""
        response = _build_response(sample_a_query, sample_a_response)
        assert response.header.qr == 1
        assert response.header.id == sample_a_query.header.id
        assert len(response.questions) == 1
        assert response.questions[0].qname == sample_a_query.questions[0].qname
        assert response.answers[0].rdata == sample_a_response.answers[0].rdata

    def test_with_multiple_answers(self, sample_a_query):
        """多条答案."""
        result = DnsMessage.create_response(
            sample_a_query,
            answers=[
                DnsResourceRecord.create_a("www.example.com", "1.1.1.1"),
                DnsResourceRecord.create_a("www.example.com", "2.2.2.2"),
            ],
        )
        response = _build_response(sample_a_query, result)
        assert len(response.answers) == 2
        assert response.answers[0].rdata == "1.1.1.1"

    def test_with_authorities_additionals(self, sample_a_query):
        """含 authority 和 additional."""
        result = DnsMessage.create_response(
            sample_a_query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            authorities=[
                DnsResourceRecord.create_ns("example.com", "ns1.example.com")
            ],
            additionals=[
                DnsResourceRecord.create_a("ns1.example.com", "5.6.7.8")
            ],
        )
        response = _build_response(sample_a_query, result)
        assert len(response.authorities) == 1
        assert len(response.additionals) == 1


# ════════════════════════════════════════════════════════════════
# _log_startup
# ════════════════════════════════════════════════════════════════


class TestLogStartup:
    def test_first_call(self):
        """首次调用输出日志."""
        import dns_server
        dns_server._log_started = False
        _log_startup(":memory:")
        assert dns_server._log_started is True

    def test_second_call_skipped(self):
        """重复调用跳过."""
        import dns_server
        dns_server._log_started = True
        _log_startup("test.db")
        assert dns_server._log_started is True


# ════════════════════════════════════════════════════════════════
# DnsServer.handle_request — 集成测试
# ════════════════════════════════════════════════════════════════


def _handle(server, domain: str, qtype_str: str) -> DnsMessage:
    """辅助：同步调用 handle_request 并 decode 返回值。"""
    import asyncio
    wire = DnsMessage.create_query(domain, qtype_str).to_bytes()
    resp_bytes = asyncio.run(server.handle_request(wire, ("127.0.0.1", 12345)))
    return decode(resp_bytes)


class TestNoerror:
    """rcode=0: 7 种 QTYPE 通过缓存命中走完整管线。"""

    def _cached_server(self, domain: str, qtype: int, response: DnsMessage) -> DnsServer:
        """创建 DnsServer 并预填缓存。"""
        server = DnsServer(database_path=":memory:")
        server._cache.set_answer(domain, qtype, 1, response)
        return server

    def test_a(self, sample_a_response):
        """A 记录 (qtype=1)."""
        msg = _handle(self._cached_server("t.example", 1, sample_a_response), "t.example", "A")
        assert msg.header.rcode == 0
        assert len(msg.answers) == 1
        assert msg.answers[0].rdata == "93.184.216.34"

    def test_aaaa(self, sample_aaaa_response):
        """AAAA 记录 (qtype=28)."""
        msg = _handle(self._cached_server("t.example", 28, sample_aaaa_response), "t.example", "AAAA")
        assert msg.header.rcode == 0
        assert len(msg.answers) == 1
        assert msg.answers[0].rdata == "2606:2800:0220:0001:0248:1893:25c8:1946"

    def test_ns(self):
        """NS 记录 (qtype=2)."""
        r = DnsMessage.create_response(
            DnsMessage.create_query("example.com", "NS"),
            answers=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        )
        msg = _handle(self._cached_server("example.com", 2, r), "example.com", "NS")
        assert msg.header.rcode == 0
        assert msg.answers[0].rdata == "ns1.example.com"

    def test_cname(self, sample_cname_response):
        """CNAME 记录 (qtype=5)."""
        msg = _handle(self._cached_server("alias.t.example", 5, sample_cname_response), "alias.t.example", "CNAME")
        assert msg.header.rcode == 0
        assert msg.answers[0].rr_type == 5
        assert msg.answers[0].rdata == "www.example.com"

    def test_mx(self):
        """MX 记录 (qtype=15)."""
        r = DnsMessage.create_response(
            DnsMessage.create_query("example.com", "MX"),
            answers=[DnsResourceRecord(
                name="example.com", rr_type=15, type_str="MX",
                rr_class=1, class_str="IN", ttl=300,
                rdata={"preference": 10, "exchange": "mail.example.com"},
            )],
        )
        msg = _handle(self._cached_server("example.com", 15, r), "example.com", "MX")
        assert msg.header.rcode == 0
        assert msg.answers[0].rdata["preference"] == 10
        assert msg.answers[0].rdata["exchange"] == "mail.example.com"

    def test_txt(self):
        """TXT 记录 (qtype=16)."""
        r = DnsMessage.create_response(
            DnsMessage.create_query("example.com", "TXT"),
            answers=[DnsResourceRecord(
                name="example.com", rr_type=16, type_str="TXT",
                rr_class=1, class_str="IN", ttl=300,
                rdata="v=spf1 include:_spf.example.com ~all",
            )],
        )
        msg = _handle(self._cached_server("example.com", 16, r), "example.com", "TXT")
        assert msg.header.rcode == 0
        assert "spf" in msg.answers[0].rdata

    def test_soa(self):
        """SOA 记录 (qtype=6)."""
        r = DnsMessage.create_response(
            DnsMessage.create_query("example.com", "SOA"),
            answers=[DnsResourceRecord(
                name="example.com", rr_type=6, type_str="SOA",
                rr_class=1, class_str="IN", ttl=3600,
                rdata={
                    "mname": "ns1.example.com", "rname": "admin.example.com",
                    "serial": 2026070901, "refresh": 3600, "retry": 900,
                    "expire": 1209600, "minimum": 86400,
                },
            )],
        )
        msg = _handle(self._cached_server("example.com", 6, r), "example.com", "SOA")
        assert msg.header.rcode == 0
        assert msg.answers[0].rdata["mname"] == "ns1.example.com"
        assert msg.answers[0].rdata["serial"] == 2026070901


class TestFormerr:
    """rcode=1: 空 question 节。"""

    def _formerr(self, data: bytes) -> DnsMessage:
        import asyncio
        server = DnsServer(database_path=":memory:")
        resp_bytes = asyncio.run(server.handle_request(data, ("127.0.0.1", 12345)))
        return decode(resp_bytes)

    def test_qdcount_zero(self):
        """12B header, QDCOUNT=0."""
        msg = self._formerr(struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0))
        assert msg.header.rcode == 1

    def test_qdcount_zero_with_tail(self):
        """12B header + 尾部垃圾, QDCOUNT=0."""
        msg = self._formerr(
            struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0) + b"\xde\xad\xbe\xef"
        )
        assert msg.header.rcode == 1

    def test_qdcount_zero_valid_answer(self):
        """QDCOUNT=0, ANCOUNT=1 (有效 DNS 响应但无 question)."""
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 1, 0, 0)
        answer = (
            b"\x00" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([1, 2, 3, 4])  # name=root, type=A, class=IN, TTL=300, rdata=1.2.3.4
        )
        msg = self._formerr(header + answer)
        assert msg.header.rcode == 1


class TestServfail:
    """rcode=2: 引擎无法完成解析。"""

    def test_transport_all_timeout(self, mock_transport):
        """所有目标服务器超时 → SERVFAIL."""
        import asyncio
        server = DnsServer(transport=mock_transport, database_path=":memory:")
        wire = DnsMessage.create_query("fail.example", "A").to_bytes()
        resp_bytes = asyncio.run(server.handle_request(wire, ("127.0.0.1", 12345)))
        msg = decode(resp_bytes)
        assert msg.header.rcode == 2

    def test_empty_response_no_answers(self, mock_transport):
        """收到 rcode=0 但无答案/CNAME → NODATA (NOERROR+空答案)."""
        import asyncio
        empty = DnsMessage.create_response(
            DnsMessage.create_query("x.example", "A"), answers=[], authorities=[], additionals=[],
        )
        mock_transport.set_response("198.41.0.4", empty)
        server = DnsServer(transport=mock_transport, database_path=":memory:")
        wire = DnsMessage.create_query("x.example", "A").to_bytes()
        resp_bytes = asyncio.run(server.handle_request(wire, ("127.0.0.1", 12345)))
        msg = decode(resp_bytes)
        # 修复后行为：NOERROR+空答案是合法的 NODATA，非 SERVFAIL
        assert msg.header.rcode == 0

    def test_transport_error(self, mock_transport):
        """TransportError (非超时) → SERVFAIL."""
        import asyncio
        mock_transport.set_error("198.41.0.4", TransportError("connection refused"))
        server = DnsServer(transport=mock_transport, database_path=":memory:")
        wire = DnsMessage.create_query("err.example", "A").to_bytes()
        resp_bytes = asyncio.run(server.handle_request(wire, ("127.0.0.1", 12345)))
        msg = decode(resp_bytes)
        assert msg.header.rcode == 2


class TestNxdomain:
    """rcode=3: NXDOMAIN 透传。"""

    def _cached_server(self, domain: str, qtype: int, response: DnsMessage) -> DnsServer:
        server = DnsServer(database_path=":memory:")
        server._cache.set_answer(domain, qtype, 1, response)
        return server

    def test_basic(self):
        """标准 NXDOMAIN."""
        r = DnsMessage.create_response(
            DnsMessage.create_query("nx.example", "A"), rcode=3, authorities=[],
        )
        server = self._cached_server("nx.example", 1, r)
        msg = _handle(server, "nx.example", "A")
        assert msg.header.rcode == 3

    def test_with_soa(self):
        """NXDOMAIN + SOA authority."""
        soa = DnsResourceRecord(
            name="example.com", rr_type=6, type_str="SOA",
            rr_class=1, class_str="IN", ttl=3600,
            rdata={
                "mname": "ns1.example.com", "rname": "admin.example.com",
                "serial": 2026070901, "refresh": 3600, "retry": 900,
                "expire": 1209600, "minimum": 86400,
            },
        )
        r = DnsMessage.create_response(
            DnsMessage.create_query("nx.example", "A"), rcode=3, authorities=[soa],
        )
        server = self._cached_server("nx.example", 1, r)
        msg = _handle(server, "nx.example", "A")
        assert msg.header.rcode == 3

    def test_with_multiple_auth(self):
        """NXDOMAIN + 多条 authority."""
        r = DnsMessage.create_response(
            DnsMessage.create_query("nx.example", "A"), rcode=3,
            authorities=[
                DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
                DnsResourceRecord.create_ns("example.com", "ns2.example.com"),
            ],
        )
        server = self._cached_server("nx.example", 1, r)
        msg = _handle(server, "nx.example", "A")
        assert msg.header.rcode == 3


class TestExceptionEcho:
    """异常时回显原始 data。"""

    def _echo(self, data: bytes) -> bytes:
        import asyncio
        server = DnsServer(database_path=":memory:")
        return asyncio.run(server.handle_request(data, ("127.0.0.1", 12345)))

    def test_too_short(self):
        """1 字节 → decode 失败 → echo."""
        assert self._echo(b"\x00") == b"\x00"

    def test_empty(self):
        """空数据 → decode 失败 → echo."""
        assert self._echo(b"") == b""

    def test_truncated_question(self):
        """header 正常但 question 截断 → decode 越界 → echo."""
        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        assert self._echo(hdr) == hdr


# ════════════════════════════════════════════════════════════════
# DnsServer 集成 — 生命周期与三层管线
# ════════════════════════════════════════════════════════════════


class TestServerIntegration:
    """DnsServer 集成测试：生命周期 + 三层管线优先级。"""

    def test_async_context_manager(self):
        """async with 生命周期：start → stop 正常完成。"""
        import asyncio

        async def _lifecycle():
            server = DnsServer(
                host="127.0.0.1", port=0,
                database_path=":memory:",
            )
            async with server:
                assert server._running is True
                assert server._sock is not None
                assert server._sock.fileno() > 0
            # 退出上下文后应已关闭
            assert server._running is False
            assert server._sock is None

        asyncio.run(_lifecycle())

    def test_cache_priority_over_db(self, sample_a_query):
        """
        三层管线优先级验证：Cache > Database > Engine。
        
        Cache 和 Database 中都有同一域名的缓存条目但 IP 不同，
        验证 handle_request 返回的是缓存中的结果。
        """
        import asyncio

        async def _test():
            server = DnsServer(database_path=":memory:")

            # Cache: 写入 IP_A
            cache_a = DnsMessage.create_response(
                sample_a_query,
                answers=[DnsResourceRecord.create_a(
                    "www.example.com", "1.1.1.1", ttl=300,
                )],
            )
            server._cache.set_answer("www.example.com", 1, 1, cache_a)

            # Database: 写入不同的 IP_B
            db_b = DnsMessage.create_response(
                sample_a_query,
                answers=[DnsResourceRecord.create_a(
                    "www.example.com", "2.2.2.2", ttl=300,
                )],
            )
            server._database.set_answer("www.example.com", 1, 1, db_b)

            # 走 handle_request
            wire = DnsMessage.create_query("www.example.com", "A").to_bytes()
            resp_bytes = await server.handle_request(
                wire, ("127.0.0.1", 12345),
            )
            msg = decode(resp_bytes)

            # 应返回缓存中的 IP_A（1.1.1.1），而非数据库中的 2.2.2.2
            assert msg.header.rcode == 0
            assert len(msg.answers) == 1
            assert msg.answers[0].rdata == "1.1.1.1"

        asyncio.run(_test())

    def test_query_with_unknown_qtype_defaults_to_a(self):
        """
        未注册的 qtype 字符串 → 默认降级为 A 记录查询，
        handle_request 不应崩溃。
        """
        import asyncio

        async def _test():
            server = DnsServer(database_path=":memory:")

            # 预填缓存以快速命中
            query = DnsMessage.create_query("unknown.example", "A")
            response = DnsMessage.create_response(
                query,
                answers=[DnsResourceRecord.create_a(
                    "unknown.example", "10.0.0.1", ttl=300,
                )],
            )
            server._cache.set_answer("unknown.example", 1, 1, response)

            # 用非法 qtype 字符串构造查询（走 QTYPE_MAP fallback）
            wire = DnsMessage.create_query("unknown.example", "UNKNOWN").to_bytes()
            resp_bytes = await server.handle_request(
                wire, ("127.0.0.1", 12345),
            )
            msg = decode(resp_bytes)

            # 应正常返回（降级为 A 查询）
            assert msg.header.rcode == 0

        asyncio.run(_test())
