"""
pytest 共享 fixtures — 集成测试基础设施。

提供:
- MockTransport: 模拟传输层，返回预定义响应
- 样本 DnsMessage fixtures (A/AAAA/CNAME/NS/MX/SOA/NXDOMAIN)
- 样本二进制报文 bytes (用于 decoder/coder 测试)
- DnsCache / DnsDatabase / ResolutionEngine / DnsOrchestrator 实例
"""

from __future__ import annotations

import json
import logging
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

import pytest

from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_decoder import decode
from dns_iterative.engine import ResolutionEngine
from dns_iterative.models import TaskResult
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_orchestrator import DnsOrchestrator
from dns_transport import (
    AsyncUdpTransport,
    DnsMessage,
    QueryFrame,
    Transport,
    TransportError,
    TransportTimeoutError,
)
from dns_types import DnsHeader, DnsQuestion, DnsResourceRecord

# ─────────────────────────────────────────────────────────────
# MockTransport
# ─────────────────────────────────────────────────────────────


class MockTransport(Transport):
    """
    模拟传输层 — 按 target_ip 或 (target_ip, domain) 返回预注册的 DnsMessage。

    用法:
        transport = MockTransport()
        transport.set_response("198.41.0.4", sample_ns_response)
        transport.set_response("1.2.3.4", sample_a_response)
        msg = await transport.query(QueryFrame("198.41.0.4", "www.example.com", 1))
    """

    def __init__(self) -> None:
        self._responses: Dict[str, DnsMessage] = {}
        self._domain_responses: Dict[str, Dict[str, DnsMessage]] = {}
        self._errors: Dict[str, TransportError] = {}
        self._call_log: List[QueryFrame] = []

    def set_response(self, target_ip: str, response: DnsMessage) -> None:
        """注册 target_ip → 响应。"""
        self._responses[target_ip] = response

    def set_domain_response(self, target_ip: str, domain: str, response: DnsMessage) -> None:
        """注册 (target_ip, domain) → 响应（优先级高于 IP 级）。"""
        self._domain_responses.setdefault(target_ip, {})[domain.lower()] = response

    def set_error(self, target_ip: str, error: TransportError) -> None:
        """注册 target_ip → 抛出异常。"""
        self._errors[target_ip] = error

    def set_responses(self, responses: Dict[str, DnsMessage]) -> None:
        """批量注册响应。"""
        self._responses.update(responses)

    def clear(self) -> None:
        self._responses.clear()
        self._domain_responses.clear()
        self._errors.clear()
        self._call_log.clear()

    @property
    def call_count(self) -> int:
        return len(self._call_log)

    @property
    def last_frame(self) -> Optional[QueryFrame]:
        return self._call_log[-1] if self._call_log else None

    async def query(self, frame: QueryFrame) -> DnsMessage:
        self._call_log.append(frame)
        ip = frame.target_ip
        domain = frame.domain.lower()

        # 优先检查 domain 级响应
        if ip in self._domain_responses and domain in self._domain_responses[ip]:
            return self._domain_responses[ip][domain]

        # 优先检查错误
        if ip in self._errors:
            raise self._errors[ip]

        # 检查 IP 级响应
        if ip in self._responses:
            return self._responses[ip]
            return self._responses[ip]

        # 默认：超时
        raise TransportTimeoutError(
            f"MockTransport: no response registered for {ip}"
        )


# ─────────────────────────────────────────────────────────────
# 样本 DnsMessage — 查询
# ─────────────────────────────────────────────────────────────


@pytest.fixture
def sample_a_query() -> DnsMessage:
    return DnsMessage.create_query("www.example.com", "A")


@pytest.fixture
def sample_aaaa_query() -> DnsMessage:
    return DnsMessage.create_query("www.example.com", "AAAA")


@pytest.fixture
def sample_ns_query() -> DnsMessage:
    return DnsMessage.create_query("example.com", "NS")


@pytest.fixture
def sample_mx_query() -> DnsMessage:
    return DnsMessage.create_query("example.com", "MX")


@pytest.fixture
def sample_txt_query() -> DnsMessage:
    return DnsMessage.create_query("example.com", "TXT")


@pytest.fixture
def sample_cname_query() -> DnsMessage:
    return DnsMessage.create_query("alias.example.com", "A")


# ─────────────────────────────────────────────────────────────
# 样本 DnsMessage — 响应
# ─────────────────────────────────────────────────────────────


@pytest.fixture
def sample_a_response(sample_a_query: DnsMessage) -> DnsMessage:
    return DnsMessage.create_response(
        sample_a_query,
        answers=[
            DnsResourceRecord.create_a(
                "www.example.com", "93.184.216.34", ttl=300
            ),
        ],
    )


@pytest.fixture
def sample_aaaa_response(sample_aaaa_query: DnsMessage) -> DnsMessage:
    return DnsMessage.create_response(
        sample_aaaa_query,
        answers=[
            DnsResourceRecord.create_aaaa(
                "www.example.com",
                "2606:2800:220:1:248:1893:25c8:1946",
                ttl=300,
            ),
        ],
    )


@pytest.fixture
def sample_cname_response(sample_cname_query: DnsMessage) -> DnsMessage:
    """CNAME 响应: alias.example.com → www.example.com"""
    return DnsMessage.create_response(
        sample_cname_query,
        answers=[
            DnsResourceRecord.create_cname(
                "alias.example.com", "www.example.com", ttl=300
            ),
        ],
    )


@pytest.fixture
def sample_ns_delegation() -> DnsMessage:
    """NS 委派响应: example.com → ns1.example.com (含 glue A)."""
    query = DnsMessage.create_query("example.com", "NS")
    return DnsMessage.create_response(
        query,
        authorities=[
            DnsResourceRecord.create_ns(
                "example.com", "ns1.example.com", ttl=3600
            ),
        ],
        additionals=[
            DnsResourceRecord.create_a(
                "ns1.example.com", "1.2.3.4", ttl=3600
            ),
        ],
    )


@pytest.fixture
def sample_ns_noglue() -> DnsMessage:
    """NS 响应: 无 glue（触发 referral 路径）. """
    query = DnsMessage.create_query("example.com", "A")
    return DnsMessage.create_response(
        query,
        authorities=[
            DnsResourceRecord.create_ns(
                "example.com", "ns1.example.com", ttl=3600
            ),
        ],
    )


@pytest.fixture
def sample_nxdomain_response(sample_a_query: DnsMessage) -> DnsMessage:
    """NXDOMAIN 响应. """
    return DnsMessage.create_response(
        sample_a_query, rcode=3, authorities=[]
    )


@pytest.fixture
def sample_servfail_response(sample_a_query: DnsMessage) -> DnsMessage:
    """SERVFAIL 响应. """
    return DnsMessage.create_response(
        sample_a_query, rcode=2, authorities=[]
    )


@pytest.fixture
def sample_soa_response(sample_ns_query: DnsMessage) -> DnsMessage:
    """SOA 响应（无 NS 的 authoritative 响应）. """
    return DnsMessage.create_response(
        sample_ns_query,
        authorities=[
            DnsResourceRecord(
                name="example.com",
                rr_type=6,
                type_str="SOA",
                rr_class=1,
                class_str="IN",
                ttl=3600,
                rdata={
                    "mname": "ns1.example.com",
                    "rname": "admin.example.com",
                    "serial": 2026070901,
                    "refresh": 3600,
                    "retry": 900,
                    "expire": 1209600,
                    "minimum": 86400,
                },
            )
        ],
    )


@pytest.fixture
def sample_multi_answer_response(sample_a_query: DnsMessage) -> DnsMessage:
    """多条 A 记录. """
    return DnsMessage.create_response(
        sample_a_query,
        answers=[
            DnsResourceRecord.create_a("www.example.com", "93.184.216.34", ttl=300),
            DnsResourceRecord.create_a("www.example.com", "93.184.216.35", ttl=300),
        ],
    )


# ─────────────────────────────────────────────────────────────
# 样本二进制报文 bytes（用于 decoder/coder 测试）
# ─────────────────────────────────────────────────────────────


@pytest.fixture
def sample_a_wire_bytes() -> bytes:
    """A 查询的二进制报文 (31 bytes, 类似 dns_client.py 输出)."""
    return bytes.fromhex(
        "12 34 01 00 00 01 00 00 00 00 00 00 "
        "03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 "
        "00 01 00 01"
    )


@pytest.fixture
def sample_a_response_wire_bytes() -> bytes:
    """A 响应的二进制报文 (47 bytes, 来自 README 示例)."""
    return bytes.fromhex(
        "12 34 81 80 00 01 00 01 00 00 00 00 "
        "03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01 "
        "c0 0c 00 01 00 01 00 00 00 01 00 04 c6 12 00 9d"
    )


@pytest.fixture
def sample_ns_response_wire_bytes() -> bytes:
    """NS 委派响应的二进制报文（含 glue A）. """
    # Header (12 bytes)
    txid = 0x1234
    flags = 0x8180  # QR=1, RD=1, RA=1, RCODE=0
    qdcount, ancount, nscount, arcount = 1, 0, 1, 1
    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    # Question at offset 12: example.com type=NS class=IN
    # \x07example\x03com\x00 = 14 bytes
    question_domain = b"\x07example\x03com\x00"  # 11 bytes
    question = (
        question_domain  # offset 12-22
        + struct.pack("!HH", 2, 1)  # offset 23-26: type=NS, class=IN
    )
    # question section ends at offset 27

    # Authority: example.com NS ns1.example.com
    # name pointer 0xc00c → offset 12 (start of question domain) = 2 bytes
    # type(2)+class(2)+ttl(4)+rdlen(2) = 10 bytes
    # rdata: \x03ns1\x07example\x03com\x00 = 17 bytes
    # total = 2+10+17 = 29 bytes
    authority = (
        b"\xc0\x0c"  # name pointer to offset 12
        + struct.pack("!HHIH", 2, 1, 3600, 17)  # type=NS, class=IN, TTL=3600, rdlen=17
        + b"\x03ns1\x07example\x03com\x00"  # rdata: ns1.example.com (17 bytes)
    )
    # authority ends at offset 27+29 = 56

    # Additional: ns1.example.com A 1.2.3.4
    # name: \x03ns1 + pointer to offset 12 = 1+3+2 = 6 bytes
    # type(2)+class(2)+ttl(4)+rdlen(2) = 10 bytes
    # rdata: 1.2.3.4 = 4 bytes
    # total = 6+10+4 = 20 bytes
    additional = (
        b"\x03ns1\xc0\x0c"  # name: ns1 + pointer to "example.com" at offset 12
        + struct.pack("!HHIH", 1, 1, 3600, 4)  # type=A, class=IN, TTL=3600, rdlen=4
        + bytes([1, 2, 3, 4])  # 1.2.3.4
    )

    return header + question + authority + additional


@pytest.fixture
def sample_cname_wire_bytes() -> bytes:
    """CNAME 链响应的二进制报文. """
    query = DnsMessage.create_query("alias.example.com", "A")
    response = DnsMessage.create_response(
        query,
        answers=[
            DnsResourceRecord.create_cname(
                "alias.example.com", "www.example.com", ttl=300
            ),
        ],
    )
    return response.to_bytes()


# ─────────────────────────────────────────────────────────────
# 缓存 / 数据库 / 传输 / 引擎 / 编排器 实例
# ─────────────────────────────────────────────────────────────


@pytest.fixture
def cache() -> DnsCache:
    return DnsCache()


@pytest.fixture
def db() -> DnsDatabase:
    return DnsDatabase(":memory:")


@pytest.fixture
def mock_transport() -> MockTransport:
    return MockTransport()


@pytest.fixture
def engine(
    mock_transport: MockTransport, cache: DnsCache
) -> ResolutionEngine:
    return ResolutionEngine(mock_transport, cache=cache)


@pytest.fixture
def engine_no_cache(mock_transport: MockTransport) -> ResolutionEngine:
    return ResolutionEngine(mock_transport, cache=None)


@pytest.fixture
def orchestrator(
    cache: DnsCache, db: DnsDatabase, engine: ResolutionEngine
) -> DnsOrchestrator:
    return DnsOrchestrator(cache, db, engine)


# ─────────────────────────────────────────────────────────────
# MockTransport 预配置助手
# ─────────────────────────────────────────────────────────────


@pytest.fixture
def mock_transport_with_root_a(
    mock_transport: MockTransport,
    sample_a_response: DnsMessage,
) -> MockTransport:
    """根服务器返回 A 响应. """
    mock_transport.set_response("198.41.0.4", sample_a_response)
    return mock_transport


@pytest.fixture
def mock_transport_with_cname_chain(
    mock_transport: MockTransport,
    sample_cname_response: DnsMessage,
    sample_a_response: DnsMessage,
) -> MockTransport:
    """
    模拟 CNAME 链:
      第一次查询 alias.example.com → CNAME 响应 (指向 www.example.com)
      第二次(子任务)查询 www.example.com → A 响应
    """
    mock_transport.set_response("198.41.0.4", sample_cname_response)
    mock_transport.set_response("93.184.216.34", sample_a_response)
    return mock_transport


# ─────────────────────────────────────────────────────────────
# pytest 配置 hooks
# ─────────────────────────────────────────────────────────────


def pytest_configure(config):
    """注册自定义标记。"""
    config.addinivalue_line("markers", "network: tests that require real network access")


# ─────────────────────────────────────────────────────────────
# 真实传输层 fixture（用于集成/网络测试）
# ─────────────────────────────────────────────────────────────


@pytest.fixture
def real_transport() -> AsyncUdpTransport:
    """返回真实的 AsyncUdpTransport 实例（超时 8 秒）。"""
    return AsyncUdpTransport(timeout=8.0)
