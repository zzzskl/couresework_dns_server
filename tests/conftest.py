"""
共享 fixtures：MockTransport + 预置 DNS 响应。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from dns_transport import DnsMessage, QueryFrame, Transport, TransportError
from dns_types import DnsHeader, DnsResourceRecord


# ══════════════════════════════════════════════════════════════
# MockTransport
# ══════════════════════════════════════════════════════════════

class MockTransport(Transport):
    """可编程 Mock — 按预设顺序返回响应或抛出异常。"""

    def __init__(self):
        self._responses: list[DnsMessage | TransportError] = []
        self.call_history: list[QueryFrame] = []

    def add_response(self, response: DnsMessage) -> None:
        self._responses.append(response)

    def add_error(self, error: TransportError) -> None:
        self._responses.append(error)

    async def query(self, frame: QueryFrame) -> DnsMessage:
        self.call_history.append(frame)
        if not self._responses:
            raise TransportError("MockTransport 预设响应已耗尽")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


# ══════════════════════════════════════════════════════════════
# 消息构建辅助
# ══════════════════════════════════════════════════════════════

def _msg(answers=None, authorities=None, additionals=None, rcode=0) -> DnsMessage:
    """快速构造测试用 DnsMessage。"""
    return DnsMessage(
        header=DnsHeader(rcode=rcode),
        questions=[],
        answers=answers or [],
        authorities=authorities or [],
        additionals=additionals or [],
    )


# ══════════════════════════════════════════════════════════════
# fixtures
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_transport() -> MockTransport:
    return MockTransport()


@pytest.fixture
def sample_a() -> DnsMessage:
    return _msg(answers=[DnsResourceRecord.create_a("www.baidu.com", "93.184.216.34")])


@pytest.fixture
def sample_cname() -> DnsMessage:
    return _msg(answers=[DnsResourceRecord.create_cname("www.baidu.com", "target.baidu.com")])


@pytest.fixture
def sample_ns_glue() -> DnsMessage:
    return _msg(
        authorities=[DnsResourceRecord.create_ns("baidu.com", "ns1.baidu.com")],
        additionals=[DnsResourceRecord.create_a("ns1.baidu.com", "1.2.3.4")],
    )


@pytest.fixture
def sample_ns_no_glue() -> DnsMessage:
    return _msg(
        authorities=[DnsResourceRecord.create_ns("baidu.com", "ns1.baidu.com")],
    )
