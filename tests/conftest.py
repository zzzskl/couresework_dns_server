"""
测试共享 Fixtures：复用 testutils 中的工具构建预置响应。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# 将 tests 目录加入 sys.path（使 testutils 可导入）
_TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))

from testutils import (
    DnsMessage,
    DnsResourceRecord,
    MockTransport,
    make_dns_message,
)


@pytest.fixture
def mock_transport() -> MockTransport:
    """提供一个干净的 MockTransport 实例。"""
    return MockTransport()


@pytest.fixture
def sample_a_response() -> DnsMessage:
    """一个简单的 A 记录响应。"""
    return make_dns_message(
        answers=[DnsResourceRecord.create_a("www.baidu.com", "93.184.216.34")],
    )


@pytest.fixture
def sample_cname_response() -> DnsMessage:
    """一个 CNAME 响应。"""
    return make_dns_message(
        answers=[DnsResourceRecord.create_cname("www.baidu.com", "target.baidu.com")],
    )


@pytest.fixture
def sample_ns_glue_response() -> DnsMessage:
    """一个 NS + 胶水响应（权威段有 NS，附加段有对应的 A 胶水）。"""
    return make_dns_message(
        authorities=[DnsResourceRecord.create_ns("baidu.com", "ns1.baidu.com")],
        additionals=[DnsResourceRecord.create_a("ns1.baidu.com", "1.2.3.4")],
    )


@pytest.fixture
def sample_ns_no_glue_response() -> DnsMessage:
    """一个 NS 无胶水响应（权威段有 NS，附加段无匹配 A 记录）。"""
    return make_dns_message(
        authorities=[DnsResourceRecord.create_ns("baidu.com", "ns1.baidu.com")],
    )


@pytest.fixture
def sample_empty_response() -> DnsMessage:
    """一个空响应（无答案、无权威、无附加）。"""
    return make_dns_message()
