"""
Transport 模块测试：

  1. QueryFrame 输入验证（空 target_ip、空 domain、qtype 越界）
  2. Transport ABC 接口符合性
  3. MockTransport 的基本行为
"""

from __future__ import annotations

import asyncio

import pytest

from dns_transport import (
    QueryFrame,
    Transport,
    TransportError,
    TransportTimeoutError,
)
from testutils import MockTransport


# ══════════════════════════════════════════════════════════════
# QueryFrame 验证
# ══════════════════════════════════════════════════════════════


class TestQueryFrame:
    """QueryFrame 输入验证。"""

    def test_valid_frame(self):
        """正常参数应成功创建。"""
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)
        assert frame.target_ip == "8.8.8.8"
        assert frame.domain == "www.example.com"
        assert frame.qtype == 1

    def test_empty_target_ip(self):
        """target_ip 为空应抛 ValueError。"""
        with pytest.raises(ValueError, match="target_ip 不能为空"):
            QueryFrame("", "www.example.com", 1)

    def test_empty_domain(self):
        """domain 为空应抛 ValueError。"""
        with pytest.raises(ValueError, match="domain 不能为空"):
            QueryFrame("8.8.8.8", "", 1)

    def test_qtype_negative(self):
        """qtype 为负值应抛 ValueError。"""
        with pytest.raises(ValueError, match="qtype 超出有效范围"):
            QueryFrame("8.8.8.8", "www.example.com", -1)

    def test_qtype_too_large(self):
        """qtype 超过 65535 应抛 ValueError。"""
        with pytest.raises(ValueError, match="qtype 超出有效范围"):
            QueryFrame("8.8.8.8", "www.example.com", 99999)

    def test_qtype_zero(self):
        """qtype=0 是合法的（SIGWIN 保留类型），应能创建。"""
        frame = QueryFrame("8.8.8.8", "www.example.com", 0)
        assert frame.qtype == 0

    def test_qtype_max_valid(self):
        """qtype=65535 是边界合法值，应能创建。"""
        frame = QueryFrame("8.8.8.8", "www.example.com", 65535)
        assert frame.qtype == 65535

    def test_frame_immutable(self):
        """QueryFrame 是 frozen dataclass，应不可变。"""
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)
        with pytest.raises(AttributeError):
            frame.target_ip = "1.1.1.1"


# ══════════════════════════════════════════════════════════════
# Transport ABC 接口符合性
# ══════════════════════════════════════════════════════════════


class TestTransportABC:
    """Transport 抽象基类接口校验。"""

    def test_transport_is_abc(self):
        """Transport 应有 abstractmethod。"""
        assert Transport.query.__isabstractmethod__

    def test_transport_cannot_instantiate(self):
        """Transport 不能直接实例化。"""
        with pytest.raises(TypeError):
            Transport()  # type: ignore[abstract]

    def test_mock_transport_is_concrete(self):
        """MockTransport 应可实例化且实现 query。"""
        t = MockTransport()
        assert isinstance(t, Transport)


# ══════════════════════════════════════════════════════════════
# MockTransport 行为
# ══════════════════════════════════════════════════════════════


class TestMockTransport:
    """MockTransport 的预设响应与异常行为。"""

    def test_return_preset_response(self, mock_transport, sample_a_response):
        """预设一个响应应能正确返回。"""
        mock_transport.add_response(sample_a_response)
        result = asyncio.run(mock_transport.query(
            QueryFrame("8.8.8.8", "www.example.com", 1)
        ))
        assert result is sample_a_response

    def test_record_call_history(self, mock_transport, sample_a_response):
        """query 调用应记录到 call_history。"""
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)
        mock_transport.add_response(sample_a_response)
        asyncio.run(mock_transport.query(frame))
        assert len(mock_transport.call_history) == 1
        assert mock_transport.call_history[0] is frame

    def test_preset_error(self, mock_transport):
        """预设异常应正确抛出。"""
        error = TransportTimeoutError("模拟超时")
        mock_transport.add_error(error)
        with pytest.raises(TransportTimeoutError, match="模拟超时"):
            asyncio.run(mock_transport.query(
                QueryFrame("8.8.8.8", "www.example.com", 1)
            ))

    def test_exhausted_responses(self, mock_transport):
        """耗尽预设响应后应抛 TransportError。"""
        with pytest.raises(TransportError, match="预设响应已耗尽"):
            asyncio.run(mock_transport.query(
                QueryFrame("8.8.8.8", "www.example.com", 1)
            ))
