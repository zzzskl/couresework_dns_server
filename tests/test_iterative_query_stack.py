"""
dns_iterative/query_stack.py — 完整集成测试。

覆盖: QueryStack — init / push / run (正常答案, NS+胶水自旋, 超时重试, 全失败) /
      consume_result / _switch_target / _has_ns_glue / _build_glue_frame
共 ~12 个测试函数。
"""

from __future__ import annotations

import pytest

from dns_iterative.query_stack import QueryStack
from dns_iterative.models import QueryStatus
from dns_transport import (
    DnsMessage,
    QueryFrame,
    TransportTimeoutError,
)
from dns_types import DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# QueryStack 外部接口
# ════════════════════════════════════════════════════════════════


class TestQueryStackBasic:
    def test_init(self, mock_transport):
        qs = QueryStack(mock_transport)
        assert qs.get_status() == QueryStatus.FINISHED
        assert qs._is_empty() is True
        assert qs.consume_result() is None

    def test_push_basic(self, mock_transport):
        qs = QueryStack(mock_transport)
        frame = QueryFrame("198.41.0.4", "www.example.com", 1)
        qs.push(frame)
        assert qs.get_status() == QueryStatus.READY
        assert qs._is_empty() is False

    def test_push_with_targets(self, mock_transport):
        qs = QueryStack(mock_transport)
        frame = QueryFrame("1.1.1.1", "test.com", 1)
        qs.push(frame, targets=["1.1.1.1", "2.2.2.2"])
        assert qs._targets == ["1.1.1.1", "2.2.2.2"]
        assert qs._target_idx == 0

    def test_push_overwrites_old(self, mock_transport):
        """第二次 push 替换旧帧."""
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("1.1.1.1", "old.com", 1))
        qs.push(QueryFrame("2.2.2.2", "new.com", 1))
        assert qs._peek().domain == "new.com"
        assert qs._peek().target_ip == "2.2.2.2"

    def test_consume_result(self, mock_transport):
        qs = QueryStack(mock_transport)
        assert qs.consume_result() is None


# ════════════════════════════════════════════════════════════════
# QueryStack.run() — 各路径
# ════════════════════════════════════════════════════════════════


class TestQueryStackRun:
    def test_run_basic_answer(self, mock_transport, sample_a_response):
        """transport 返回 A 响应 → FINISHED + result."""
        import asyncio
        mock_transport.set_response("198.41.0.4", sample_a_response)
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("198.41.0.4", "www.example.com", 1))
        asyncio.run(qs.run())
        assert qs.get_status() == QueryStatus.FINISHED
        result = qs.consume_result()
        assert result is not None
        assert result.response is not None
        assert len(result.response.answers) == 1

    def test_run_ns_glue_spin(self, mock_transport, sample_ns_delegation, sample_a_response):
        """
        NS+胶水自旋：
        第1次 query → NS+glue 响应 → 自旋
        第2次 query → A 响应 → FINISHED
        """
        import asyncio
        mock_transport.set_response("198.41.0.4", sample_ns_delegation)
        # 第二次查询会使用 glue IP: 1.2.3.4
        mock_transport.set_response("1.2.3.4", sample_a_response)

        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("198.41.0.4", "www.example.com", 1))
        asyncio.run(qs.run())
        assert qs.get_status() == QueryStatus.FINISHED
        result = qs.consume_result()
        assert result is not None
        assert result.response is not None
        # 验证发生了 2 次 transport query
        assert mock_transport.call_count == 2
        assert mock_transport.last_frame.target_ip == "1.2.3.4"

    def test_run_all_targets_fail(self, mock_transport):
        """所有目标失败 → error result."""
        import asyncio
        mock_transport.set_error("198.41.0.4", TransportTimeoutError("timeout"))
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("198.41.0.4", "www.example.com", 1))
        asyncio.run(qs.run())
        assert qs.get_status() == QueryStatus.FINISHED
        result = qs.consume_result()
        assert result is not None
        assert result.error is not None
        assert "所有目标服务器均无响应" in result.error

    def test_run_some_targets_fail(self, mock_transport, sample_a_response):
        """前一个目标失败 → 切换到下一个 → 成功."""
        import asyncio
        mock_transport.set_error("1.1.1.1", TransportTimeoutError("timeout"))
        mock_transport.set_response("2.2.2.2", sample_a_response)
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("1.1.1.1", "test.com", 1),
                targets=["1.1.1.1", "2.2.2.2"])
        asyncio.run(qs.run())
        assert qs.get_status() == QueryStatus.FINISHED
        result = qs.consume_result()
        assert result is not None
        assert result.response is not None
        assert mock_transport.call_count == 2


# ════════════════════════════════════════════════════════════════
# 内部方法
# ════════════════════════════════════════════════════════════════


class TestQueryStackInternal:
    def test_switch_target_success(self, mock_transport):
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("1.1.1.1", "test.com", 1),
                targets=["1.1.1.1", "2.2.2.2"])
        assert qs._switch_target() is True
        assert qs._peek().target_ip == "2.2.2.2"

    def test_switch_target_exhausted(self, mock_transport):
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("1.1.1.1", "test.com", 1),
                targets=["1.1.1.1"])
        assert qs._switch_target() is False  # 只有一个目标

    def test_has_ns_glue_true(self, sample_ns_delegation):
        """有 NS + 匹配 glue → True."""
        # sample_ns_delegation 中包含 NS+glue
        # 但直接测试需构造 mock_transport + query_stack
        from dns_common import extract_ns_glue_pairs
        glue = extract_ns_glue_pairs(
            sample_ns_delegation.authorities,
            sample_ns_delegation.additionals,
        )
        assert len(glue) > 0

    def test_has_ns_glue_false(self, sample_a_response):
        """无 NS → False."""
        from dns_common import extract_ns_glue_pairs
        glue = extract_ns_glue_pairs(
            sample_a_response.authorities,
            sample_a_response.additionals,
        )
        assert glue == {}

    def test_build_glue_frame(self, mock_transport, sample_ns_delegation):
        """从 NS+glue 响应构建新帧."""
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("198.41.0.4", "www.example.com", 1))
        new_frame = qs._build_glue_frame(sample_ns_delegation)
        assert isinstance(new_frame, QueryFrame)
        # glue IP 来自 additionals: 1.2.3.4
        assert new_frame.target_ip == "1.2.3.4"
        assert new_frame.domain == "www.example.com"

    def test_build_glue_frame_no_match(self, mock_transport, sample_a_response):
        """_has_ns_glue 返回 True 但无匹配 → AssertionError."""
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("1.1.1.1", "test.com", 1))
        # sample_a_response 没有 NS+glue
        with pytest.raises(AssertionError, match="_has_ns_glue 返回 True"):
            qs._build_glue_frame(sample_a_response)

    def test_has_ns_glue_via_query_stack(self, mock_transport, sample_ns_delegation):
        """通过 QueryStack._has_ns_glue 测试."""
        qs = QueryStack(mock_transport)
        assert qs._has_ns_glue(sample_ns_delegation) is True

    def test_has_ns_glue_false_via_query_stack(self, mock_transport, sample_a_response):
        """通过 QueryStack._has_ns_glue 测试 False."""
        qs = QueryStack(mock_transport)
        assert qs._has_ns_glue(sample_a_response) is False
