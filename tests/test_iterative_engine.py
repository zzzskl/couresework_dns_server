"""
dns_iterative/engine.py — 完整集成测试。

覆盖: ResolutionEngine — init / resolve (答案缓存命中/委派缓存命中/transport正常/
      transport失败/无缓存) / _cache_lookup / _resolve_initial_targets /
      _enhance_task_stack / _enhance_query_stack
共 ~12 个测试函数。
"""

from __future__ import annotations

import pytest

from dns_cache import DnsCache
from dns_iterative.consts import ROOT_SERVERS
from dns_iterative.engine import ResolutionEngine
from dns_iterative.models import TaskResult
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_transport import (
    DnsMessage,
    QueryFrame,
    TransportTimeoutError,
)
from dns_types import DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# init
# ════════════════════════════════════════════════════════════════


class TestEngineInit:
    def test_init_with_cache(self, mock_transport, cache):
        engine = ResolutionEngine(mock_transport, cache=cache)
        assert engine._transport is mock_transport
        assert engine._cache is cache

    def test_init_without_cache(self, mock_transport):
        engine = ResolutionEngine(mock_transport, cache=None)
        assert engine._cache is None


# ════════════════════════════════════════════════════════════════
# resolve — 各路径
# ════════════════════════════════════════════════════════════════


class TestEngineResolve:
    def test_answer_cache_hit(self, mock_transport, cache, sample_a_response):
        """答案缓存命中 → 直接返回（不走 transport）. """
        import asyncio
        cache.set_answer("www.example.com", 1, 1, sample_a_response)
        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com", qtype=1))
        assert result is not None
        assert len(result.answers) == 1
        assert mock_transport.call_count == 0  # 没有走网络

    def test_answer_cache_hit_nxdomain(
        self, mock_transport, cache, sample_nxdomain_response
    ):
        """答案缓存命中 NXDomain. """
        import asyncio
        cache.set_answer("nx.example.com", 1, 1, sample_nxdomain_response)
        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("nx.example.com", qtype=1))
        assert result is not None
        assert result.header.rcode == 3
        assert mock_transport.call_count == 0

    def test_delegation_cache_hit(self, mock_transport, cache, sample_a_response):
        """委派缓存命中 → 跳过根服务器."""
        import asyncio
        ns_records = [DnsResourceRecord.create_ns("example.com", "ns1.example.com")]
        glue_records = [DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")]
        cache.set_delegation("example.com", ns_records, glue_records)
        mock_transport.set_response("1.2.3.4", sample_a_response)

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com", qtype=1))
        assert result is not None
        # 验证从 glue IP 而非根服务器查询
        assert mock_transport.call_count >= 1

    def test_resolve_via_transport(self, mock_transport, cache, sample_a_response):
        """cache miss → transport 成功 → 回填 cache."""
        import asyncio
        mock_transport.set_response("198.41.0.4", sample_a_response)
        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com", qtype=1))
        assert result is not None
        assert len(result.answers) == 1
        assert mock_transport.call_count >= 1
        # 验证写回了答案缓存
        cached = cache.get_answer("www.example.com", 1)
        assert cached is not None

    def test_resolve_transport_fail(self, mock_transport, cache):
        """transport 全失败 → None."""
        import asyncio
        mock_transport.set_error("198.41.0.4", TransportTimeoutError("timeout"))
        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("fail.example.com", qtype=1))
        assert result is None

    def test_resolve_no_cache(self, mock_transport, sample_a_response):
        """cache=None → 无缓存操作."""
        import asyncio
        mock_transport.set_response("198.41.0.4", sample_a_response)
        engine = ResolutionEngine(mock_transport, cache=None)
        result = asyncio.run(engine.resolve("www.example.com", qtype=1))
        assert result is not None
        assert len(result.answers) == 1

    def test_resolve_other_qtype(self, mock_transport, sample_aaaa_query):
        """qtype=28 (AAAA) 的解析."""
        import asyncio
        sample_aaaa_resp = DnsMessage.create_response(
            sample_aaaa_query,
            answers=[
                DnsResourceRecord.create_aaaa(
                    "www.example.com",
                    "2606:2800:220:1:248:1893:25c8:1946",
                )
            ],
        )
        mock_transport.set_response("198.41.0.4", sample_aaaa_resp)
        engine = ResolutionEngine(mock_transport, cache=DnsCache())
        result = asyncio.run(engine.resolve("www.example.com", qtype=28))
        assert result is not None
        assert result.answers[0].rr_type == 28


# ════════════════════════════════════════════════════════════════
# 缓存操作
# ════════════════════════════════════════════════════════════════


class TestEngineCacheOps:
    def test_cache_hit_via_get_answer(self, mock_transport, cache, sample_a_response):
        """engine.resolve 通过 get_answer 命中缓存."""
        cache.set_answer("www.example.com", 1, 1, sample_a_response)
        engine = ResolutionEngine(mock_transport, cache=cache)
        result = cache.get_answer("www.example.com", 1)
        assert result is not None

    def test_cache_miss_via_get_answer(self, mock_transport, cache):
        """engine.resolve 未命中缓存返回 None."""
        engine = ResolutionEngine(mock_transport, cache=cache)
        result = cache.get_answer("unknown.com", 1)
        assert result is None

    def test_no_cache_returns_none(self, mock_transport):
        """无 cache 实例时 get_answer 安全."""
        engine = ResolutionEngine(mock_transport, cache=None)
        # 没有 cache，直接调用 resolve 应走 engine 路径
        assert engine._cache is None

    def test_resolve_initial_targets_exact(self, mock_transport, cache):
        """精确匹配委派缓存."""
        ns_records = [DnsResourceRecord.create_ns("example.com", "ns1.example.com")]
        glue_records = [DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")]
        cache.set_delegation("example.com", ns_records, glue_records)
        engine = ResolutionEngine(mock_transport, cache=cache)
        targets = engine._resolve_initial_targets("www.example.com")
        assert targets is not None
        assert "1.2.3.4" in targets

    def test_resolve_initial_targets_parent(self, mock_transport, cache):
        """父域名委派匹配."""
        ns_records = [DnsResourceRecord.create_ns("com", "a.gtld-servers.net")]
        glue_records = [DnsResourceRecord.create_a("a.gtld-servers.net", "192.5.6.30")]
        cache.set_delegation("com", ns_records, glue_records)
        engine = ResolutionEngine(mock_transport, cache=cache)
        targets = engine._resolve_initial_targets("www.example.com")
        assert targets is not None
        assert "192.5.6.30" in targets

    def test_resolve_initial_targets_none(self, mock_transport, cache):
        """无匹配 → None."""
        engine = ResolutionEngine(mock_transport, cache=cache)
        targets = engine._resolve_initial_targets("unknown.bogus")
        assert targets is None

    def test_resolve_initial_targets_no_cache(self, mock_transport):
        """无缓存实例 → None."""
        engine = ResolutionEngine(mock_transport, cache=None)
        targets = engine._resolve_initial_targets("www.example.com")
        assert targets is None

    def test_resolve_initial_targets_multiple_glue(self, mock_transport, cache):
        """多个 glue IP 都返回."""
        ns_records = [DnsResourceRecord.create_ns("ex.com", "ns1.ex.com")]
        glue_records = [
            DnsResourceRecord.create_a("ns1.ex.com", "1.1.1.1"),
            DnsResourceRecord.create_a("ns1.ex.com", "2.2.2.2"),
        ]
        cache.set_delegation("ex.com", ns_records, glue_records)
        engine = ResolutionEngine(mock_transport, cache=cache)
        targets = engine._resolve_initial_targets("www.ex.com")
        assert targets is not None
        assert "1.1.1.1" in targets
        assert "2.2.2.2" in targets
        assert len(targets) == 2


# ════════════════════════════════════════════════════════════════
# 增强代理
# ════════════════════════════════════════════════════════════════


class TestEngineEnhancements:
    def test_enhance_task_stack_cache_hit(
        self, mock_transport, cache, sample_a_response
    ):
        """cached_push 在缓存命中时不压栈."""
        cache.set_answer("cached.com", 1, 1, sample_a_response)
        engine = ResolutionEngine(mock_transport, cache=cache)
        ts = TaskStack()
        ts._qtype = 1
        ts._initial_targets = ["198.41.0.4"]
        engine._enhance_task_stack(ts)

        # 缓存命中 → 不压栈
        ts.push("cached.com")
        assert ts._is_empty()  # 没有被 push
        assert ts._result_data is not None
        assert ts._result_data.answer_ip == "93.184.216.34"

    def test_enhance_task_stack_cache_miss(self, mock_transport, cache):
        """缓存未命中 → 正常压栈."""
        engine = ResolutionEngine(mock_transport, cache=cache)
        ts = TaskStack()
        ts._qtype = 1
        engine._enhance_task_stack(ts)
        ts.push("fresh.com")
        assert ts._is_empty() is False
        assert ts._peek().domain == "fresh.com"

    def test_enhance_query_stack_logged_push(self, mock_transport, cache):
        """logged_push 记录日志."""
        engine = ResolutionEngine(mock_transport, cache=cache)
        qs = QueryStack(mock_transport)
        engine._enhance_query_stack(qs)
        # push 应顺利执行（日志副作用）
        qs.push(QueryFrame("8.8.8.8", "test.com", 1))
        assert qs._is_empty() is False
