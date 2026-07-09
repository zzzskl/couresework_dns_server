"""
dns_orchestrator.py — 完整集成测试。

覆盖: DnsOrchestrator — init / properties / resolve (三步管线: Step1缓存,
      Step2数据库, Step3引擎成功/失败)
共 ~7 个测试函数。
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_orchestrator import DnsOrchestrator
from dns_types import DnsMessage, DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# 初始化 + 属性
# ════════════════════════════════════════════════════════════════


class TestOrchestratorInit:
    def test_init(self, cache, db, engine):
        orch = DnsOrchestrator(cache, db, engine)
        assert orch._cache is cache
        assert orch._database is db
        assert orch._engine is engine

    def test_properties(self, cache, db, engine):
        orch = DnsOrchestrator(cache, db, engine)
        assert orch.cache is cache
        assert orch.database is db
        assert orch.engine is engine


# ════════════════════════════════════════════════════════════════
# resolve — 三步管线
# ════════════════════════════════════════════════════════════════


class TestOrchestratorResolve:
    """使用真实的 DnsCache + DnsDatabase(":memory:") + 使用 mock_transport 的 engine."""

    def test_step1_cache_hit(self, orchestrator, sample_a_response):
        """第①步缓存命中 → 直接返回, 不查 DB/Engine."""
        import asyncio
        orchestrator.cache.set_answer(
            "www.example.com", 1, 1, sample_a_response,
        )
        result = asyncio.run(orchestrator.resolve("www.example.com", 1))
        assert result is not None
        assert len(result.answers) == 1
        assert result.answers[0].rdata == "93.184.216.34"

    def test_step2_db_hit(self, orchestrator, sample_a_response, mock_transport):
        """第①步 cache miss → 第②步 db hit → 返回 + 回填 cache."""
        import asyncio
        orchestrator.database.set_answer(
            "dbhit.example.com", 1, 1, sample_a_response,
        )
        # 确保 cache 为空
        assert orchestrator.cache.get_answer("dbhit.example.com", 1) is None

        result = asyncio.run(orchestrator.resolve("dbhit.example.com", 1))
        assert result is not None
        assert len(result.answers) == 1

        # 验证回填到 cache
        cached = orchestrator.cache.get_answer("dbhit.example.com", 1)
        assert cached is not None

        # 验证 engine 未被调用（没有 responses 注册也不会报错）
        assert mock_transport.call_count == 0

    def test_step3_engine_success(
        self, orchestrator, mock_transport, sample_a_response,
    ):
        """第①步 cache miss, 第②步 db miss → 第③步 engine 成功 → 返回 + 回填 db/cache."""
        import asyncio
        mock_transport.set_response("198.41.0.4", sample_a_response)
        result = asyncio.run(orchestrator.resolve("www.example.com", 1))
        assert result is not None
        assert len(result.answers) == 1
        assert mock_transport.call_count >= 1

        # 验证回填到 database
        db_result = orchestrator.database.get_answer("www.example.com", 1)
        assert db_result is not None

        # 验证回填到 cache (engine 内部写 cache)
        cached = orchestrator.cache.get_answer("www.example.com", 1)
        assert cached is not None

    def test_step3_engine_failure(
        self, orchestrator, mock_transport,
    ):
        """第③步 engine 失败 → 返回 None."""
        import asyncio
        # 不注册任何响应，所有目标超时
        result = asyncio.run(orchestrator.resolve("fail.example.com", 1))
        assert result is None

    def test_qtype_28(self, orchestrator, mock_transport, sample_aaaa_query):
        """qtype=28 的三步解析."""
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
        result = asyncio.run(orchestrator.resolve("www.example.com", 28))
        assert result is not None
        assert result.answers[0].rr_type == 28

    def test_empty_domain(self, orchestrator):
        """空域名 → 内部抛出 ValueError (QueryFrame 验证)."""
        import asyncio
        try:
            result = asyncio.run(orchestrator.resolve("", 1))
            # 如果未抛异常，结果应为 None
            assert result is None
        except ValueError as e:
            # QueryFrame 验证空域名
            assert "domain" in str(e).lower() or "为空" in str(e)
