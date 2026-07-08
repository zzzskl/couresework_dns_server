"""
DNS 缓存层单元测试。

测试范围:
  1. CacheEntry：基本属性、to_message、from_message
  2. DnsCache：get/set/delete、TTL 过期、负缓存、key 精确匹配
  3. DelegationCache：set/get_delegation、extract_ns_delegations
  4. ResolutionEngine 缓存集成：MockTransport 模拟首次 miss + 二次 hit
  5. CacheCallback：CNAME 短路、PAUSED 短路
  6. 并发安全
"""

from __future__ import annotations

import asyncio
import time

import pytest

from dns_cache import (
    CacheEntry,
    DnsCache,
    extract_ns_delegations,
    min_ttl_from_message,
)
from dns_iterative.engine import ResolutionEngine
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_transport import DnsMessage, QueryFrame, TransportError
from dns_types import DnsResourceRecord
from testutils import MockTransport, make_dns_message


# ══════════════════════════════════════════════════════════════
# CacheEntry 测试
# ══════════════════════════════════════════════════════════════


class TestCacheEntry:
    """CacheEntry 数据类行为。"""

    def test_basic_properties(self):
        """基本属性：domain、qtype、qclass。"""
        entry = CacheEntry("www.example.com", 1, 1, expires_at=9999999999.0)
        assert entry.domain == "www.example.com"
        assert entry.qtype == 1
        assert entry.qclass == 1
        assert not entry.is_negative

    def test_is_expired_true(self):
        """过期时间已到 → is_expired 为 True。"""
        entry = CacheEntry("x", 1, 1, expires_at=0.0)
        assert entry.is_expired

    def test_is_expired_false(self):
        """过期时间未到 → is_expired 为 False。"""
        entry = CacheEntry("x", 1, 1, expires_at=time.time() + 3600)
        assert not entry.is_expired

    def test_ttl_remaining(self):
        """ttl_remaining 返回剩余秒数（不精确但应为正数）。"""
        entry = CacheEntry("x", 1, 1, expires_at=time.time() + 300)
        remaining = entry.ttl_remaining
        assert 299 <= remaining <= 301

    def test_ttl_remaining_expired(self):
        """已过期 → ttl_remaining 为 0。"""
        entry = CacheEntry("x", 1, 1, expires_at=time.time() - 10)
        assert entry.ttl_remaining == 0.0

    def test_to_message_without_query(self):
        """to_message() 不传 query → 构造最小响应。"""
        entry = CacheEntry(
            "www.example.com", 1, 1,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            rcode=0,
            expires_at=9999999999.0,
        )
        msg = entry.to_message()
        assert msg.header.qr == 1
        assert msg.header.rcode == 0
        assert len(msg.answers) == 1
        assert msg.answers[0].rdata == "1.2.3.4"

    def test_to_message_with_query(self):
        """to_message(query_msg) → 复制查询的 id 和 questions。"""
        query = DnsMessage.create_query("www.example.com", "A")
        query.header.id = 0xABCD
        entry = CacheEntry(
            "www.example.com", 1, 1,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            rcode=0,
            expires_at=9999999999.0,
        )
        msg = entry.to_message(query)
        assert msg.header.id == 0xABCD
        assert len(msg.questions) == 1
        assert msg.questions[0].qname == "www.example.com"
        assert msg.header.qr == 1

    def test_from_message(self):
        """from_message 从 DnsMessage 正确提取数据。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300)],
        )
        entry = CacheEntry.from_message(resp)
        assert entry.domain == "www.example.com"
        assert entry.qtype == 1
        assert entry.qclass == 1
        assert len(entry.answers) == 1
        assert entry.answers[0].rdata == "1.2.3.4"
        assert not entry.is_negative
        # TTL 应为最小 TTL（300）
        assert entry.expires_at > time.time() + 299

    def test_from_message_negative(self):
        """from_message 支持负缓存标记。"""
        query = DnsMessage.create_query("nonexist.example.com", "A")
        resp = DnsMessage.create_response(query, rcode=3)  # NXDOMAIN
        entry = CacheEntry.from_message(resp, ttl=60, is_negative=True)
        assert entry.is_negative
        assert entry.rcode == 3

    def test_from_message_custom_ttl(self):
        """from_message 可指定自定义 TTL。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300)],
        )
        entry = CacheEntry.from_message(resp, ttl=10)
        remaining = entry.expires_at - time.time()
        assert 9 <= remaining <= 11  # 指定 TTL=10


# ══════════════════════════════════════════════════════════════
# DnsCache 测试
# ══════════════════════════════════════════════════════════════


class TestDnsCache:
    """DnsCache 容器行为。"""

    @pytest.fixture
    def cache(self):
        return DnsCache()

    @pytest.fixture
    def sample_msg(self):
        query = DnsMessage.create_query("www.example.com", "A")
        return DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300)],
        )

    def test_get_miss(self, cache):
        """不存在的 key → 返回 None。"""
        result = asyncio.run(cache.get("www.example.com", 1))
        assert result is None

    def test_set_and_get(self, cache, sample_msg):
        """set 后 get 应返回相同的条目。"""
        asyncio.run(cache.set_answer("www.example.com", 1, 1, sample_msg))
        entry = asyncio.run(cache.get("www.example.com", 1))
        assert entry is not None
        assert len(entry.answers) == 1
        assert entry.answers[0].rdata == "1.2.3.4"

    def test_get_answer(self, cache, sample_msg):
        """get_answer 返回重建的 DnsMessage。"""
        asyncio.run(cache.set_answer("www.example.com", 1, 1, sample_msg))
        msg = asyncio.run(cache.get_answer("www.example.com", 1))
        assert msg is not None
        assert len(msg.answers) == 1
        assert msg.answers[0].rdata == "1.2.3.4"

    def test_delete(self, cache, sample_msg):
        """delete 移除条目。"""
        asyncio.run(cache.set_answer("www.example.com", 1, 1, sample_msg))
        assert cache.size == 1
        deleted = asyncio.run(cache.delete("www.example.com", 1))
        assert deleted
        assert cache.size == 0
        result = asyncio.run(cache.get("www.example.com", 1))
        assert result is None

    def test_delete_miss(self, cache):
        """delete 不存在的 key → 返回 False。"""
        deleted = asyncio.run(cache.delete("nonexist", 1))
        assert not deleted

    def test_key_precision(self, cache):
        """不同 qtype 的 key 互不干扰。"""
        query_a = DnsMessage.create_query("www.example.com", "A")
        resp_a = DnsMessage.create_response(
            query_a,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300)],
        )
        query_aaaa = DnsMessage.create_query("www.example.com", "AAAA")
        resp_aaaa = DnsMessage.create_response(
            query_aaaa,
            answers=[DnsResourceRecord.create_aaaa("www.example.com", "::1", ttl=300)],
        )
        asyncio.run(cache.set_answer("www.example.com", 1, 1, resp_a))
        asyncio.run(cache.set_answer("www.example.com", 28, 1, resp_aaaa))

        entry_a = asyncio.run(cache.get("www.example.com", 1))
        entry_aaaa = asyncio.run(cache.get("www.example.com", 28))

        assert entry_a is not None
        assert entry_a.answers[0].rdata == "1.2.3.4"
        assert entry_aaaa is not None
        assert entry_aaaa.answers[0].rdata == "::1"

    def test_set_overwrites(self, cache, sample_msg):
        """set 相同 key 覆盖旧值。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp2 = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_a("www.example.com", "5.6.7.8", ttl=300)],
        )
        asyncio.run(cache.set_answer("www.example.com", 1, 1, sample_msg))
        asyncio.run(cache.set_answer("www.example.com", 1, 1, resp2))
        entry = asyncio.run(cache.get("www.example.com", 1))
        assert entry is not None
        assert entry.answers[0].rdata == "5.6.7.8"

    def test_expired_auto_removed(self, cache):
        """过期的条目在 get 时自动删除（懒清理）。"""
        entry = CacheEntry(
            "expired.example.com", 1, 1,
            expires_at=time.time() - 1,  # 已过期
        )
        asyncio.run(cache.set("expired.example.com", 1, 1, entry))
        assert cache.size == 1  # 过期但尚未清理

        result = asyncio.run(cache.get("expired.example.com", 1))
        assert result is None
        assert cache.size == 0  # 懒清理后自动删除

    def test_clear_expired(self, cache):
        """clear_expired 清理所有过期条目。"""
        fresh = CacheEntry("fresh.example.com", 1, 1, expires_at=time.time() + 3600)
        stale = CacheEntry("stale.example.com", 1, 1, expires_at=time.time() - 1)
        asyncio.run(cache.set("fresh.example.com", 1, 1, fresh))
        asyncio.run(cache.set("stale.example.com", 1, 1, stale))
        assert cache.size == 2

        n = asyncio.run(cache.clear_expired())
        assert n == 1
        assert cache.size == 1

    def test_clear_all(self, cache, sample_msg):
        """clear 清空所有条目。"""
        asyncio.run(cache.set_answer("www.example.com", 1, 1, sample_msg))
        asyncio.run(cache.clear())
        assert cache.size == 0

    def test_negative_cache_flag(self, cache):
        """负缓存条目 is_negative=True。"""
        query = DnsMessage.create_query("nonexist.example.com", "A")
        resp = DnsMessage.create_response(query, rcode=3)
        asyncio.run(cache.set_answer("nonexist.example.com", 1, 1, resp,
                                     is_negative=True))
        entry = asyncio.run(cache.get("nonexist.example.com", 1))
        assert entry is not None
        assert entry.is_negative
        assert entry.rcode == 3


# ══════════════════════════════════════════════════════════════
# DelegationCache 测试
# ══════════════════════════════════════════════════════════════


class TestDelegationCache:
    """委派缓存行为。"""

    @pytest.fixture
    def cache(self):
        return DnsCache()

    def test_set_and_get_delegation(self, cache):
        """set_delegation → get_delegation 返回 (ns, glue)。"""
        ns = [DnsResourceRecord.create_ns("example.com", "ns1.example.com")]
        glue = [DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")]
        asyncio.run(cache.set_delegation("example.com", ns, glue, ttl=3600))

        result = asyncio.run(cache.get_delegation("example.com"))
        assert result is not None
        ns_back, glue_back = result
        assert len(ns_back) == 1
        assert ns_back[0].rdata == "ns1.example.com"
        assert len(glue_back) == 1
        assert glue_back[0].rdata == "1.2.3.4"

    def test_get_delegation_miss(self, cache):
        """不存在的委派 → 返回 None。"""
        result = asyncio.run(cache.get_delegation("nonexist.com"))
        assert result is None

    def test_extract_ns_delegations(self):
        """从 DnsMessage 提取 NS+glue。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp = DnsMessage.create_response(
            query,
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
            additionals=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
        )
        delegations = extract_ns_delegations(resp)
        assert "example.com" in delegations
        ns, glue = delegations["example.com"]
        assert len(ns) == 1
        assert ns[0].rdata == "ns1.example.com"
        assert len(glue) == 1
        assert glue[0].rdata == "1.2.3.4"

    def test_extract_ns_delegations_no_ns(self):
        """无 NS 记录 → 返回空字典。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
        )
        delegations = extract_ns_delegations(resp)
        assert delegations == {}

    def test_extract_ns_delegations_no_glue(self):
        """有 NS 但无匹配 glue → glue 为空列表。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp = DnsMessage.create_response(
            query,
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        )
        delegations = extract_ns_delegations(resp)
        assert "example.com" in delegations
        ns, glue = delegations["example.com"]
        assert len(ns) == 1
        assert len(glue) == 0


# ══════════════════════════════════════════════════════════════
# ResolutionEngine 缓存集成测试
# ══════════════════════════════════════════════════════════════


class TestResolutionEngineWithCache:
    """ResolutionEngine 接入缓存后的行为。"""

    def test_resolve_without_cache(self, mock_transport, sample_a_response):
        """不传 cache → 行为与之前一致（未缓存）。"""
        mock_transport.add_response(sample_a_response)
        engine = ResolutionEngine(mock_transport)
        result = asyncio.run(engine.resolve("www.example.com"))
        assert result is sample_a_response
        assert len(mock_transport.call_history) == 1

    def test_resolve_cache_hit(self, mock_transport, sample_a_response):
        """第二次查询同一域名 → 命中 Answer Cache，不触发 transport。"""
        cache = DnsCache()
        # 手动预热缓存
        query = DnsMessage.create_query("www.example.com", "A")
        asyncio.run(cache.set_answer(
            "www.example.com", 1, 1, sample_a_response,
        ))

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com"))

        assert result is not None
        assert len(result.answers) == 1
        # transport 未被调用
        assert len(mock_transport.call_history) == 0

    def test_resolve_miss_then_hit(self, mock_transport):
        """第一次 miss → 解析并写入缓存 → 第二次命中。"""
        cache = DnsCache()
        a_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
        )
        mock_transport.add_response(a_resp)

        engine = ResolutionEngine(mock_transport, cache=cache)

        # 第一次：miss 触发真实解析
        result1 = asyncio.run(engine.resolve("www.example.com"))
        assert result1 is not None
        assert result1.answers[0].rdata == "1.2.3.4"
        assert len(mock_transport.call_history) == 1

        # 第二次：命中缓存，不触发 transport
        result2 = asyncio.run(engine.resolve("www.example.com"))
        assert result2 is not None
        assert result2.answers[0].rdata == "1.2.3.4"
        assert len(mock_transport.call_history) == 1  # 仍是 1 次

    def test_resolve_different_qtype_no_interference(self, mock_transport):
        """不同 qtype 的缓存互不干扰。"""
        cache = DnsCache()
        a_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
        )
        aaaa_resp = make_dns_message(
            answers=[DnsResourceRecord.create_aaaa("www.example.com", "::1")],
        )
        mock_transport.add_response(a_resp)
        mock_transport.add_response(aaaa_resp)

        engine = ResolutionEngine(mock_transport, cache=cache)

        # 第一次查 A
        result_a = asyncio.run(engine.resolve("www.example.com", qtype=1))
        assert result_a.answers[0].rdata == "1.2.3.4"
        assert len(mock_transport.call_history) == 1

        # 第一次查 AAAA（不同 qtype，应 miss）
        result_aaaa = asyncio.run(engine.resolve("www.example.com", qtype=28))
        assert result_aaaa.answers[0].rdata == "::1"
        assert len(mock_transport.call_history) == 2

        # 第二次查 A（缓存命中）
        result_a2 = asyncio.run(engine.resolve("www.example.com", qtype=1))
        assert result_a2.answers[0].rdata == "1.2.3.4"
        assert len(mock_transport.call_history) == 2  # 未增加

    def test_resolve_no_response_no_cache_write(self, mock_transport):
        """解析失败（None）→ 不写缓存，第二次仍走 transport。"""
        from dns_iterative.consts import ROOT_SERVERS
        cache = DnsCache()
        # 全部根服务器都返回失败
        for _ in ROOT_SERVERS:
            mock_transport.add_error(TransportError("超时"))

        engine = ResolutionEngine(mock_transport, cache=cache)

        result1 = asyncio.run(engine.resolve("www.example.com"))
        assert result1 is None
        first_call_count = len(mock_transport.call_history)

        # 第二次：因为第一次没写缓存，所以再次触发 transport
        for _ in ROOT_SERVERS:
            mock_transport.add_error(TransportError("超时"))
        result2 = asyncio.run(engine.resolve("www.example.com"))
        assert result2 is None
        # 第二次调用的查询次数与第一次相同
        assert len(mock_transport.call_history) == first_call_count * 2


# ══════════════════════════════════════════════════════════════
# CacheCallback 集成测试
# ══════════════════════════════════════════════════════════════


class TestCacheCallback:
    """TaskStack 的 cache_callback：CNAME 和 PAUSED 短路。"""

    def test_cname_cache_hit_skips_subtask(self, mock_transport):
        """
        CNAME 目标域名在缓存中 → 跳过子任务压栈，
        直接使用缓存结果作为最终答案。
        """
        cache = DnsCache()
        # 预热缓存：target.example.com 的 A 记录
        target_a = make_dns_message(
            answers=[DnsResourceRecord.create_a("target.example.com", "5.6.7.8")],
        )
        asyncio.run(cache.set_answer("target.example.com", 1, 1, target_a))

        # 第一次查询 www.example.com 返回 CNAME → target.example.com
        cname_resp = make_dns_message(
            answers=[DnsResourceRecord.create_cname("www.example.com", "target.example.com")],
        )
        mock_transport.add_response(cname_resp)

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com", qtype=1))

        assert result is not None
        # 验证结果是缓存中的 target A 记录
        assert len(result.answers) == 1
        assert result.answers[0].rdata == "5.6.7.8"
        # 只发了一次查询（CNAME 前缀），没有发第二次（CNAME 目标）
        assert len(mock_transport.call_history) == 1
        assert mock_transport.call_history[0].domain == "www.example.com"

    def test_cname_cache_miss_normal_path(self, mock_transport):
        """CNAME 目标未缓存 → 正常压子任务解析（原有逻辑不变）。"""
        cache = DnsCache()
        # 不预热 cache

        cname_resp = make_dns_message(
            answers=[DnsResourceRecord.create_cname("www.example.com", "target.example.com")],
        )
        a_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("target.example.com", "5.6.7.8")],
        )
        mock_transport.add_response(cname_resp)
        mock_transport.add_response(a_resp)

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com"))

        assert result is not None
        assert result.answers[0].rdata == "5.6.7.8"
        assert len(mock_transport.call_history) == 2

    def test_paused_cache_hit_skips_subtask(self, mock_transport):
        """
        PAUSED（NS 无胶水）→ NS 域名 IP 在缓存中 →
        跳过子任务解析，直接使用缓存 IP 恢复查询。
        """
        cache = DnsCache()
        # 预热缓存：ns1.example.com 的 A 记录
        ns_a = make_dns_message(
            answers=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
        )
        asyncio.run(cache.set_answer("ns1.example.com", 1, 1, ns_a))

        # 第一次查询：NS 无胶水
        ns_no_glue = make_dns_message(
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        )
        # 第二次查询（用缓存 IP 恢复）：返回最终答案
        final_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "93.184.216.34")],
        )
        mock_transport.add_response(ns_no_glue)
        mock_transport.add_response(final_resp)

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com"))

        assert result is not None
        assert result.answers[0].rdata == "93.184.216.34"
        # 只发了 2 次查询（NS 无胶水 + 用缓存 IP 恢复）
        # 没有第 3 次查询（NS 域名解析被缓存短路了）
        assert len(mock_transport.call_history) == 2
        # 第二次查询的目标 IP 是缓存的 IP
        assert mock_transport.call_history[1].target_ip == "1.2.3.4"

    def test_paused_cache_miss_normal_path(self, mock_transport):
        """PAUSED 未缓存 → 正常压子任务解析 NS IP。"""
        cache = DnsCache()
        # 不预热 cache

        ns_no_glue = make_dns_message(
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        )
        ns_ip = make_dns_message(
            answers=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
        )
        final = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "93.184.216.34")],
        )
        mock_transport.add_response(ns_no_glue)
        mock_transport.add_response(ns_ip)
        mock_transport.add_response(final)

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com"))

        assert result is not None
        assert result.answers[0].rdata == "93.184.216.34"
        assert len(mock_transport.call_history) == 3

    def test_cache_callback_not_called_without_cache(self, mock_transport):
        """不传 cache → cache_callback 为 None → callback 不会被调用。"""
        engine = ResolutionEngine(mock_transport, cache=None)
        # 验证 _check_cache 在缓存为 None 时返回 None
        result = asyncio.run(engine._check_cache("www.example.com", 1))
        assert result is None


# ══════════════════════════════════════════════════════════════
# 工具函数测试
# ══════════════════════════════════════════════════════════════


class TestMinTTL:
    """min_ttl_from_message 工具函数。"""

    def test_min_ttl_from_answers(self):
        """从 answers 取最小 TTL。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp = DnsMessage.create_response(query, answers=[
            DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300),
            DnsResourceRecord.create_a("www.example.com", "5.6.7.8", ttl=600),
        ])
        assert min_ttl_from_message(resp) == 300

    def test_min_ttl_from_all_sections(self):
        """从 answers + authorities + additionals 取最小 TTL。"""
        query = DnsMessage.create_query("www.example.com", "A")
        resp = DnsMessage.create_response(query, answers=[
            DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300),
        ], authorities=[
            DnsResourceRecord.create_ns("example.com", "ns1.example.com", ttl=60),
        ])
        assert min_ttl_from_message(resp) == 60

    def test_min_ttl_empty(self):
        """空消息 → 返回默认值 60。"""
        msg = make_dns_message()
        assert min_ttl_from_message(msg) == 60


# ══════════════════════════════════════════════════════════════
# 并发安全测试
# ══════════════════════════════════════════════════════════════


class TestConcurrency:
    """DnsCache 并发安全。"""

    def test_concurrent_set_and_get(self):
        """并发 set/get 不崩溃。"""
        cache = DnsCache()

        async def worker(domain: str, ip: str):
            query = DnsMessage.create_query(domain, "A")
            resp = DnsMessage.create_response(
                query,
                answers=[DnsResourceRecord.create_a(domain, ip, ttl=300)],
            )
            for _ in range(20):
                await cache.set_answer(domain, 1, 1, resp)
                got = await cache.get_answer(domain, 1)
                assert got is not None

        async def run():
            tasks = [
                worker("a.example.com", "1.1.1.1"),
                worker("b.example.com", "2.2.2.2"),
                worker("c.example.com", "3.3.3.3"),
            ]
            await asyncio.gather(*tasks)

        asyncio.run(run())
        assert cache.size == 3


# ══════════════════════════════════════════════════════════════
# Delegation Cache ➔ 初始目标加速测试
# ══════════════════════════════════════════════════════════════


class TestDelegationInitialTargets:
    """委派缓存加速初始目标。"""

    def test_delegation_cache_initial_targets(self, mock_transport):
        """
        Delegation Cache 有缓存 NS 时，engine 将其作为
        QueryStack 的初始目标，跳过根服务器。
        """
        cache = DnsCache()
        # 预热委派缓存：example.com → ns1.example.com (1.2.3.4)
        asyncio.run(cache.set_delegation(
            "example.com",
            ns_records=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
            glue_records=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
            ttl=3600,
        ))

        # 查询 www.example.com 的 A 记录
        # 第一次 transport 调用应直接到 ns1.example.com(1.2.3.4)，而非根服务器
        a_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "93.184.216.34")],
        )
        mock_transport.add_response(a_resp)

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.example.com"))

        assert result is not None
        assert result.answers[0].rdata == "93.184.216.34"
        # 只发了 1 次查询，且目标 IP 是 glue IP 而非根服务器
        assert len(mock_transport.call_history) == 1
        assert mock_transport.call_history[0].target_ip == "1.2.3.4"

    def test_delegation_cache_not_affects_other_domains(self, mock_transport):
        """
        委派缓存仅影响匹配的域名及其子域。
        不匹配的域名仍从根服务器开始。
        """
        cache = DnsCache()
        # 预热委派缓存：example.com
        asyncio.run(cache.set_delegation(
            "example.com",
            ns_records=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
            glue_records=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
            ttl=3600,
        ))

        # 查询 other.com → 不从委派缓存读，仍用根服务器
        a_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.other.com", "9.9.9.9")],
        )
        mock_transport.add_response(a_resp)

        engine = ResolutionEngine(mock_transport, cache=cache)
        result = asyncio.run(engine.resolve("www.other.com"))

        assert result is not None
        assert result.answers[0].rdata == "9.9.9.9"
        # 目标 IP 不是 glue IP（用的是根服务器列表的第一个）
        assert mock_transport.call_history[0].target_ip != "1.2.3.4"
