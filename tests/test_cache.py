"""
dns_cache.py — 完整集成测试。

覆盖: CacheEntry (is_expired, ttl_remaining, to_message, from_message) +
      DnsCache (get/set/delete/clear/clear_expired/size + get_answer/set_answer +
      get_delegation/set_delegation)
共 ~20 个测试函数。
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from dns_cache import CacheEntry, DnsCache
from dns_types import DnsMessage, DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# CacheEntry
# ════════════════════════════════════════════════════════════════


class TestCacheEntry:
    def test_is_expired_true(self):
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1, expires_at=time.time() - 10)
        assert entry.is_expired is True

    def test_is_expired_false(self):
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1, expires_at=time.time() + 3600)
        assert entry.is_expired is False

    def test_ttl_remaining_positive(self):
        future = time.time() + 100
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1, expires_at=future)
        assert 99 < entry.ttl_remaining <= 100

    def test_ttl_remaining_expired(self):
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1, expires_at=time.time() - 10)
        assert entry.ttl_remaining == 0.0

    def test_to_message_with_query(self, sample_a_query):
        entry = CacheEntry(
            domain="www.example.com",
            qtype=1,
            qclass=1,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            rcode=0,
            expires_at=time.time() + 300,
        )
        msg = entry.to_message(query_msg=sample_a_query)
        assert msg.header.qr == 1
        assert msg.header.id == sample_a_query.header.id
        assert msg.questions[0].qname == "www.example.com"
        assert msg.answers[0].rdata == "1.2.3.4"

    def test_to_message_without_query(self):
        entry = CacheEntry(
            domain="www.example.com",
            qtype=1,
            qclass=1,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            rcode=0,
            expires_at=time.time() + 300,
        )
        msg = entry.to_message(query_msg=None)
        assert msg.header.qr == 1
        assert msg.header.rcode == 0
        assert msg.answers[0].rdata == "1.2.3.4"
        assert msg.questions == []  # 无 query 时 questions 为空

    def test_from_message(self, sample_a_response):
        """从 DnsMessage 构建 CacheEntry."""
        entry = CacheEntry.from_message(sample_a_response)
        assert entry.domain == "www.example.com"
        assert entry.qtype == 1
        assert entry.qclass == 1
        assert len(entry.answers) == 1
        assert entry.rcode == 0
        assert entry.is_negative is False
        assert entry.expires_at > time.time()

    def test_from_message_with_params(self, sample_a_response):
        """显式 ttl + is_negative."""
        entry = CacheEntry.from_message(sample_a_response, ttl=60, is_negative=True)
        assert entry.is_negative is True
        # ttl=60 → expires_at = now + 60
        assert time.time() + 55 < entry.expires_at <= time.time() + 60

    def test_from_message_empty_questions(self):
        """msg.questions 为空 → domain/qtype/qclass 使用默认值."""
        msg = DnsMessage(
            answers=[DnsResourceRecord.create_a("test.com", "1.2.3.4")]
        )
        entry = CacheEntry.from_message(msg)
        assert entry.domain == ""  # questions 为空 → 空
        assert entry.qtype == 1
        assert len(entry.answers) == 1

    def test_from_message_empty_rrs(self):
        """无 RR → ttl 默认 60."""
        msg = DnsMessage()
        entry = CacheEntry.from_message(msg)
        assert entry.expires_at <= time.time() + 60


# ════════════════════════════════════════════════════════════════
# DnsCache
# ════════════════════════════════════════════════════════════════


class TestDnsCache:
    def test_init(self):
        cache = DnsCache()
        assert cache.size == 0

    def test_get_miss(self):
        cache = DnsCache()
        assert cache.get("nonexistent.com", 1) is None

    def test_get_hit(self):
        cache = DnsCache()
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1,
                           expires_at=time.time() + 3600)
        cache.set("test.com", 1, 1, entry)
        result = cache.get("test.com", 1)
        assert result is not None
        assert result.domain == "test.com"

    def test_get_expired(self):
        cache = DnsCache()
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1,
                           expires_at=time.time() - 10)
        cache.set("test.com", 1, 1, entry)
        assert cache.get("test.com", 1) is None
        assert cache.size == 0  # 自动删除

    def test_get_with_different_qclass(self):
        """不同 qclass 隔离."""
        cache = DnsCache()
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1,
                           expires_at=time.time() + 3600)
        cache.set("test.com", 1, 1, entry)
        assert cache.get("test.com", 1, 2) is None  # qclass=2 不同

    def test_set_overwrite(self):
        cache = DnsCache()
        e1 = CacheEntry(domain="test.com", qtype=1, qclass=1,
                        expires_at=time.time() + 3600)
        e2 = CacheEntry(domain="test.com", qtype=1, qclass=1,
                        expires_at=time.time() + 7200)
        cache.set("test.com", 1, 1, e1)
        cache.set("test.com", 1, 1, e2)
        assert cache.size == 1
        result = cache.get("test.com", 1)
        assert result.expires_at == e2.expires_at

    def test_delete_exist(self):
        cache = DnsCache()
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1,
                           expires_at=time.time() + 3600)
        cache.set("test.com", 1, 1, entry)
        assert cache.delete("test.com", 1) is True
        assert cache.size == 0

    def test_delete_missing(self):
        cache = DnsCache()
        assert cache.delete("nonexistent.com", 1) is False

    def test_clear_expired(self):
        cache = DnsCache()
        cache.set("fresh.com", 1, 1,
                  CacheEntry(domain="fresh", qtype=1, qclass=1,
                             expires_at=time.time() + 3600))
        cache.set("stale.com", 1, 1,
                  CacheEntry(domain="stale", qtype=1, qclass=1,
                             expires_at=time.time() - 10))
        assert cache.clear_expired() == 1
        assert cache.get("stale.com", 1) is None
        assert cache.get("fresh.com", 1) is not None

    def test_clear(self):
        cache = DnsCache()
        entry = CacheEntry(domain="test.com", qtype=1, qclass=1,
                           expires_at=time.time() + 3600)
        cache.set("test.com", 1, 1, entry)
        cache.clear()
        assert cache.size == 0

    def test_size_with_expired(self):
        """size 包含已过期条目（未清理前）. """
        cache = DnsCache()
        cache.set("stale.com", 1, 1,
                  CacheEntry(domain="stale", qtype=1, qclass=1,
                             expires_at=time.time() - 10))
        assert cache.size == 1  # 仍计数
        cache.clear_expired()
        assert cache.size == 0

    # ── 便捷方法 ─────────────────────────────────────────

    def test_get_answer_hit(self, sample_a_query):
        cache = DnsCache()
        cache.set_answer("www.example.com", 1, 1, sample_a_query)
        result = cache.get_answer("www.example.com", 1)
        assert result is not None
        assert isinstance(result, DnsMessage)

    def test_get_answer_miss(self):
        cache = DnsCache()
        assert cache.get_answer("nonexistent.com", 1) is None

    def test_set_answer_negative(self, sample_a_query):
        cache = DnsCache()
        cache.set_answer("nx.example.com", 1, 1, sample_a_query,
                         is_negative=True, ttl=60)
        entry = cache.get("nx.example.com", 1)
        assert entry is not None
        assert entry.is_negative is True

    def test_set_answer_ttl_zero(self, sample_a_query):
        """ttl=0 → 立即过期."""
        cache = DnsCache()
        cache.set_answer("ephemeral.com", 1, 1, sample_a_query, ttl=0)
        assert cache.get_answer("ephemeral.com", 1) is None  # 过期

    def test_set_answer_default_ttl(self, sample_a_response):
        """ttl=None → 使用 msg 最小 TTL."""
        cache = DnsCache()
        cache.set_answer("www.example.com", 1, 1, sample_a_response, ttl=None)
        entry = cache.get("www.example.com", 1)
        assert entry is not None
        # sample_a_response 中 ttl=300
        assert time.time() + 290 < entry.expires_at <= time.time() + 300

    def test_get_delegation_hit(self):
        cache = DnsCache()
        ns_records = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com")
        ]
        glue_records = [
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")
        ]
        cache.set_delegation("example.com", ns_records, glue_records)
        result = cache.get_delegation("example.com")
        assert result is not None
        ns, glue = result
        assert len(ns) == 1
        assert len(glue) == 1
        assert glue[0].rdata == "1.2.3.4"

    def test_get_delegation_miss(self):
        cache = DnsCache()
        assert cache.get_delegation("unknown.com") is None

    def test_get_delegation_expired(self):
        cache = DnsCache()
        ns_records = [DnsResourceRecord.create_ns("test.com", "ns1.test.com")]
        cache.set_delegation("test.com", ns_records, [], ttl=-1)  # 立即过期
        assert cache.get_delegation("test.com") is None

    def test_set_delegation_default_ttl(self, sample_a_query):
        """set_delegation 默认 ttl=3600."""
        cache = DnsCache()
        ns_records = [DnsResourceRecord.create_ns("ex.com", "ns1.ex.com")]
        cache.set_delegation("ex.com", ns_records, [])
        entry = cache.get("ex.com", 2)
        assert entry is not None
        assert time.time() + 3590 < entry.expires_at <= time.time() + 3600
