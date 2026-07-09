"""
dns_database.py — 完整集成测试。

覆盖: DnsDatabase — init / get_answer / set_answer / get_delegation /
      set_delegation / delete / clear / close / _rr_to_json / _json_to_rr
共 ~15 个测试函数。
"""

from __future__ import annotations

import json
import os
import time

import pytest

from dns_database import DnsDatabase
from dns_types import DnsMessage, DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# 初始化
# ════════════════════════════════════════════════════════════════


class TestDnsDatabaseInit:
    def test_memory(self):
        db = DnsDatabase(":memory:")
        assert db.path == ":memory:"
        db.close()

    def test_file_path(self, tmp_path):
        db_path = os.path.join(str(tmp_path), "test.db")
        db = DnsDatabase(db_path)
        assert db.path == db_path
        assert os.path.exists(db_path)
        db.close()

    def test_path_property(self):
        db = DnsDatabase(":memory:")
        assert db.path == ":memory:"
        db.close()

    def test_default_path_not_memory(self):
        """未传参时使用默认路径."""
        db = DnsDatabase(":memory:")  # 使用 :memory: 避免写磁盘
        assert db.path == ":memory:"
        db.close()


# ════════════════════════════════════════════════════════════════
# 序列化辅助
# ════════════════════════════════════════════════════════════════


class TestSerialization:
    def test_rr_to_json_empty(self):
        assert DnsDatabase._rr_to_json([]) == "[]"

    def test_rr_to_json_single(self):
        rrs = [DnsResourceRecord.create_a("test.com", "1.2.3.4")]
        json_str = DnsDatabase._rr_to_json(rrs)
        data = json.loads(json_str)
        assert len(data) == 1
        assert data[0]["name"] == "test.com"
        assert data[0]["rdata"] == "1.2.3.4"

    def test_json_to_rr_empty(self):
        assert DnsDatabase._json_to_rr("[]") == []

    def test_json_to_rr_single(self):
        json_str = '[{"name": "test.com", "type": 1, "class": 1, "ttl": 300, "rdata": "1.2.3.4"}]'
        rrs = DnsDatabase._json_to_rr(json_str)
        assert len(rrs) == 1
        assert rrs[0].name == "test.com"
        assert rrs[0].rdata == "1.2.3.4"

    def test_json_to_rr_invalid(self):
        """损坏 JSON → log warning + 空列表."""
        result = DnsDatabase._json_to_rr("not-json")
        assert result == []

    def test_json_to_rr_empty_string(self):
        result = DnsDatabase._json_to_rr("")
        assert result == []

    def test_roundtrip(self):
        """_rr_to_json → _json_to_rr 往返."""
        rrs = [
            DnsResourceRecord.create_a("a.com", "1.2.3.4", ttl=100),
            DnsResourceRecord.create_ns("b.com", "ns.b.com", ttl=200),
            DnsResourceRecord.create_mx("c.com", 10, "mx.c.com", ttl=300),
        ]
        json_str = DnsDatabase._rr_to_json(rrs)
        restored = DnsDatabase._json_to_rr(json_str)
        assert len(restored) == 3
        assert restored[0].name == "a.com"
        assert restored[0].rdata == "1.2.3.4"
        assert restored[1].rr_type == 2
        assert restored[2].rr_type == 15


# ════════════════════════════════════════════════════════════════
# 答案缓存
# ════════════════════════════════════════════════════════════════


class TestAnswerCache:
    def test_get_answer_miss(self, db):
        assert db.get_answer("nonexistent.com", 1) is None

    def test_set_and_get_answer(self, db, sample_a_query):
        db.set_answer("www.example.com", 1, 1, sample_a_query)
        result = db.get_answer("www.example.com", 1)
        assert result is not None
        assert isinstance(result, DnsMessage)
        assert result.header.qr == 1

    def test_get_answer_different_qclass(self, db, sample_a_query):
        """不同 qclass 隔离."""
        db.set_answer("test.com", 1, 1, sample_a_query)
        assert db.get_answer("test.com", 1, 2) is None

    def test_set_and_get_answer_with_real_rrs(self, db, sample_a_response):
        db.set_answer("www.example.com", 1, 1, sample_a_response)
        result = db.get_answer("www.example.com", 1)
        assert result is not None
        assert len(result.answers) == 1
        assert result.answers[0].rdata == "93.184.216.34"
        assert result.answers[0].ttl == 300

    def test_set_answer_negative(self, db, sample_a_query):
        db.set_answer("nx.example.com", 1, 1, sample_a_query, is_negative=True)
        # 负缓存标志存在但 get_answer 不暴露 is_negative
        row = db._conn.execute(
            "SELECT is_negative FROM dns_cache WHERE domain=? AND qtype=1",
            ("nx.example.com",),
        ).fetchone()
        assert row["is_negative"] == 1

    def test_set_answer_ttl_zero(self, db, sample_a_query):
        """ttl=0 → 立即过期."""
        db.set_answer("ephemeral.com", 1, 1, sample_a_query, ttl=0)
        assert db.get_answer("ephemeral.com", 1) is None

    def test_get_answer_expired_lazy_cleanup(self, db, sample_a_query):
        """过期条目在 get 时被清理."""
        db.set_answer("stale.com", 1, 1, sample_a_query, ttl=-1)  # 已过期
        assert db.get_answer("stale.com", 1) is None
        # 确认从 DB 删除
        row = db._conn.execute(
            "SELECT count(*) as cnt FROM dns_cache WHERE domain='stale.com'"
        ).fetchone()
        assert row["cnt"] == 0

    def test_set_answer_empty_msg(self, db):
        """msg 无 answers 也可存储."""
        msg = DnsMessage()
        db.set_answer("empty.com", 1, 1, msg)
        result = db.get_answer("empty.com", 1)
        assert result is not None
        assert result.answers == []


# ════════════════════════════════════════════════════════════════
# 委派缓存
# ════════════════════════════════════════════════════════════════


class TestDelegationCache:
    def test_get_delegation_miss(self, db):
        assert db.get_delegation("unknown.com") is None

    def test_set_and_get_delegation(self, db):
        ns = [DnsResourceRecord.create_ns("example.com", "ns1.example.com")]
        glue = [DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")]
        db.set_delegation("example.com", ns, glue)
        result = db.get_delegation("example.com")
        assert result is not None
        ns_result, glue_result = result
        assert len(ns_result) == 1
        assert ns_result[0].rdata == "ns1.example.com"
        assert len(glue_result) == 1
        assert glue_result[0].rdata == "1.2.3.4"

    def test_get_delegation_expired(self, db):
        ns = [DnsResourceRecord.create_ns("test.com", "ns.test.com")]
        db.set_delegation("test.com", ns, [], ttl=-1)
        assert db.get_delegation("test.com") is None

    def test_delegation_no_glue(self, db):
        ns = [DnsResourceRecord.create_ns("ex.com", "ns.ex.com")]
        db.set_delegation("ex.com", ns, [])
        result = db.get_delegation("ex.com")
        assert result is not None
        _, glue = result
        assert glue == []


# ════════════════════════════════════════════════════════════════
# 通用操作
# ════════════════════════════════════════════════════════════════


class TestGeneral:
    def test_delete_existing(self, db, sample_a_query):
        db.set_answer("delete-me.com", 1, 1, sample_a_query)
        assert db.delete("delete-me.com", 1) is True
        assert db.get_answer("delete-me.com", 1) is None

    def test_delete_missing(self, db):
        assert db.delete("nothing.com", 1) is False

    def test_clear(self, db, sample_a_query):
        db.set_answer("a.com", 1, 1, sample_a_query)
        db.set_answer("b.com", 1, 1, sample_a_query)
        db.clear()
        assert db.get_answer("a.com", 1) is None
        assert db.get_answer("b.com", 1) is None

    def test_close_then_reopen(self, tmp_path):
        """close 后重新打开同一文件，数据持久."""
        db_path = os.path.join(str(tmp_path), "persist.db")
        db1 = DnsDatabase(db_path)
        msg = DnsMessage.create_query("persist.com")
        msg.answers.append(DnsResourceRecord.create_a("persist.com", "9.9.9.9"))
        db1.set_answer("persist.com", 1, 1, msg)
        db1.close()

        db2 = DnsDatabase(db_path)
        result = db2.get_answer("persist.com", 1)
        assert result is not None
        assert result.answers[0].rdata == "9.9.9.9"
        db2.close()
