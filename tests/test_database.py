"""
DNS 数据库持久化层测试套件。

覆盖范围:
  1. 基本 CRUD — set_answer / get_answer
  2. 过期懒清理 — 过期条目自动忽略并删除
  3. Key 隔离 — 不同 qtype 互不干扰
  4. 委派缓存 — get_delegation / set_delegation
  5. JSON 序列化往返 — RR → JSON → RR
  6. delete / clear 操作
  7. 负缓存 — is_negative 标记
  8. 错误降级 — 数据库操作失败时返回 None 而非抛出异常
  9. 多次读写 — 覆盖模式正确
"""

from __future__ import annotations

import time

import pytest

from dns_database import DnsDatabase
from dns_types import DnsMessage, DnsResourceRecord


@pytest.fixture
def db():
    """每次测试使用独立的内存数据库。"""
    database = DnsDatabase(":memory:")
    yield database
    database.close()


@pytest.fixture
def sample_response() -> DnsMessage:
    """预置的 A 记录响应。"""
    query = DnsMessage.create_query("www.example.com", "A")
    return DnsMessage.create_response(
        query,
        answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300)],
    )


# ══════════════════════════════════════════════════════════════
# 1. 基本 CRUD
# ══════════════════════════════════════════════════════════════


def test_set_and_get_answer(db, sample_response):
    """写入后应能读出相同内容。"""
    db.set_answer("www.example.com", 1, 1, sample_response)
    msg = db.get_answer("www.example.com", 1)
    assert msg is not None
    assert len(msg.answers) == 1
    assert msg.answers[0].rdata == "1.2.3.4"
    assert msg.answers[0].name == "www.example.com"


def test_get_miss_returns_none(db):
    """未写入的域名应返回 None。"""
    assert db.get_answer("nonexistent.com", 1) is None


def test_get_wrong_type_returns_none(db, sample_response):
    """写入 A 记录后查询 AAAA 应返回 None。"""
    db.set_answer("www.example.com", 1, 1, sample_response)
    assert db.get_answer("www.example.com", 28) is None


def test_overwrite_existing(db, sample_response):
    """覆盖写入同一 key 应更新内容。"""
    db.set_answer("www.example.com", 1, 1, sample_response)

    # 写入新值
    query = DnsMessage.create_query("www.example.com", "A")
    new_resp = DnsMessage.create_response(
        query,
        answers=[DnsResourceRecord.create_a("www.example.com", "5.6.7.8", ttl=300)],
    )
    db.set_answer("www.example.com", 1, 1, new_resp)
    msg = db.get_answer("www.example.com", 1)
    assert msg is not None
    assert msg.answers[0].rdata == "5.6.7.8"


# ══════════════════════════════════════════════════════════════
# 2. 过期懒清理
# ══════════════════════════════════════════════════════════════


def test_expired_entry_returns_none(db):
    """已过期的条目应返回 None 且自动删除。"""
    query = DnsMessage.create_query("www.example.com", "A")
    resp = DnsMessage.create_response(
        query,
        answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=0)],
    )
    db.set_answer("www.example.com", 1, 1, resp)
    # ttl=0 意味着 expires_at ≈ time.time()，小睡一毫秒确保过期
    time.sleep(0.01)
    assert db.get_answer("www.example.com", 1) is None


def test_expired_entry_deleted_from_db(db):
    """过期条目在被访问后应从数据库删除。"""
    query = DnsMessage.create_query("www.example.com", "A")
    resp = DnsMessage.create_response(
        query,
        answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=0)],
    )
    db.set_answer("www.example.com", 1, 1, resp)
    time.sleep(0.01)
    db.get_answer("www.example.com", 1)  # 触发懒清理

    # 直接查 SQLite 验证确实删除了
    cursor = db._conn.execute(
        "SELECT COUNT(*) as cnt FROM dns_cache WHERE domain='www.example.com'",
    )
    assert cursor.fetchone()["cnt"] == 0


def test_fresh_entry_not_expired(db, sample_response):
    """未过期的条目应正常返回。"""
    db.set_answer("www.example.com", 1, 1, sample_response)
    assert db.get_answer("www.example.com", 1) is not None


# ══════════════════════════════════════════════════════════════
# 3. Key 隔离
# ══════════════════════════════════════════════════════════════


def test_different_qtype_independent(db):
    """不同 qtype 的缓存互不干扰。"""
    query_a = DnsMessage.create_query("x.com", "A")
    query_aaaa = DnsMessage.create_query("x.com", "AAAA")

    resp_a = DnsMessage.create_response(
        query_a,
        answers=[DnsResourceRecord.create_a("x.com", "1.1.1.1")],
    )
    resp_aaaa = DnsMessage.create_response(
        query_aaaa,
        answers=[DnsResourceRecord.create_aaaa("x.com", "::1")],
    )

    db.set_answer("x.com", 1, 1, resp_a)
    db.set_answer("x.com", 28, 1, resp_aaaa)

    msg_a = db.get_answer("x.com", 1)
    assert msg_a is not None and msg_a.answers[0].rdata == "1.1.1.1"

    msg_aaaa = db.get_answer("x.com", 28)
    assert msg_aaaa is not None and msg_aaaa.answers[0].rdata == "::1"


# ══════════════════════════════════════════════════════════════
# 4. 委派缓存
# ══════════════════════════════════════════════════════════════


def test_delegation_set_and_get(db):
    """set_delegation 后应能通过 get_delegation 读出。"""
    ns = [DnsResourceRecord.create_ns("example.com", "ns1.example.com")]
    glue = [DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")]
    db.set_delegation("example.com", ns, glue)

    result = db.get_delegation("example.com")
    assert result is not None
    ns_records, glue_records = result
    assert ns_records[0].rdata == "ns1.example.com"
    assert glue_records[0].rdata == "1.2.3.4"


def test_delegation_miss_returns_none(db):
    """未写入的委派应返回 None。"""
    assert db.get_delegation("nonexistent.com") is None


def test_delegation_expired(db):
    """过期的委派缓存应返回 None。"""
    ns = [DnsResourceRecord.create_ns("example.com", "ns1.example.com")]
    glue = [DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")]
    db.set_delegation("example.com", ns, glue, ttl=0)
    time.sleep(0.01)
    assert db.get_delegation("example.com") is None


# ══════════════════════════════════════════════════════════════
# 5. JSON 序列化往返
# ══════════════════════════════════════════════════════════════


def test_serialize_multiple_types(db):
    """多种 RR 类型（A, AAAA, CNAME, NS, MX）的序列化往返。"""
    query = DnsMessage.create_query("multi.example.com", "A")
    resp = DnsMessage.create_response(
        query,
        answers=[
            DnsResourceRecord.create_a("multi.example.com", "1.2.3.4"),
            DnsResourceRecord.create_aaaa("multi.example.com", "::1"),
            DnsResourceRecord.create_cname("multi.example.com", "target.example.com"),
        ],
        authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        additionals=[DnsResourceRecord.create_a("ns1.example.com", "10.0.0.1")],
    )
    db.set_answer("multi.example.com", 1, 1, resp)

    msg = db.get_answer("multi.example.com", 1)
    assert msg is not None
    assert len(msg.answers) == 3
    assert msg.answers[0].rdata == "1.2.3.4"
    assert msg.answers[1].rdata == "::1"
    assert msg.answers[2].rdata == "target.example.com"
    assert len(msg.authorities) == 1
    assert msg.authorities[0].rdata == "ns1.example.com"
    assert len(msg.additionals) == 1
    assert msg.additionals[0].rdata == "10.0.0.1"


# ══════════════════════════════════════════════════════════════
# 6. delete / clear
# ══════════════════════════════════════════════════════════════


def test_delete_existing(db, sample_response):
    """删除存在的条目应返回 True 且之后查询为 None。"""
    db.set_answer("www.example.com", 1, 1, sample_response)
    assert db.delete("www.example.com", 1) is True
    assert db.get_answer("www.example.com", 1) is None


def test_delete_nonexistent(db):
    """删除不存在的条目应返回 False。"""
    assert db.delete("nonexistent.com", 1) is False


def test_clear(db, sample_response):
    """clear 后所有条目清空。"""
    db.set_answer("a.com", 1, 1, sample_response)
    db.set_answer("b.com", 1, 1, sample_response)
    db.clear()
    assert db.get_answer("a.com", 1) is None
    assert db.get_answer("b.com", 1) is None


# ══════════════════════════════════════════════════════════════
# 7. 负缓存
# ══════════════════════════════════════════════════════════════


def test_negative_cache(db):
    """负缓存条目（NXDOMAIN）存储和读取。"""
    query = DnsMessage.create_query("nxdomain.example.com", "A")
    resp = DnsMessage.create_response(query, rcode=3)  # NXDOMAIN
    db.set_answer("nxdomain.example.com", 1, 1, resp, is_negative=True)

    msg = db.get_answer("nxdomain.example.com", 1)
    assert msg is not None
    assert msg.header.rcode == 3  # NXDOMAIN
    assert len(msg.answers) == 0


# ══════════════════════════════════════════════════════════════
# 8. 错误降级
# ══════════════════════════════════════════════════════════════


def test_get_answer_after_close_returns_none(db, sample_response):
    """数据库关闭后查询应静默返回 None。"""
    db.set_answer("www.example.com", 1, 1, sample_response)
    db.close()
    # 不应抛异常
    msg = db.get_answer("www.example.com", 1)
    assert msg is None


def test_set_answer_after_close_no_crash(db, sample_response):
    """数据库关闭后写入应静默忽略。"""
    db.close()
    # 不应抛异常
    db.set_answer("www.example.com", 1, 1, sample_response)
    # 验证写入未生效
    assert db.get_answer("www.example.com", 1) is None
