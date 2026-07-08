"""
DNS 协议栈统一测试套件（24 个测试）。

覆盖范围:
  1. dns_common      — 域名编解码、压缩指针
  2. dns_types       — DnsMessage/DnsResourceRecord 工厂与序列化
  3. dns_decoder     — bytes → DnsMessage 解析
  4. dns_coder       — RDATA 编码、往返一致性
  5. dns_cache       — CacheEntry / DnsCache / NS 委派提取
  6. dns_transport   — QueryFrame 验证、MockTransport
  7. QueryStack      — 正常路径、NS+胶水自旋、全部失败
  8. TaskStack       — 简单 A、CNAME 链、PAUSED 恢复
  9. ResolutionEngine — 端到端、缓存命中、委派缓存
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from dns_common import encode_domain, decode_domain
from dns_types import DnsMessage, DnsResourceRecord, DnsHeader
from dns_decoder import decode
from dns_coder import encode_message, encode_rdata
from dns_cache import CacheEntry, DnsCache, extract_ns_delegations
from dns_transport import (
    QueryFrame,
    TransportError,
    TransportTimeoutError,
)
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_iterative.engine import ResolutionEngine
from dns_iterative.models import QueryStatus

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_hex(name: str) -> bytes:
    return bytes.fromhex("".join((FIXTURES_DIR / name).read_text("utf-8").split()))


# ══════════════════════════════════════════════════════════════
# 1. dns_common — 域名编解码
# ══════════════════════════════════════════════════════════════

def test_encode_decode_domain_roundtrip():
    """域名编码再解码应还原。"""
    for domain in ("www.baidu.com", "ns1.example.com", "baidu.com"):
        assert decode_domain(encode_domain(domain), 0)[0] == domain


def test_decode_compression_pointer():
    """压缩指针 C0 0C 应正确解析为 www.baidu.com。"""
    parsed = decode(_load_hex("compressed.hex"))
    for ans in parsed.answers:
        assert ans.name == "www.baidu.com"


# ══════════════════════════════════════════════════════════════
# 2. dns_types — 工厂方法与序列化
# ══════════════════════════════════════════════════════════════

def test_create_query_and_response():
    """create_query 和 create_response 的字段正确性。"""
    q = DnsMessage.create_query("www.example.com", "AAAA")
    assert q.header.qr == 0
    assert q.questions[0].qname == "www.example.com"
    assert q.questions[0].qtype == 28

    r = DnsMessage.create_response(q, answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")])
    assert r.header.qr == 1
    assert r.header.id == q.header.id
    assert r.answers[0].rdata == "1.2.3.4"


def test_resource_record_factories():
    """四种工厂方法创建不同类型 RR。"""
    a = DnsResourceRecord.create_a("x.com", "1.1.1.1", ttl=100)
    assert a.rr_type == 1 and a.rdata == "1.1.1.1" and a.ttl == 100

    aaaa = DnsResourceRecord.create_aaaa("x.com", "::1")
    assert aaaa.rr_type == 28 and aaaa.rdata == "::1"

    cname = DnsResourceRecord.create_cname("x.com", "y.com")
    assert cname.rr_type == 5 and cname.rdata == "y.com"

    ns = DnsResourceRecord.create_ns("x.com", "ns1.x.com")
    assert ns.rr_type == 2 and ns.rdata == "ns1.x.com"


# ══════════════════════════════════════════════════════════════
# 3. dns_decoder — bytes → DnsMessage
# ══════════════════════════════════════════════════════════════

def test_decode_query_a():
    """解码 A 查询报文，验证 header 和 question。"""
    parsed = decode(_load_hex("query_a.hex"))
    assert parsed.header.qr == 0
    assert parsed.header.rd == 1
    assert parsed.questions[0].qname == "www.baidu.com"
    assert parsed.questions[0].qtype_str == "A"


def test_decode_response_a():
    """解码 A 响应报文，验证答案。"""
    parsed = decode(_load_hex("response_a.hex"))
    assert parsed.header.qr == 1
    assert parsed.answers[0].rdata == "192.168.0.1"
    assert parsed.answers[0].ttl == 60


def test_decode_too_short():
    """小于 12 字节抛 ValueError。"""
    with pytest.raises(ValueError, match="数据太短"):
        decode(b"\x00" * 11)


# ══════════════════════════════════════════════════════════════
# 4. dns_coder — 编码与往返
# ══════════════════════════════════════════════════════════════

def test_encode_rdata_a():
    """A 记录 RDATA 编码为 4 字节 IP。"""
    assert encode_rdata("192.168.0.1", 1, "A") == b"\xc0\xa8\x00\x01"


def test_roundtrip_query_exact():
    """无压缩指针的查询报文应精确往返。"""
    data = _load_hex("query_a.hex")
    assert encode_message(decode(data)) == data


def test_roundtrip_response_semantic():
    """含压缩指针的响应报文语义等价。"""
    data = _load_hex("compressed.hex")
    parsed = decode(data)
    reparsed = decode(encode_message(parsed))
    assert len(reparsed.answers) == len(parsed.answers)
    for a, b in zip(parsed.answers, reparsed.answers):
        assert a.rdata == b.rdata
        assert a.ttl == b.ttl


# ══════════════════════════════════════════════════════════════
# 5. dns_cache — CacheEntry / DnsCache / NS 委派
# ══════════════════════════════════════════════════════════════

def test_cache_entry_properties():
    """CacheEntry 过期检测和 TTL 剩余。"""
    expired = CacheEntry("x", 1, 1, expires_at=0.0)
    assert expired.is_expired
    assert expired.ttl_remaining == 0.0

    fresh = CacheEntry("x", 1, 1, expires_at=time.time() + 3600)
    assert not fresh.is_expired
    assert fresh.ttl_remaining > 0


def test_cache_entry_message_roundtrip():
    """from_message → to_message 往返后答案一致。"""
    query = DnsMessage.create_query("www.example.com", "A")
    resp = DnsMessage.create_response(
        query, answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300)]
    )
    entry = CacheEntry.from_message(resp)
    assert entry.domain == "www.example.com"
    assert entry.answers[0].rdata == "1.2.3.4"

    msg = entry.to_message(query)
    assert msg.header.id == query.header.id
    assert msg.answers[0].rdata == "1.2.3.4"


def test_dns_cache_basic():
    """缓存 set/get/expire 懒清理。"""
    cache = DnsCache()
    query = DnsMessage.create_query("www.example.com", "A")
    resp = DnsMessage.create_response(
        query, answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")]
    )
    # miss
    assert cache.get("www.example.com", 1) is None
    # set → hit
    cache.set_answer("www.example.com", 1, 1, resp)
    entry = cache.get("www.example.com", 1)
    assert entry is not None and entry.answers[0].rdata == "1.2.3.4"
    # 过期 → 自动删除
    entry.expires_at = 0.0
    cache.set("www.example.com", 1, 1, entry)
    assert cache.get("www.example.com", 1) is None


def test_dns_cache_key_precision():
    """不同 qtype 的 key 互不干扰。"""
    cache = DnsCache()
    q_a = DnsMessage.create_query("x.com", "A")
    q_aaaa = DnsMessage.create_query("x.com", "AAAA")
    resp_a = DnsMessage.create_response(q_a, answers=[DnsResourceRecord.create_a("x.com", "1.1.1.1")])
    resp_aaaa = DnsMessage.create_response(q_aaaa, answers=[DnsResourceRecord.create_aaaa("x.com", "::1")])
    cache.set_answer("x.com", 1, 1, resp_a)
    cache.set_answer("x.com", 28, 1, resp_aaaa)
    assert cache.get("x.com", 1).answers[0].rdata == "1.1.1.1"
    assert cache.get("x.com", 28).answers[0].rdata == "::1"


def test_extract_ns_delegations():
    """从响应中提取 NS+glue。"""
    query = DnsMessage.create_query("www.example.com", "A")
    resp = DnsMessage.create_response(
        query,
        authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        additionals=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
    )
    d = extract_ns_delegations(resp)
    assert "example.com" in d
    ns, glue = d["example.com"]
    assert ns[0].rdata == "ns1.example.com"
    assert glue[0].rdata == "1.2.3.4"


# ══════════════════════════════════════════════════════════════
# 6. dns_transport — QueryFrame + MockTransport
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("target_ip,domain,qtype,err", [
    ("", "x.com", 1, "target_ip 不能为空"),
    ("8.8.8.8", "", 1, "domain 不能为空"),
    ("8.8.8.8", "x.com", -1, "qtype 超出有效范围"),
    ("8.8.8.8", "x.com", 99999, "qtype 超出有效范围"),
])
def test_query_frame_validation(target_ip, domain, qtype, err):
    """QueryFrame 输入验证。"""
    with pytest.raises(ValueError, match=err):
        QueryFrame(target_ip, domain, qtype)


def test_mock_transport(mock_transport, sample_a):
    """MockTransport 预设响应与调用记录。"""
    frame = QueryFrame("8.8.8.8", "www.baidu.com", 1)
    mock_transport.add_response(sample_a)
    result = asyncio.run(mock_transport.query(frame))
    assert result is sample_a
    assert mock_transport.call_history == [frame]


# ══════════════════════════════════════════════════════════════
# 7. QueryStack — 状态机
# ══════════════════════════════════════════════════════════════

def test_query_stack_normal(mock_transport, sample_a):
    """正常路径：READY→SENT→FINISHED。"""
    mock_transport.add_response(sample_a)
    qs = QueryStack(mock_transport)
    qs.push(QueryFrame("8.8.8.8", "www.baidu.com", 1))
    asyncio.run(qs.run())
    assert qs.consume_result().response is sample_a
    assert qs._status == QueryStatus.FINISHED


def test_query_stack_ns_glue_spin(mock_transport):
    """NS+胶水→自旋，用胶水 IP 重查。"""
    ns = DnsMessage(
        header=DnsHeader(), questions=[],
        authorities=[DnsResourceRecord.create_ns("baidu.com", "ns1.baidu.com")],
        additionals=[DnsResourceRecord.create_a("ns1.baidu.com", "1.2.3.4")],
    )
    final = DnsMessage(
        header=DnsHeader(), questions=[],
        answers=[DnsResourceRecord.create_a("www.baidu.com", "93.184.216.34")],
    )
    mock_transport.add_response(ns)
    mock_transport.add_response(final)

    qs = QueryStack(mock_transport)
    qs.push(QueryFrame("8.8.8.8", "www.baidu.com", 1))
    asyncio.run(qs.run())

    assert qs.consume_result().response is final
    assert mock_transport.call_history[0].target_ip == "8.8.8.8"
    assert mock_transport.call_history[1].target_ip == "1.2.3.4"


def test_query_stack_all_fail(mock_transport):
    """全部目标失败→error。"""
    mock_transport.add_error(TransportTimeoutError("超时"))
    qs = QueryStack(mock_transport)
    qs.push(QueryFrame("8.8.8.8", "www.baidu.com", 1))
    asyncio.run(qs.run())
    r = qs.consume_result()
    assert r is not None and r.error is not None


# ══════════════════════════════════════════════════════════════
# 8. TaskStack — 状态机
# ══════════════════════════════════════════════════════════════

def test_task_stack_simple_a(mock_transport, sample_a):
    """简单 A 记录：NEW→PENDING→FINISHED。"""
    mock_transport.add_response(sample_a)
    qs = QueryStack(mock_transport)
    ts = TaskStack()
    ts._query_stack = qs
    ts._initial_targets = ["8.8.8.8"]
    ts.push("www.baidu.com")
    asyncio.run(ts.run())
    assert ts._result_data.response is sample_a


def test_task_stack_cname_chain(mock_transport, sample_cname):
    """CNAME 链：CNAME→目标 A→最终答案。"""
    a_resp = DnsMessage(
        header=DnsHeader(), questions=[],
        answers=[DnsResourceRecord.create_a("target.baidu.com", "93.184.216.34")],
    )
    mock_transport.add_response(sample_cname)
    mock_transport.add_response(a_resp)

    qs = QueryStack(mock_transport)
    ts = TaskStack()
    ts._query_stack = qs
    ts._initial_targets = ["8.8.8.8"]
    ts.push("www.baidu.com")
    asyncio.run(ts.run())
    assert ts._result_data.response is a_resp


def test_task_stack_paused_recovery(mock_transport, sample_ns_no_glue):
    """NS 无胶水→子任务解析 NS IP→恢复原查询。"""
    ns_ip = DnsMessage(
        header=DnsHeader(), questions=[],
        answers=[DnsResourceRecord.create_a("ns1.baidu.com", "1.2.3.4")],
    )
    final = DnsMessage(
        header=DnsHeader(), questions=[],
        answers=[DnsResourceRecord.create_a("www.baidu.com", "93.184.216.34")],
    )
    mock_transport.add_response(sample_ns_no_glue)
    mock_transport.add_response(ns_ip)
    mock_transport.add_response(final)

    qs = QueryStack(mock_transport)
    ts = TaskStack()
    ts._query_stack = qs
    ts._initial_targets = ["8.8.8.8"]
    ts.push("www.baidu.com")
    asyncio.run(ts.run())
    assert ts._result_data.response is final
    assert mock_transport.call_history[2].target_ip == "1.2.3.4"


# ══════════════════════════════════════════════════════════════
# 9. ResolutionEngine — 端到端 + 缓存
# ══════════════════════════════════════════════════════════════

def test_engine_resolve(mock_transport, sample_a):
    """engine.resolve 返回 A 答案。"""
    mock_transport.add_response(sample_a)
    engine = ResolutionEngine(mock_transport)
    result = asyncio.run(engine.resolve("www.baidu.com"))
    assert result is sample_a


def test_engine_cache_hit(mock_transport):
    """第一次 miss→写入缓存→第二次命中。"""
    cache = DnsCache()
    a_resp = DnsMessage(
        header=DnsHeader(), questions=[],
        answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
    )
    mock_transport.add_response(a_resp)

    engine = ResolutionEngine(mock_transport, cache=cache)
    r1 = asyncio.run(engine.resolve("www.example.com"))
    assert r1 is not None and r1.answers[0].rdata == "1.2.3.4"
    assert len(mock_transport.call_history) == 1

    r2 = asyncio.run(engine.resolve("www.example.com"))
    assert r2 is not None and r2.answers[0].rdata == "1.2.3.4"
    assert len(mock_transport.call_history) == 1  # 未增加


def test_engine_delegation_cache(mock_transport):
    """委派缓存命中→跳过根服务器，直接用 glue IP。"""
    cache = DnsCache()
    cache.set_delegation(
        "example.com",
        [DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        [DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
    )
    a_resp = DnsMessage(
        header=DnsHeader(), questions=[],
        answers=[DnsResourceRecord.create_a("www.example.com", "93.184.216.34")],
    )
    mock_transport.add_response(a_resp)

    engine = ResolutionEngine(mock_transport, cache=cache)
    result = asyncio.run(engine.resolve("www.example.com"))
    assert result is not None
    assert mock_transport.call_history[0].target_ip == "1.2.3.4"
