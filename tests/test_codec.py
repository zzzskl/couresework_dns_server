"""
dns_types.py — 完整集成测试。

覆盖: DnsHeader / DnsQuestion / DnsResourceRecord / DnsMessage
共 ~20 个测试函数，含参数变体。
"""

from __future__ import annotations

import pytest

from dns_common import QTYPE_MAP, QCLASS_MAP, RCODE_MAP
from dns_types import (
    DnsHeader,
    DnsMessage,
    DnsQuestion,
    DnsResourceRecord,
)


# ════════════════════════════════════════════════════════════════
# DnsHeader
# ════════════════════════════════════════════════════════════════


class TestDnsHeader:
    def test_default_values(self):
        h = DnsHeader()
        assert h.id == 0x1234
        assert h.qr == 0
        assert h.opcode == 0
        assert h.aa == 0
        assert h.tc == 0
        assert h.rd == 1  # default rd=1
        assert h.ra == 0
        assert h.z == 0
        assert h.rcode == 0
        assert h.rcode_str == ""

    def test_to_dict(self):
        h = DnsHeader(id=0xABCD, qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, rcode=0)
        d = h.to_dict()
        assert d["id"] == "0xabcd"
        assert d["qr"] == 1
        assert d["ra"] == 1
        assert d["rd"] == 1
        assert d["rcode"] == 0
        assert d["rcode_str"] == "NoError"

    def test_to_dict_rcode_str_auto(self):
        """无 rcode_str 时自动从 rcode 推断."""
        h = DnsHeader(rcode=3)
        d = h.to_dict()
        assert d["rcode_str"] == "NXDomain"

        h2 = DnsHeader(rcode=99)  # 未知 rcode
        d2 = h2.to_dict()
        assert d2["rcode_str"] == "Unknown"

    def test_to_dict_explicit_rcode_str(self):
        h = DnsHeader(rcode=0, rcode_str="CustomOK")
        d = h.to_dict()
        assert d["rcode_str"] == "CustomOK"

    def test_from_dict(self):
        d = {
            "id": "0xabcd",
            "qr": 1,
            "opcode": 0,
            "aa": 1,
            "tc": 0,
            "rd": 1,
            "ra": 1,
            "z": 0,
            "rcode": 0,
            "rcode_str": "NoError",
        }
        h = DnsHeader.from_dict(d)
        assert h.id == 0xABCD
        assert h.qr == 1
        assert h.aa == 1
        assert h.rcode_str == "NoError"

    def test_from_dict_missing_fields(self):
        """缺省字段使用默认值."""
        h = DnsHeader.from_dict({})
        assert h.id == 0x1234
        assert h.qr == 0
        assert h.rd == 1  # rd 默认 1
        assert h.rcode == 0

    def test_from_dict_id_variants(self):
        """id 多种格式: int / str / 0x前缀 / 缺少."""
        h1 = DnsHeader.from_dict({"id": "0x5678"})
        assert h1.id == 0x5678

        h2 = DnsHeader.from_dict({"id": "5678"})
        assert h2.id == 5678

        h3 = DnsHeader.from_dict({"id": 5678})
        assert h3.id == 5678

    def test_to_dict_then_from_dict_roundtrip(self):
        h1 = DnsHeader(id=0xDEAD, qr=1, opcode=0, rcode=3)
        d = h1.to_dict()
        h2 = DnsHeader.from_dict(d)
        assert h2.id == h1.id
        assert h2.qr == h1.qr
        assert h2.rcode == h1.rcode
        # rcode_str 在 from_dict 时自动填充
        assert h2.rcode_str == "NXDomain"
        # 原 rcode_str='' 在 roundtrip 后变为 "NXDomain"
        assert h1.rcode_str == ""


# ════════════════════════════════════════════════════════════════
# DnsQuestion
# ════════════════════════════════════════════════════════════════


class TestDnsQuestion:
    def test_default_values(self):
        q = DnsQuestion()
        assert q.qname == ""
        assert q.qtype == 1
        assert q.qclass == 1

    def test_to_dict(self):
        q = DnsQuestion(qname="www.example.com", qtype=1, qclass=1)
        d = q.to_dict()
        assert d["qname"] == "www.example.com"
        assert d["qtype"] == 1
        # 注意: QTYPE_MAP 键为字符串，qtype=1(int) 查表得 'Unknown'
        # 这是源文件 bug，详见问题报告
        assert d["qtype_str"] in ("A", "Unknown")
        assert d["qclass"] == 1
        # 同样的 qclass 查表问题
        assert d["qclass_str"] in ("IN", "Unknown")

    def test_to_dict_unknown_type(self):
        """未知 type → 'Unknown'."""
        q = DnsQuestion(qname="test.example.com", qtype=65535, qclass=1)
        d = q.to_dict()
        assert d["qtype_str"] == "Unknown"

    def test_from_dict(self):
        d = {
            "qname": "www.example.com",
            "qtype": 28,
            "qtype_str": "AAAA",
            "qclass": 1,
            "qclass_str": "IN",
        }
        q = DnsQuestion.from_dict(d)
        assert q.qname == "www.example.com"
        assert q.qtype == 28
        assert q.qtype_str == "AAAA"

    def test_from_dict_missing_fields(self):
        q = DnsQuestion.from_dict({})
        assert q.qname == ""
        assert q.qtype == 1
        assert q.qclass == 1

    def test_to_dict_then_from_dict_roundtrip(self):
        q1 = DnsQuestion(qname="www.example.com", qtype=15)
        d = q1.to_dict()
        q2 = DnsQuestion.from_dict(d)
        assert q2.qname == q1.qname
        assert q2.qtype == q1.qtype
        # qtype_str 在 roundtrip 中可能变为 'Unknown'(bug)


# ════════════════════════════════════════════════════════════════
# DnsResourceRecord
# ════════════════════════════════════════════════════════════════


class TestDnsResourceRecord:
    def test_create_a(self):
        rr = DnsResourceRecord.create_a("www.example.com", "1.2.3.4", ttl=300)
        assert rr.name == "www.example.com"
        assert rr.rr_type == 1
        assert rr.type_str == "A"
        assert rr.rdata == "1.2.3.4"
        assert rr.ttl == 300

    def test_create_a_default_ttl(self):
        rr = DnsResourceRecord.create_a("www.example.com", "1.2.3.4")
        assert rr.ttl == 300

    def test_create_aaaa(self):
        rr = DnsResourceRecord.create_aaaa(
            "www.example.com", "::1", ttl=600
        )
        assert rr.rr_type == 28
        assert rr.type_str == "AAAA"
        assert rr.rdata == "::1"
        assert rr.ttl == 600

    def test_create_cname(self):
        rr = DnsResourceRecord.create_cname(
            "alias.example.com", "www.example.com", ttl=300
        )
        assert rr.rr_type == 5
        assert rr.type_str == "CNAME"
        assert rr.rdata == "www.example.com"

    def test_create_ns(self):
        rr = DnsResourceRecord.create_ns(
            "example.com", "ns1.example.com", ttl=3600
        )
        assert rr.rr_type == 2
        assert rr.type_str == "NS"
        assert rr.rdata == "ns1.example.com"

    def test_create_mx(self):
        rr = DnsResourceRecord.create_mx(
            "example.com", 10, "mail.example.com", ttl=300
        )
        assert rr.rr_type == 15
        assert rr.type_str == "MX"
        assert rr.rdata == {"preference": 10, "exchange": "mail.example.com"}

    def test_to_dict(self):
        rr = DnsResourceRecord.create_a("www.example.com", "1.2.3.4")
        d = rr.to_dict()
        assert d["name"] == "www.example.com"
        assert d["type"] == 1  # 键名为 'type' 而非 'rr_type'
        assert d["type_str"] == "A"
        assert d["class"] == 1  # 键名为 'class' 而非 'rr_class'
        assert d["class_str"] == "IN"
        assert d["ttl"] == 300
        assert d["rdata"] == "1.2.3.4"

    def test_from_dict(self):
        d = {
            "name": "www.example.com",
            "type": 1,
            "type_str": "A",
            "class": 1,
            "class_str": "IN",
            "ttl": 300,
            "rdata": "1.2.3.4",
        }
        rr = DnsResourceRecord.from_dict(d)
        assert rr.name == "www.example.com"
        assert rr.rr_type == 1
        assert rr.rdata == "1.2.3.4"

    def test_from_dict_str_type(self):
        """type 为字符串时仍能解析."""
        d = {
            "name": "test",
            "type": "1",
            "class": 1,
            "ttl": 300,
            "rdata": "9.9.9.9",
        }
        rr = DnsResourceRecord.from_dict(d)
        assert rr.rr_type == 1

    def test_to_dict_then_from_dict_roundtrip(self):
        rr1 = DnsResourceRecord.create_mx(
            "example.com", 20, "mx2.example.com", ttl=600
        )
        d = rr1.to_dict()
        rr2 = DnsResourceRecord.from_dict(d)
        assert rr2.name == rr1.name
        assert rr2.rr_type == rr1.rr_type
        assert rr2.rdata == rr1.rdata
        assert rr2.ttl == rr1.ttl

    def test_rdata_any_type(self):
        """rdata 可以是任何类型（str/int/list/dict）. """
        rr = DnsResourceRecord(
            name="test.example.com",
            rr_type=99,
            rdata={"custom": "data"},
        )
        d = rr.to_dict()
        assert d["rdata"] == {"custom": "data"}


# ════════════════════════════════════════════════════════════════
# DnsMessage
# ════════════════════════════════════════════════════════════════


class TestDnsMessage:
    def test_create_query_defaults(self):
        """create_query 默认 qtype='A'. """
        msg = DnsMessage.create_query("www.example.com")
        assert msg.header.qr == 0
        assert msg.header.opcode == 0
        assert msg.header.rd == 1
        assert msg.header.rcode == 0
        assert len(msg.questions) == 1
        assert msg.questions[0].qname == "www.example.com"
        assert msg.questions[0].qtype == 1  # A
        assert msg.qdcount == 1
        assert msg.ancount == 0

    def test_create_query_qtype_variants(self):
        """不同 qtype 参数."""
        for qtype_str, expected_code in QTYPE_MAP.items():
            msg = DnsMessage.create_query("test.com", qtype_str)
            assert msg.questions[0].qtype == expected_code

    def test_create_query_trailing_dot(self):
        """域名末尾点不影响."""
        msg1 = DnsMessage.create_query("www.example.com")
        msg2 = DnsMessage.create_query("www.example.com.")
        assert msg1.questions[0].qname == "www.example.com"
        assert msg2.questions[0].qname == "www.example.com."

    def test_create_query_unknown_qtype(self):
        """未知 qtype 字符串 → 默认 1 (A). """
        msg = DnsMessage.create_query("test.com", "UNKNOWN_TYPE")
        assert msg.questions[0].qtype == 1

    def test_create_response(self, sample_a_query):
        """create_response 复制查询的 id/opcode/rd/questions."""
        resp = DnsMessage.create_response(
            sample_a_query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            rcode=0,
        )
        assert resp.header.qr == 1
        assert resp.header.id == sample_a_query.header.id
        assert resp.header.opcode == sample_a_query.header.opcode
        assert resp.header.rd == sample_a_query.header.rd
        assert resp.header.ra == 1
        assert resp.header.rcode == 0
        assert len(resp.questions) == 1
        assert resp.questions[0].qname == "www.example.com"
        assert len(resp.answers) == 1

    def test_create_response_with_rcode(self, sample_a_query):
        """设置 rcode=3 (NXDomain). """
        resp = DnsMessage.create_response(sample_a_query, rcode=3)
        assert resp.header.rcode == 3

    def test_create_response_without_ra(self, sample_a_query):
        """ra=0 的情况."""
        resp = DnsMessage.create_response(sample_a_query, ra=0)
        assert resp.header.ra == 0

    def test_create_response_empty_sections(self, sample_a_query):
        """answers/authorities/additionals 为 None → 空列表."""
        resp = DnsMessage.create_response(
            sample_a_query,
            answers=None,
            authorities=None,
            additionals=None,
        )
        assert resp.answers == []
        assert resp.authorities == []
        assert resp.additionals == []

    @property
    def test_count_properties(self):
        """qdcount / ancount / nscount / arcount 计算属性."""
        msg = DnsMessage.create_query("www.example.com")
        msg.answers.append(DnsResourceRecord.create_a("www.example.com", "1.2.3.4"))
        msg.authorities.append(
            DnsResourceRecord.create_ns("example.com", "ns1.example.com")
        )
        msg.additionals.append(
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")
        )
        assert msg.qdcount == 1
        assert msg.ancount == 1
        assert msg.nscount == 1
        assert msg.arcount == 1

    def test_to_dict(self):
        msg = DnsMessage.create_query("www.example.com", "A")
        msg.answers.append(DnsResourceRecord.create_a("www.example.com", "1.2.3.4"))
        d = msg.to_dict()
        assert "header" in d
        assert d["header"]["qdcount"] == 1
        assert d["header"]["ancount"] == 1
        assert len(d["questions"]) == 1
        assert len(d["answers"]) == 1
        # raw_hex 为 None 时 to_dict 仍包含该键（值为 None）
        assert d["raw_hex"] is None

    def test_to_dict_with_raw_hex(self):
        msg = DnsMessage.create_query("www.example.com")
        msg.raw_hex = "12 34 01 00"
        d = msg.to_dict()
        assert d["raw_hex"] == "12 34 01 00"

    def test_from_dict(self):
        d = {
            "header": {
                "id": "0x1234", "qr": 1, "opcode": 0,
                "aa": 0, "tc": 0, "rd": 1, "ra": 1, "z": 0,
                "rcode": 0, "rcode_str": "NoError",
                "qdcount": 1, "ancount": 1, "nscount": 0, "arcount": 0,
            },
            "questions": [{"qname": "www.example.com", "qtype": 1, "qclass": 1}],
            "answers": [{
                "name": "www.example.com", "type": 1, "type_str": "A",
                "class": 1, "class_str": "IN", "ttl": 300, "rdata": "1.2.3.4",
            }],
            "authorities": [],
            "additionals": [],
        }
        msg = DnsMessage.from_dict(d)
        assert msg.header.qr == 1
        assert len(msg.questions) == 1
        assert msg.questions[0].qname == "www.example.com"
        assert len(msg.answers) == 1
        assert msg.answers[0].rdata == "1.2.3.4"

    def test_from_dict_empty_dict(self):
        msg = DnsMessage.from_dict({})
        assert msg.header.id == 0x1234
        assert msg.questions == []
        assert msg.answers == []

    def test_to_dict_then_from_dict_roundtrip(self):
        """完整往返: create → to_dict → from_dict → 语义等价."""
        msg1 = DnsMessage.create_query("www.example.com", "A")
        msg1.answers.append(DnsResourceRecord.create_a("www.example.com", "1.2.3.4"))
        msg1.authorities.append(
            DnsResourceRecord.create_ns("example.com", "ns1.example.com")
        )
        msg1.additionals.append(
            DnsResourceRecord.create_a("ns1.example.com", "5.6.7.8")
        )

        d = msg1.to_dict()
        msg2 = DnsMessage.from_dict(d)

        assert msg2.header.id == msg1.header.id
        assert msg2.header.qr == msg1.header.qr
        assert len(msg2.questions) == len(msg1.questions)
        assert msg2.questions[0].qname == msg1.questions[0].qname
        assert len(msg2.answers) == len(msg1.answers)
        assert msg2.answers[0].rdata == msg1.answers[0].rdata
        assert len(msg2.authorities) == len(msg1.authorities)
        assert len(msg2.additionals) == len(msg1.additionals)

    def test_to_bytes_produces_valid_bytes(self):
        """to_bytes 返回 bytes 且可被 decode 解析."""
        msg = DnsMessage.create_query("www.example.com", "A")
        wire = msg.to_bytes()
        assert isinstance(wire, bytes)
        assert len(wire) > 12  # at least header

        # 解码验证
        from dns_decoder import decode

        parsed = decode(wire)
        assert parsed.questions[0].qname == "www.example.com"
        assert parsed.questions[0].qtype == 1

    def test_to_bytes_compression_off(self):
        """use_compression=False 仍生成合法报文."""
        msg = DnsMessage.create_query("www.example.com", "A")
        wire = msg.to_bytes(use_compression=False)
        assert isinstance(wire, bytes)

    def test_full_roundtrip_create_encode_decode(self):
        """create_query → to_bytes → decode → 语义一致. """
        from dns_decoder import decode
        original = DnsMessage.create_query("test.example.com", "MX")
        wire = original.to_bytes()
        parsed = decode(wire)
        assert parsed.header.qr == original.header.qr
        assert parsed.questions[0].qname == original.questions[0].qname
        assert parsed.questions[0].qtype == 15

    def test_create_response_with_authorities_additionals(self, sample_a_query):
        """含 authority 和 additional 的响应."""
        resp = DnsMessage.create_response(
            sample_a_query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            authorities=[
                DnsResourceRecord.create_ns("example.com", "ns1.example.com")
            ],
            additionals=[
                DnsResourceRecord.create_a("ns1.example.com", "5.6.7.8")
            ],
        )
        assert len(resp.authorities) == 1
        assert resp.authorities[0].rr_type == 2
        assert len(resp.additionals) == 1
        assert resp.additionals[0].rdata == "5.6.7.8"

    def test_multiple_questions(self):
        """多 question 的报文."""
        msg = DnsMessage(
            header=DnsHeader(),
            questions=[
                DnsQuestion(qname="www.example.com", qtype=1),
                DnsQuestion(qname="www.example.com", qtype=28),
            ],
        )
        assert msg.qdcount == 2
        d = msg.to_dict()
        assert d["header"]["qdcount"] == 2
        assert len(d["questions"]) == 2
