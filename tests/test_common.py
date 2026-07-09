"""
dns_common.py — 完整集成测试。

覆盖: encode_domain / decode_domain / build_query / extract_ns_glue_pairs /
      min_ttl_from_message / extract_ns_delegations + 常量映射
共 ~18 个测试函数。
"""

from __future__ import annotations

import warnings

import pytest

from dns_common import (
    QCLASS_MAP,
    QCLASS_REVERSE,
    QTYPE_MAP,
    QTYPE_REVERSE,
    RCODE_MAP,
    build_query,
    decode_domain,
    encode_domain,
    extract_ns_delegations,
    extract_ns_glue_pairs,
    min_ttl_from_message,
)
from dns_types import DnsMessage, DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# 常量映射
# ════════════════════════════════════════════════════════════════


class TestConstants:
    def test_qtype_map_reversible(self):
        """QTYPE_MAP ↔ QTYPE_REVERSE 可逆."""
        for name, code in QTYPE_MAP.items():
            assert QTYPE_REVERSE[code] == name
        for code, name in QTYPE_REVERSE.items():
            assert QTYPE_MAP[name] == code

    def test_qtype_map_coverage(self):
        """重要 qtype 均已定义."""
        for required in ("A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "ANY"):
            assert required in QTYPE_MAP
            assert QTYPE_MAP[required] is not None

    def test_qclass_map_reversible(self):
        for name, code in QCLASS_MAP.items():
            assert QCLASS_REVERSE[code] == name

    def test_rcode_map_coverage(self):
        for code in range(6):
            assert code in RCODE_MAP
        # rcode 6 不应在标准映射中
        assert 6 not in RCODE_MAP


# ════════════════════════════════════════════════════════════════
# encode_domain
# ════════════════════════════════════════════════════════════════


class TestEncodeDomain:
    def test_simple(self):
        result = encode_domain("www.example.com")
        assert result == b"\x03www\x07example\x03com\x00"

    def test_single_label(self):
        result = encode_domain("localhost")
        assert result == b"\x09localhost\x00"

    def test_trailing_dot(self):
        """末尾点被去除."""
        result = encode_domain("www.example.com.")
        assert result == b"\x03www\x07example\x03com\x00"

    def test_empty(self):
        assert encode_domain("") == b"\x00"

    def test_root(self):
        """根域名 '.' → b'\\x00'."""
        assert encode_domain(".") == b"\x00"

    def test_consecutive_dots(self):
        """连续点（空标签）被跳过."""
        result = encode_domain("www..example.com")
        # "www" + "" + "example" + "com"
        assert result == b"\x03www\x07example\x03com\x00"

    def test_ascii_only(self):
        """非 ASCII 字符可能引发编码错误."""
        with pytest.raises(UnicodeEncodeError):
            encode_domain("中文.cn")


# ════════════════════════════════════════════════════════════════
# decode_domain
# ════════════════════════════════════════════════════════════════


class TestDecodeDomain:
    def test_simple(self):
        data = b"\x03www\x07example\x03com\x00"
        domain, offset = decode_domain(data, 0)
        assert domain == "www.example.com"
        assert offset == len(data)

    def test_with_pointer(self):
        """压缩指针指向已解析域名. """
        # 构造: 完整域名 (16 bytes) + 指向偏移 0 的指针
        domain_part = b"\x03www\x07example\x03com\x00"  # 17 bytes
        pointer = b"\xc0\x00"  # 指向 offset 0
        data = domain_part + pointer
        # 指针从 len(domain_part)=17 开始
        domain, offset = decode_domain(data, len(domain_part))
        assert domain == "www.example.com"
        assert offset == len(domain_part) + 2  # 19

    def test_multi_label_pointer(self):
        """多标签 + 指针混合."""
        domain_part = b"\x03www\x07example\x03com\x00"  # 17 bytes
        # api + 指向偏移 0 的指针
        multi = b"\x03api\xc0\x00"  # 3+1+2 = 6 bytes
        data = domain_part + multi
        domain, offset = decode_domain(data, len(domain_part))
        assert domain == "api.www.example.com"
        assert offset == len(domain_part) + len(multi)  # 23

    def test_max_jumps_exceeded(self):
        """超过 MAX_JUMPS=10 → ValueError."""
        # 构造循环指针链
        data = bytearray(22)
        data[0] = 0xC0
        data[1] = 2  # → offset 2
        data[2] = 0xC0
        data[3] = 0  # → offset 0 (循环)
        with pytest.raises(ValueError, match="压缩指针跳转次数超过上限"):
            decode_domain(bytes(data), 0)

    def test_self_reference(self):
        """自引用指针 → ValueError."""
        data = bytearray(10)
        data[0] = 0xC0
        data[1] = 0  # 指向自身 offset 0
        with pytest.raises(ValueError, match="压缩指针自引用"):
            decode_domain(bytes(data), 0)

    def test_pointer_out_of_bounds(self):
        """指针超出数据长度 → ValueError."""
        data = b"\xc0\xff"  # 指向 offset 255, 但数据只有 2 字节
        with pytest.raises(ValueError, match="超出数据长度"):
            decode_domain(data, 0)

    def test_pointer_truncated(self):
        """指针需要 2 字节但只有 1 字节 → ValueError."""
        data = b"\xc0"  # 不完整指针
        with pytest.raises(ValueError, match="越界"):
            decode_domain(data, 0)

    def test_empty_domain(self):
        """结束标记 \\x00 → 空域名. """
        domain, offset = decode_domain(b"\x00", 0)
        assert domain == ""
        assert offset == 1


# ════════════════════════════════════════════════════════════════
# build_query (deprecated)
# ════════════════════════════════════════════════════════════════


class TestBuildQuery:
    def test_deprecation_warning(self):
        with pytest.warns(DeprecationWarning):
            result = build_query("www.example.com", "A")
        assert isinstance(result, bytes)
        assert len(result) > 12

    def test_result_matches_create_query(self):
        """build_query 结果与 DnsMessage.create_query 等价."""
        from dns_decoder import decode

        with pytest.warns(DeprecationWarning):
            legacy = build_query("www.example.com", "MX")
        modern = DnsMessage.create_query("www.example.com", "MX").to_bytes()
        # 解码后比较语义（TxID 固定 0x1234 所以 bytes 可能一致）
        legacy_parsed = decode(legacy)
        modern_parsed = decode(modern)
        assert legacy_parsed.questions[0].qname == modern_parsed.questions[0].qname
        assert legacy_parsed.questions[0].qtype == modern_parsed.questions[0].qtype

    def test_build_query_default_type(self):
        with pytest.warns(DeprecationWarning):
            result = build_query("test.com")
        from dns_decoder import decode
        parsed = decode(result)
        assert parsed.questions[0].qtype == 1  # A


# ════════════════════════════════════════════════════════════════
# extract_ns_glue_pairs
# ════════════════════════════════════════════════════════════════


class TestExtractNsGluePairs:
    def test_basic(self):
        """authorities 有 NS + additionals 有匹配 A → 返回."""
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
        ]
        additionals = [
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4"),
        ]
        result = extract_ns_glue_pairs(authorities, additionals)
        assert "ns1.example.com" in result
        assert len(result["ns1.example.com"]) == 1

    def test_no_authorities(self):
        """无 NS 记录 → {}."""
        assert extract_ns_glue_pairs([], []) == {}
        assert extract_ns_glue_pairs(
            [DnsResourceRecord.create_a("test.com", "1.2.3.4")], []
        ) == {}

    def test_no_matching_glue(self):
        """有 NS 但 no matching A/AAAA → {}."""
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
        ]
        additionals = [
            DnsResourceRecord.create_a("other.com", "9.9.9.9"),
        ]
        result = extract_ns_glue_pairs(authorities, additionals)
        assert result == {}

    def test_aaaa_glue(self):
        """AAAA 胶水也可匹配."""
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
        ]
        additionals = [
            DnsResourceRecord.create_aaaa("ns1.example.com", "::1"),
        ]
        result = extract_ns_glue_pairs(authorities, additionals)
        assert "ns1.example.com" in result
        assert len(result["ns1.example.com"]) == 1
        assert result["ns1.example.com"][0].rr_type == 28

    def test_multiple_glue(self):
        """多个 glue per NS."""
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
        ]
        additionals = [
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4"),
            DnsResourceRecord.create_a("ns1.example.com", "5.6.7.8"),
        ]
        result = extract_ns_glue_pairs(authorities, additionals)
        assert len(result["ns1.example.com"]) == 2

    def test_case_insensitive(self):
        """域名大小写不敏感."""
        authorities = [
            DnsResourceRecord.create_ns("Example.Com", "NS1.Example.Com"),
        ]
        additionals = [
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4"),
        ]
        result = extract_ns_glue_pairs(authorities, additionals)
        assert "ns1.example.com" in result


# ════════════════════════════════════════════════════════════════
# min_ttl_from_message
# ════════════════════════════════════════════════════════════════


class TestMinTtlFromMessage:
    def test_basic(self):
        msg = DnsMessage.create_query("test.com")
        msg.answers.append(DnsResourceRecord.create_a("test.com", "1.2.3.4", ttl=300))
        msg.authorities.append(
            DnsResourceRecord.create_ns("test.com", "ns1.test.com", ttl=600)
        )
        assert min_ttl_from_message(msg) == 300

    def test_empty_response(self):
        msg = DnsMessage()
        assert min_ttl_from_message(msg) == 60  # 默认值

    def test_mixed_sections(self):
        """跨所有 section 取最小."""
        msg = DnsMessage.create_query("test.com")
        msg.answers.append(DnsResourceRecord.create_a("test.com", "1.2.3.4", ttl=100))
        msg.authorities.append(
            DnsResourceRecord.create_ns("test.com", "ns1.test.com", ttl=50)
        )
        msg.additionals.append(
            DnsResourceRecord.create_a("ns1.test.com", "5.6.7.8", ttl=200)
        )
        assert min_ttl_from_message(msg) == 50

    def test_single_rr(self):
        msg = DnsMessage.create_query("test.com")
        msg.answers.append(DnsResourceRecord.create_a("test.com", "1.2.3.4", ttl=42))
        assert min_ttl_from_message(msg) == 42

    def test_zero_ttl(self):
        """TTL=0 也可返回 0."""
        msg = DnsMessage.create_query("test.com")
        msg.answers.append(DnsResourceRecord.create_a("test.com", "1.2.3.4", ttl=0))
        assert min_ttl_from_message(msg) == 0


# ════════════════════════════════════════════════════════════════
# extract_ns_delegations
# ════════════════════════════════════════════════════════════════


class TestExtractNsDelegations:
    def test_basic(self):
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
        ]
        additionals = [
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4"),
        ]
        msg = DnsMessage(
            authorities=authorities,
            additionals=additionals,
        )
        result = extract_ns_delegations(msg)
        assert "example.com" in result
        ns_records, glue_records = result["example.com"]
        assert len(ns_records) == 1
        assert len(glue_records) == 1

    def test_no_ns(self):
        """无 NS → {}."""
        msg = DnsMessage()
        assert extract_ns_delegations(msg) == {}

    def test_ns_without_glue(self):
        """有 NS 但无 glue."""
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
        ]
        msg = DnsMessage(authorities=authorities)
        result = extract_ns_delegations(msg)
        assert "example.com" in result
        ns_records, glue_records = result["example.com"]
        assert len(ns_records) == 1
        assert len(glue_records) == 0  # 无 glue

    def test_multiple_domains(self):
        """多个域名各有委派."""
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
            DnsResourceRecord.create_ns("test.com", "ns1.test.com"),
        ]
        additionals = [
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4"),
            DnsResourceRecord.create_a("ns1.test.com", "5.6.7.8"),
        ]
        msg = DnsMessage(authorities=authorities, additionals=additionals)
        result = extract_ns_delegations(msg)
        assert "example.com" in result
        assert "test.com" in result

    def test_mixed_authority_types(self):
        """authorities 中混有非 NS 记录."""
        authorities = [
            DnsResourceRecord.create_ns("example.com", "ns1.example.com"),
            DnsResourceRecord(
                name="example.com", rr_type=6, rdata="soa data"
            ),  # SOA
        ]
        additionals = [
            DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4"),
        ]
        msg = DnsMessage(authorities=authorities, additionals=additionals)
        result = extract_ns_delegations(msg)
        assert "example.com" in result
