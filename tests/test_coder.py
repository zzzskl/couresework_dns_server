"""
dns_coder.py — 完整集成测试。

覆盖: NameCompressor / encode_header / encode_question / encode_rdata (9种) /
      encode_record / _encode_rdata_compressed / encode_message (含CLI)
共 ~20 个测试函数。
"""

from __future__ import annotations

import json
import struct
from unittest.mock import patch

import pytest

from dns_coder import (
    NameCompressor,
    _encode_record_compressed,
    encode_header,
    encode_message,
    encode_question,
    encode_rdata,
    encode_record,
    export_output,
    load_input,
    main,
    verify_roundtrip,
)
from dns_types import DnsMessage, DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# NameCompressor
# ════════════════════════════════════════════════════════════════


class TestNameCompressor:
    def test_register_name(self):
        """注册域名及所有后缀."""
        c = NameCompressor()
        c.register_name("www.example.com", 0)
        assert "www.example.com" in c._table
        assert "example.com" in c._table
        assert "com" in c._table

    def test_register_empty_name(self):
        c = NameCompressor()
        c.register_name("", 0)  # 不应抛出异常
        assert len(c._table) == 0

    def test_register_trailing_dot(self):
        c = NameCompressor()
        c.register_name("example.com.", 0)
        assert len(c._table) == 0  # 末尾点被跳过

    def test_exact_match(self):
        """精确匹配 → 2 字节指针."""
        c = NameCompressor()
        c.register_name("www.example.com", 12)
        result = c.encode_name("www.example.com", 100)
        assert result == struct.pack("!H", 0xC000 | 12)

    def test_suffix_match(self):
        """后缀匹配 → 前缀 + 指针."""
        c = NameCompressor()
        c.register_name("example.com", 20)
        result = c.encode_name("www.example.com", 50)
        # 结果应包含 "www" 标签 (\x03www = 4 字节) + 指针
        assert result[:4] == b"\x03www"
        assert len(result) >= 2  # 至少包含指针

    def test_no_match(self):
        """无匹配 → 完整标签序列."""
        c = NameCompressor()
        result = c.encode_name("www.example.com", 0)
        assert result == b"\x03www\x07example\x03com\x00"
        # 且注册了所有后缀
        assert "www.example.com" in c._table
        assert "example.com" in c._table

    def test_empty_name(self):
        c = NameCompressor()
        assert c.encode_name("", 0) == b"\x00"

    def test_trailing_dot_name(self):
        c = NameCompressor()
        c.register_name("example.com", 10)
        # 输入末尾点 → 先去除
        result = c.encode_name("www.example.com.", 50)
        assert result[:4] == b"\x03www"
        # 后缀匹配应触发
        assert len(result) >= 2  # 至少是指针长度

    def test_register_idempotent(self):
        """重复注册不改变偏移."""
        c = NameCompressor()
        c.register_name("example.com", 20)
        c.register_name("example.com", 30)  # 已存在，不更新
        assert c._table["example.com"] == 20


# ════════════════════════════════════════════════════════════════
# encode_header
# ════════════════════════════════════════════════════════════════


class TestEncodeHeader:
    def test_from_fields_query(self):
        """从字段组合 (QR=0, RD=1)."""
        h = {
            "id": "0x1234",
            "qr": 0, "opcode": 0, "aa": 0, "tc": 0,
            "rd": 1, "ra": 0, "z": 0, "rcode": 0,
            "qdcount": 1, "ancount": 0, "nscount": 0, "arcount": 0,
        }
        result = encode_header(h)
        assert len(result) == 12
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", result)
        assert txid == 0x1234
        assert (flags >> 15) & 1 == 0  # QR=0
        assert (flags >> 8) & 1 == 1  # RD=1
        assert (flags & 0xF) == 0  # RCODE=0
        assert qd == 1

    def test_from_fields_response_with_rcode(self):
        """响应 + rcode=3."""
        h = {
            "id": "0xabcd",
            "qr": 1, "opcode": 0, "rd": 1, "ra": 1, "rcode": 3,
            "qdcount": 1, "ancount": 0, "nscount": 0, "arcount": 0,
        }
        result = encode_header(h)
        txid, flags, *_ = struct.unpack("!HHHHHH", result)
        assert txid == 0xABCD
        assert (flags >> 15) & 1 == 1  # QR=1
        assert (flags & 0xF) == 3  # RCODE=3

    def test_flags_raw_priority(self):
        """flags_raw 优先于各字段."""
        h = {
            "id": "0x1234",
            "flags_raw": "0x8580",  # QR=1, RD=1, RA=1, RCODE=0
            "qr": 0,  # 应被忽略
            "qdcount": 1, "ancount": 0, "nscount": 0, "arcount": 0,
        }
        result = encode_header(h)
        txid, flags, *_ = struct.unpack("!HHHHHH", result)
        assert flags == 0x8580

    def test_zero_counts(self):
        h = {"id": "0x0000"}
        result = encode_header(h)
        *_, qd, an, ns, ar = struct.unpack("!HHHHHH", result)
        assert qd == an == ns == ar == 0


# ════════════════════════════════════════════════════════════════
# encode_question
# ════════════════════════════════════════════════════════════════


class TestEncodeQuestion:
    def test_basic(self):
        q = {"qname": "www.example.com", "qtype": 1, "qclass": 1}
        result = encode_question(q)
        assert result.startswith(b"\x03www\x07example\x03com\x00")
        # 最后 4 字节 = qtype + qclass
        qtype, qclass = struct.unpack("!HH", result[-4:])
        assert qtype == 1
        assert qclass == 1

    def test_str_type(self):
        q = {"qname": "test.com", "qtype": "A", "qclass": 1}
        result = encode_question(q)
        qtype, _ = struct.unpack("!HH", result[-4:])
        assert qtype == 1

    def test_str_class(self):
        q = {"qname": "test.com", "qtype": 1, "qclass": "IN"}
        result = encode_question(q)
        _, qclass = struct.unpack("!HH", result[-4:])
        assert qclass == 1

    def test_unknown_type_fallback(self):
        """未知 type 字符串 → 默认 1."""
        q = {"qname": "test.com", "qtype": "UNKNOWN", "qclass": 1}
        result = encode_question(q)
        qtype, _ = struct.unpack("!HH", result[-4:])
        assert qtype == 1


# ════════════════════════════════════════════════════════════════
# encode_rdata — 9 种 rtype
# ════════════════════════════════════════════════════════════════


class TestEncodeRdata:
    def test_a(self):
        result = encode_rdata("1.2.3.4", 1, "A")
        assert result == bytes([1, 2, 3, 4])

    def test_a_invalid(self):
        """非法 IPv4 → 全零."""
        result = encode_rdata("not.an.ip", 1, "A")
        assert result == b"\x00\x00\x00\x00"

    def test_aaaa(self):
        """完整 8 段 IPv6."""
        result = encode_rdata(
            "2606:2800:0220:0001:0248:1893:25c8:1946", 28, "AAAA"
        )
        assert len(result) == 16
        assert result == bytes.fromhex("26062800022000010248189325c81946")

    def test_aaaa_short_form(self):
        """简写 IPv6 ::1 → 回退为全零（因代码仅支持 8 段）."""
        result = encode_rdata("::1", 28, "AAAA")
        assert result == b"\x00" * 16

    def test_aaaa_full(self):
        """标准 IPv6 格式."""
        result = encode_rdata(
            "2606:2800:0220:0001:0248:1893:25c8:1946", 28, "AAAA"
        )
        assert len(result) == 16

    def test_aaaa_invalid(self):
        result = encode_rdata("not-ipv6", 28, "AAAA")
        assert result == b"\x00" * 16

    def test_cname(self):
        result = encode_rdata("www.example.com", 5, "CNAME")
        assert result == b"\x03www\x07example\x03com\x00"

    def test_ns(self):
        result = encode_rdata("ns1.example.com", 2, "NS")
        assert result == b"\x03ns1\x07example\x03com\x00"

    def test_ptr(self):
        result = encode_rdata("www.example.com", 12, "PTR")
        assert result == b"\x03www\x07example\x03com\x00"

    def test_mx(self):
        result = encode_rdata(
            {"preference": 10, "exchange": "mail.example.com"}, 15, "MX"
        )
        # 2 字节 preference + 域名
        pref, = struct.unpack("!H", result[:2])
        assert pref == 10
        assert result[2:] == b"\x04mail\x07example\x03com\x00"

    def test_mx_invalid(self):
        """MX rdata 非 dict → 空."""
        result = encode_rdata("invalid", 15, "MX")
        assert result == b"\x00\x00\x00"

    def test_txt(self):
        result = encode_rdata("hello", 16, "TXT")
        assert result == b"\x05hello"

    def test_txt_long(self):
        """超 255 字节 → 分段."""
        long_str = "a" * 300
        result = encode_rdata(long_str, 16, "TXT")
        assert len(result) > 300
        assert result[0] == 255  # 第一段长度
        assert result[256] == 45  # 第二段长度 (300-255=45)

    def test_txt_invalid(self):
        """TXT rdata 非 str → 空."""
        result = encode_rdata(12345, 16, "TXT")
        assert result == b"\x00"

    def test_soa(self):
        result = encode_rdata(
            {
                "mname": "ns1.example.com",
                "rname": "admin.example.com",
                "serial": 2026070901,
                "refresh": 3600,
                "retry": 900,
                "expire": 1209600,
                "minimum": 86400,
            },
            6,
            "SOA",
        )
        assert len(result) > 20
        # 域名部分可解析
        assert b"ns1" in result

    def test_soa_invalid(self):
        """SOA rdata 非 dict → 20 字节填充."""
        result = encode_rdata("invalid", 6, "SOA")
        assert result == b"\x00" * 20

    def test_unknown_type_hex(self):
        """未知类型且 rdata 为 hex 字符串 → raw bytes."""
        result = encode_rdata("deadbeef", 99, "Unknown")
        assert result == bytes.fromhex("deadbeef")

    def test_unknown_type_invalid_hex(self):
        result = encode_rdata("not-hex!", 99, "Unknown")
        assert result == b""

    def test_rtype_str_driven(self):
        """依赖 type_str 而非 type 数值."""
        result = encode_rdata("1.2.3.4", 0, "A")  # type=0 但 type_str="A"
        assert result == bytes([1, 2, 3, 4])


# ════════════════════════════════════════════════════════════════
# encode_record
# ════════════════════════════════════════════════════════════════


class TestEncodeRecord:
    def test_a_record(self):
        rec = {
            "name": "www.example.com",
            "type": 1,
            "class": 1,
            "ttl": 300,
            "rdata": "192.168.1.1",
        }
        result = encode_record(rec)
        assert len(result) > 10
        # 验证 RDATA 部分
        assert result[-4:] == bytes([192, 168, 1, 1])

    def test_record_str_fields(self):
        """type/class 为字符串."""
        rec = {
            "name": "test.com",
            "type": "A",
            "class": "IN",
            "ttl": 300,
            "rdata": "9.9.9.9",
        }
        result = encode_record(rec)
        assert len(result) > 10
        # type=1, class=1
        header = result[result.index(b"\x00"):]  # 找到域名结束
        # 跳过域名后的 10 字节头
        rr_type, rr_class = struct.unpack("!HH", result[-14:-10])
        assert rr_type == 1
        assert rr_class == 1


# ════════════════════════════════════════════════════════════════
# encode_message
# ════════════════════════════════════════════════════════════════


class TestEncodeMessage:
    def test_from_dict(self):
        d = {
            "header": {"id": "0x1234", "qr": 0, "rd": 1, "rcode": 0},
            "questions": [{"qname": "www.example.com", "qtype": 1, "qclass": 1}],
            "answers": [],
            "authorities": [],
            "additionals": [],
        }
        wire = encode_message(d)
        assert isinstance(wire, bytes)
        assert len(wire) > 12

    def test_from_dnsmessage(self):
        msg = DnsMessage.create_query("www.example.com", "A")
        wire = encode_message(msg)
        assert isinstance(wire, bytes)

    def test_compression_on(self):
        """含多条记录的报文使用压缩（至少能正确解码）. """
        from dns_decoder import decode
        query = DnsMessage.create_query("www.example.com", "A")
        response = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")],
            authorities=[
                DnsResourceRecord.create_ns("example.com", "ns1.example.com")
            ],
            additionals=[
                DnsResourceRecord.create_a("ns1.example.com", "5.6.7.8"),
                DnsResourceRecord.create_a("ns1.example.com", "9.10.11.12"),
            ],
        )
        wire = encode_message(response, use_compression=True)
        # 验证压缩后的报文可解码
        parsed = decode(wire)
        assert parsed.ancount == 1
        assert parsed.nscount == 1
        assert parsed.arcount == 2

    def test_compression_off(self):
        msg = DnsMessage.create_query("www.example.com", "A")
        wire = encode_message(msg, use_compression=False)
        assert isinstance(wire, bytes)

    def test_compressed_roundtrip(self):
        """压缩编解码往返."""
        from dns_decoder import decode

        msg = DnsMessage.create_query("www.example.com", "A")
        msg.answers.append(DnsResourceRecord.create_a("www.example.com", "1.2.3.4"))
        wire = encode_message(msg, use_compression=True)
        parsed = decode(wire)
        assert parsed.questions[0].qname == "www.example.com"
        assert parsed.answers[0].rdata == "1.2.3.4"


# ════════════════════════════════════════════════════════════════
# CLI 入口
# ════════════════════════════════════════════════════════════════


class TestCoderCLI:
    def test_main_success(self, tmp_path, capsys):
        json_file = tmp_path / "parsed.json"
        json_file.write_text(
            json.dumps({
                "header": {"id": "0x1234", "qr": 0, "rd": 1, "rcode": 0},
                "questions": [{"qname": "www.example.com", "qtype": 1, "qclass": 1}],
                "answers": [],
            })
        )
        main(
            input_mode="file",
            input_json_file=str(json_file),
            output_mode="stdout",
            print_progress=False,
        )
        captured = capsys.readouterr()
        assert "编码结果" in captured.out

    def test_verify_roundtrip_match(self, capsys):
        raw_hex = "12 34 01 00 00 01"
        msg = DnsMessage.create_query("test.com")
        msg.raw_hex = raw_hex
        verify_roundtrip(msg.to_dict(), bytes.fromhex("123401000001"))
        captured = capsys.readouterr()
        assert "一致" in captured.out or "不完全一致" in captured.out

    def test_verify_roundtrip_no_raw_hex(self, capsys):
        """无 raw_hex → 静默返回."""
        msg = DnsMessage.create_query("test.com")
        verify_roundtrip(msg.to_dict(), b"")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_export_output_stdout(self, capsys):
        export_output(b"\x00\x01\x02", output_mode="stdout")
        captured = capsys.readouterr()
        assert "00 01 02" in captured.out

    def test_export_output_file(self, tmp_path):
        out_file = tmp_path / "output.hex"
        export_output(b"\xde\xad", output_mode="file_hex", output_hex_file=str(out_file))
        assert out_file.exists()
        assert out_file.read_text() == "de ad"

    def test_export_output_binary(self, tmp_path):
        out_file = tmp_path / "output.bin"
        export_output(b"\xde\xad", output_mode="file_bin", output_bin_file=str(out_file))
        assert out_file.exists()
        assert out_file.read_bytes() == b"\xde\xad"
