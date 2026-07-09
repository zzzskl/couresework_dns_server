"""
dns_decoder.py — 完整集成测试。

覆盖: decode() / _parse_rdata(8种rtype) / _parse_rr / CLI 入口
共 ~15 个测试函数。
"""

from __future__ import annotations

import json
import struct
from unittest.mock import ANY, patch

import pytest

from dns_decoder import (
    _parse_rdata,
    _parse_rr,
    decode,
    load_data,
    main,
    output_result,
)


# ════════════════════════════════════════════════════════════════
# decode
# ════════════════════════════════════════════════════════════════


class TestDecode:
    def test_decode_a_query(self, sample_a_wire_bytes):
        """解码 A 查询报文."""
        msg = decode(sample_a_wire_bytes)
        assert msg.header.qr == 0  # query
        assert msg.header.opcode == 0
        assert msg.header.rd == 1
        assert msg.header.rcode == 0
        assert msg.qdcount == 1
        assert msg.ancount == 0
        assert msg.questions[0].qname == "www.baidu.com"
        assert msg.questions[0].qtype == 1
        assert msg.questions[0].qtype_str == "A"

    def test_decode_a_response(self, sample_a_response_wire_bytes):
        """解码 A 响应报文."""
        msg = decode(sample_a_response_wire_bytes)
        assert msg.header.qr == 1  # response
        assert msg.header.rcode == 0
        assert msg.qdcount == 1
        assert msg.ancount == 1
        assert msg.answers[0].name == "www.baidu.com"
        assert msg.answers[0].rr_type == 1
        assert msg.answers[0].rdata == "198.18.0.157"
        assert msg.answers[0].ttl == 1

    def test_decode_a_response_with_raw_hex(self, sample_a_response_wire_bytes):
        """include_raw_hex=True → raw_hex 非空."""
        msg = decode(sample_a_response_wire_bytes, include_raw_hex=True)
        assert msg.raw_hex is not None
        assert len(msg.raw_hex) > 0
        assert " " in msg.raw_hex  # 空格分隔格式
        # 验证 raw_hex 可解析回原文
        hex_clean = msg.raw_hex.replace(" ", "")
        assert bytes.fromhex(hex_clean) == sample_a_response_wire_bytes

    def test_decode_a_response_without_raw_hex(self, sample_a_response_wire_bytes):
        """include_raw_hex=False → raw_hex=None."""
        msg = decode(sample_a_response_wire_bytes, include_raw_hex=False)
        assert msg.raw_hex is None

    def test_decode_ns_response(self, sample_ns_response_wire_bytes):
        """解码 NS 委派响应."""
        msg = decode(sample_ns_response_wire_bytes)
        assert msg.header.qr == 1
        assert msg.qdcount == 1
        assert msg.nscount == 1
        assert msg.arcount == 1
        # 检查 authority (NS)
        assert msg.authorities[0].rr_type == 2
        assert msg.authorities[0].name == "example.com"
        # 检查 additional (glue A)
        assert msg.additionals[0].rr_type == 1
        assert msg.additionals[0].rdata == "1.2.3.4"

    def test_decode_too_short(self):
        """短于 12 字节 → ValueError."""
        with pytest.raises(ValueError, match="数据太短"):
            decode(b"")
        with pytest.raises(ValueError, match="数据太短"):
            decode(b"\x00" * 11)

    def test_decode_empty_questions(self):
        """没有 question (qdcount=0) 的报文."""
        wire = struct.pack("!HHHHHH", 0x1234, 0x8100, 0, 0, 0, 0)
        msg = decode(wire)
        assert msg.qdcount == 0
        assert msg.questions == []
        assert msg.header.qr == 1


# ════════════════════════════════════════════════════════════════
# _parse_rdata — 8 种 rtype
# ════════════════════════════════════════════════════════════════


class TestParseRdata:
    """_parse_rdata 各 rtype 路径全覆盖."""

    def test_type_a(self):
        """rtype=1 → IPv4 字符串."""
        data = bytes([192, 168, 1, 1])
        rdata, end = _parse_rdata(data, 0, 1, 4)
        assert rdata == "192.168.1.1"
        assert end == 4

    def test_type_aaaa(self):
        """rtype=28 → IPv6 字符串."""
        # "2606:2800:220:1:248:1893:25c8:1946"
        data = bytes.fromhex("26062800022000010248189325c81946")
        rdata, end = _parse_rdata(data, 0, 28, 16)
        assert rdata == "2606:2800:0220:0001:0248:1893:25c8:1946"
        assert end == 16

    def test_type_cname(self):
        """rtype=5 → 域名."""
        data = b"\x03www\x07example\x03com\x00"
        rdata, end = _parse_rdata(data, 0, 5, len(data))
        assert rdata == "www.example.com"

    def test_type_ns(self):
        """rtype=2 → 域名."""
        data = b"\x03ns1\x07example\x03com\x00"
        rdata, end = _parse_rdata(data, 0, 2, len(data))
        assert rdata == "ns1.example.com"

    def test_type_ptr(self):
        """rtype=12 → 域名."""
        data = b"\x03www\x07example\x03com\x00"
        rdata, end = _parse_rdata(data, 0, 12, len(data))
        assert rdata == "www.example.com"

    def test_type_mx(self):
        """rtype=15 → {preference, exchange}."""
        pref_bytes = struct.pack("!H", 10)
        domain_bytes = b"\x07example\x03com\x00"
        data = pref_bytes + domain_bytes
        rdata, end = _parse_rdata(data, 0, 15, len(data))
        assert rdata == {"preference": 10, "exchange": "example.com"}

    def test_type_txt(self):
        """rtype=16 → 字符串."""
        txt = b"hello world"
        data = bytes([len(txt)]) + txt
        rdata, end = _parse_rdata(data, 0, 16, len(data))
        assert rdata == "hello world"

    def test_type_txt_multiple_chunks(self):
        """TXT 多分段."""
        txt1 = b"hello"
        txt2 = b"world"
        data = bytes([len(txt1)]) + txt1 + bytes([len(txt2)]) + txt2
        rdata, end = _parse_rdata(data, 0, 16, len(data))
        assert rdata == "helloworld"

    def test_type_soa(self):
        """rtype=6 → {mname, rname, serial, ...}."""
        mname = b"\x03ns1\x07example\x03com\x00"
        rname = b"\x05admin\x07example\x03com\x00"
        five_ints = struct.pack("!IIIII", 2026070901, 3600, 900, 1209600, 86400)
        data = mname + rname + five_ints
        rdata, end = _parse_rdata(data, 0, 6, len(data))
        assert rdata["mname"] == "ns1.example.com"
        assert rdata["rname"] == "admin.example.com"
        assert rdata["serial"] == 2026070901
        assert rdata["refresh"] == 3600

    def test_type_unknown(self):
        """未知 type → hex 字符串."""
        data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        rdata, end = _parse_rdata(data, 0, 99, 4)
        assert rdata == "deadbeef"


# ════════════════════════════════════════════════════════════════
# _parse_rr
# ════════════════════════════════════════════════════════════════


class TestParseRR:
    def test_a_record(self):
        """解析 A 记录 single RR."""
        name = b"\x07example\x03com\x00"
        type_class_ttl_rdlen = struct.pack("!HHIH", 1, 1, 300, 4)
        rdata = bytes([192, 168, 1, 1])
        data = name + type_class_ttl_rdlen + rdata
        rr_dict, offset = _parse_rr(data, 0)
        assert rr_dict["name"] == "example.com"
        assert rr_dict["type"] == 1
        assert rr_dict["type_str"] == "A"
        assert rr_dict["class"] == 1
        assert rr_dict["ttl"] == 300
        assert rr_dict["rdata"] == "192.168.1.1"
        assert offset == len(data)

    def test_cname_record(self):
        name = b"\x05alias\x07example\x03com\x00"
        type_class_ttl_rdlen = struct.pack("!HHIH", 5, 1, 300, 18)
        rdata = b"\x03www\x07example\x03com\x00"
        data = name + type_class_ttl_rdlen + rdata
        rr_dict, offset = _parse_rr(data, 0)
        assert rr_dict["type"] == 5
        assert rr_dict["type_str"] == "CNAME"
        assert rr_dict["rdata"] == "www.example.com"


# ════════════════════════════════════════════════════════════════
# CLI 入口
# ════════════════════════════════════════════════════════════════


class TestDecoderCLI:
    def test_load_data_file_mode(self, tmp_path):
        """INPUT_MODE='file' → 读文件."""
        hex_file = tmp_path / "captured.hex"
        hex_file.write_text("12 34 01 00 00 01 00 00 00 00 00 00 00")
        data = load_data(input_mode="file", input_file=str(hex_file))
        assert data == bytes.fromhex("12340100000100000000000000")

    def test_load_data_stdin_mode(self, monkeypatch):
        """INPUT_MODE='stdin' → 读 stdin."""

        class FakeStdin:
            @staticmethod
            def read():
                return "12 34 01 00"

        monkeypatch.setattr("sys.stdin", FakeStdin())
        data = load_data(input_mode="stdin")
        assert data == bytes.fromhex("12340100")

    def test_load_data_invalid_mode(self):
        """非法 INPUT_MODE → ValueError."""
        with pytest.raises(ValueError, match="INPUT_MODE 必须是"):
            load_data(input_mode="invalid")

    def test_output_result_stdout(self, capsys):
        """OUTPUT_MODE='stdout' → 输出到控制台."""
        result = {"header": {"id": "0x1234"}, "questions": []}
        output_result(result, output_mode="stdout", print_raw_hex=False)
        captured = capsys.readouterr()
        assert "0x1234" in captured.out

    def test_output_result_file(self, tmp_path):
        """OUTPUT_MODE='file' → 写入文件."""
        out_file = tmp_path / "parsed.json"
        result = {"header": {"id": "0x1234"}, "questions": []}
        output_result(result, output_mode="file", output_json_file=str(out_file), print_raw_hex=False)
        assert out_file.exists()
        content = json.loads(out_file.read_text(encoding="utf-8"))
        assert content["header"]["id"] == "0x1234"

    def test_main_success(self, tmp_path, capsys):
        """main() 完整执行."""
        hex_file = tmp_path / "captured.hex"
        hex_file.write_text(
            "12 34 01 00 00 01 00 00 00 00 00 00 "
            "03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01"
        )
        main(
            input_mode="file",
            input_file=str(hex_file),
            output_mode="stdout",
            print_raw_hex=False,
        )
        captured = capsys.readouterr()
        assert "www.baidu.com" in captured.out
