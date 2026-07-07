"""
DNS 集成测试
===============================
覆盖范围:
  1. Decoder ↔ Coder 往返一致性  (TestRoundtrip)
  2. Decoder 解析正确性           (TestDecoder)
  3. Decoder 边界情况             (TestDecoderEdgeCases)
  4. Coder RDATA 编码             (TestCoderRDATA)
  5. Coder 完整报文编码           (TestCoderMessage)
  6. build_query                  (TestBuildQuery)
  7. Client ↔ Server 集成         (TestServerIntegration)
  8. 端到端管道                   (TestEndToEndPipeline)

用法:
    pytest tests/test_integration.py -v
"""

import os
import sys
import json
import struct
import socket
import threading
import time
import io
from unittest.mock import patch, MagicMock
from pathlib import Path

import pytest

# ── 将项目根目录加入 sys.path ─────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import dns_common
from dns_types import DnsMessage
import dns_decoder
import dns_coder
import dns_client
import dns_resolver

# ── 路径常量 ────────────────────────────────────────────
FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ══════════════════════════════════════════════════════════════
# 辅助函数
# ══════════════════════════════════════════════════════════════

def load_hex(filename: str) -> bytes:
    """从 fixtures 目录加载 hex 文件，返回 bytes"""
    path = FIXTURES_DIR / filename
    content = path.read_text(encoding='utf-8')
    return bytes.fromhex(''.join(content.split()))


def decode_hex(filename: str):
    """加载并解码一个 fixtures hex 文件"""
    data = load_hex(filename)
    return dns_decoder.decode(data)


def assert_semantic_equal(msg_a, msg_b):
    """对比两次解码结果的语义等价性（忽略域名压缩/展开引起的 name 差异）"""
    assert msg_a.questions == msg_b.questions, "Questions 不匹配"
    assert len(msg_a.answers) == len(msg_b.answers), "Answers 数量不匹配"
    for i in range(len(msg_a.answers)):
        a, b = msg_a.answers[i], msg_b.answers[i]
        assert a.name == b.name, \
            f"Answers[{i}] name 不匹配: {a.name} != {b.name}"
        assert a.rdata == b.rdata, \
            f"Answers[{i}] rdata 不匹配"
        assert a.ttl == b.ttl, \
            f"Answers[{i}] ttl 不匹配"
        assert a.type_str == b.type_str, \
            f"Answers[{i}] type 不匹配"
        assert a.rr_class == b.rr_class, \
            f"Answers[{i}] class 不匹配"


# ══════════════════════════════════════════════════════════════
# 测试 1：Decoder ↔ Coder 往返一致性
# ══════════════════════════════════════════════════════════════

class TestRoundtrip:
    """核心往返测试：decode(encode(decode(X))) ≈ decode(X)"""

    def test_query_a_exact(self):
        """纯查询（无压缩指针）应能完全还原"""
        data = load_hex("query_a.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed)
        assert reencoded == data, "A 查询往返后 bytes 不一致"

    def test_query_mx_exact(self):
        """MX 查询（无压缩指针）应能完全还原"""
        data = load_hex("query_mx.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed)
        assert reencoded == data, "MX 查询往返后 bytes 不一致"

    def test_response_a_semantic(self):
        """A 响应（含压缩指针）语义等价"""
        data = load_hex("response_a.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        assert_semantic_equal(parsed, reparsed)

    def test_response_mx_semantic(self):
        """MX 响应（含压缩指针）语义等价"""
        data = load_hex("response_mx.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        assert_semantic_equal(parsed, reparsed)

    def test_response_cname_semantic(self):
        """CNAME 响应（含压缩指针）语义等价"""
        data = load_hex("response_cname.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        assert_semantic_equal(parsed, reparsed)

    def test_compressed_two_answers(self):
        """含 2 个答案的压缩响应"""
        data = load_hex("compressed.hex")
        parsed = dns_decoder.decode(data)
        assert len(parsed.answers) == 2
        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        assert_semantic_equal(parsed, reparsed)


# ══════════════════════════════════════════════════════════════
# 测试 2：Decoder 解析正确性
# ══════════════════════════════════════════════════════════════

class TestDecoder:
    """验证 decoder 正确解析各字段"""

    def test_query_a_header(self):
        parsed = decode_hex("query_a.hex")
        h = parsed.header
        assert h.id == 0x1234
        assert h.qr == 0          # 查询
        assert h.rd == 1          # 期望递归
        assert parsed.qdcount == 1
        assert parsed.ancount == 0

    def test_query_a_question(self):
        parsed = decode_hex("query_a.hex")
        q = parsed.questions[0]
        assert q.qname == 'www.baidu.com'
        assert q.qtype == 1
        assert q.qtype_str == 'A'
        assert q.qclass == 1
        assert q.qclass_str == 'IN'

    def test_response_a_answer(self):
        parsed = decode_hex("response_a.hex")
        assert len(parsed.answers) == 1
        ans = parsed.answers[0]
        assert ans.name == 'www.baidu.com'
        assert ans.type_str == 'A'
        assert ans.rdata == '192.168.0.1'
        assert ans.ttl == 60

    def test_response_a_header(self):
        parsed = decode_hex("response_a.hex")
        h = parsed.header
        assert h.qr == 1          # 响应
        assert h.rcode_str == 'NoError'
        assert parsed.ancount == 1

    def test_query_mx_question(self):
        parsed = decode_hex("query_mx.hex")
        q = parsed.questions[0]
        assert q.qname == 'baidu.com'
        assert q.qtype == 15
        assert q.qtype_str == 'MX'

    def test_response_mx_answer(self):
        parsed = decode_hex("response_mx.hex")
        ans = parsed.answers[0]
        assert ans.type_str == 'MX'
        assert isinstance(ans.rdata, dict)
        assert ans.rdata['preference'] == 10
        assert ans.rdata['exchange'] == 'mail.com'

    def test_response_cname_answer(self):
        parsed = decode_hex("response_cname.hex")
        ans = parsed.answers[0]
        assert ans.type_str == 'CNAME'
        assert ans.rdata == 'www.a.shifen.com'

    def test_compressed_two_answers(self):
        parsed = decode_hex("compressed.hex")
        assert len(parsed.answers) == 2
        assert parsed.answers[0].rdata == '192.168.0.1'
        assert parsed.answers[1].rdata == '192.168.0.2'

    def test_raw_hex_present(self):
        """PRINT_RAW_HEX 默认为 True，raw_hex 应存在"""
        parsed = decode_hex("query_a.hex")
        assert parsed.raw_hex is not None


# ══════════════════════════════════════════════════════════════
# 测试 3：Decoder 边界情况
# ══════════════════════════════════════════════════════════════

class TestDecoderEdgeCases:
    """验证 decoder 对异常/边界输入的鲁棒性"""

    def test_data_too_short_11_bytes(self):
        """小于 12 字节的数据应抛出 ValueError"""
        with pytest.raises(ValueError, match="数据太短"):
            dns_decoder.decode(b'\x00' * 11)

    def test_data_too_short_0_bytes(self):
        with pytest.raises(ValueError, match="数据太短"):
            dns_decoder.decode(b'')

    @staticmethod
    def _build_query_with_modified_field(domain: str, qtype: str,
                                          field_offset: int, value: int) -> bytes:
        """构造查询并将指定字段替换为指定值
        field_offset: 从末尾算起 -4=qtype, -2=qclass
        """
        data = bytearray(dns_common.build_query(domain, qtype))
        data[field_offset:field_offset + 2] = struct.pack('!H', value)
        return bytes(data)

    def test_unknown_qtype(self):
        data = self._build_query_with_modified_field("test.com", "A", -4, 999)
        parsed = dns_decoder.decode(data)
        assert parsed.questions[0].qtype == 999
        assert parsed.questions[0].qtype_str == 'Unknown'

    def test_unknown_qclass(self):
        data = self._build_query_with_modified_field("test.com", "A", -2, 777)
        parsed = dns_decoder.decode(data)
        assert parsed.questions[0].qclass == 777
        assert parsed.questions[0].qclass_str == 'Unknown'

    def test_multi_question(self):
        """构造 qdcount=2 的报文，验证两个 question 都被解析"""
        q1 = dns_common.build_query("www.baidu.com", "A")
        q2 = dns_common.build_query("mail.example.com", "MX")

        # 提取 question 部分（跳过各自的 header）
        # www.baidu.com encoding: 03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 = 16 bytes
        # plus qtype+qclass = 4 bytes = 20 bytes total
        q1_question = q1[12:]   # 跳过 12 字节 header
        q2_question = q2[12:]

        # 构造新报文: header(qdcount=2) + q1 question + q2 question
        header = struct.pack('!HHHHHH', 0x1234, 0x0100, 2, 0, 0, 0)
        combined = header + q1_question + q2_question
        parsed = dns_decoder.decode(combined)

        assert len(parsed.questions) == 2
        assert parsed.questions[0].qname == 'www.baidu.com'
        assert parsed.questions[1].qname == 'mail.example.com'

    def test_compression_parse(self):
        """压缩指针 C0 0C 应正确解析为 www.baidu.com"""
        parsed = decode_hex("compressed.hex")
        for ans in parsed.answers:
            assert ans.name == 'www.baidu.com'


# ══════════════════════════════════════════════════════════════
# 测试 4：Coder RDATA 各类型编码
# ══════════════════════════════════════════════════════════════

class TestCoderRDATA:
    """验证每种 DNS 记录类型的 RDATA 编码正确性"""

    def test_a(self):
        rdata_bytes = dns_coder.encode_rdata("192.168.0.1", 1, "A")
        assert rdata_bytes == b'\xc0\xa8\x00\x01'

    def test_aaaa(self):
        """验证 AAAA 编码输出 16 字节"""
        rdata_bytes = dns_coder.encode_rdata("2001:0db8:0000:0000:0000:0000:0000:0001",
                                              28, "AAAA")
        assert len(rdata_bytes) == 16

    def test_cname(self):
        rdata_bytes = dns_coder.encode_rdata("www.a.shifen.com", 5, "CNAME")
        expected = dns_common.encode_domain("www.a.shifen.com")
        assert rdata_bytes == expected

    def test_ns(self):
        rdata_bytes = dns_coder.encode_rdata("ns1.example.com", 2, "NS")
        expected = dns_coder.encode_domain("ns1.example.com")
        assert rdata_bytes == expected

    def test_ptr(self):
        rdata_bytes = dns_coder.encode_rdata("ptr.example.com", 12, "PTR")
        expected = dns_coder.encode_domain("ptr.example.com")
        assert rdata_bytes == expected

    def test_mx(self):
        rdata_bytes = dns_coder.encode_rdata(
            {"preference": 10, "exchange": "mail.com"}, 15, "MX"
        )
        assert len(rdata_bytes) >= 3
        pref = struct.unpack('!H', rdata_bytes[:2])[0]
        assert pref == 10

    def test_txt_short(self):
        """短 TXT（<255 字节）"""
        text = "hello world"
        rdata_bytes = dns_coder.encode_rdata(text, 16, "TXT")
        expected_len = len(text)
        assert rdata_bytes[0] == expected_len    # 长度前缀
        assert rdata_bytes[1:] == text.encode('utf-8')

    def test_txt_long(self):
        """长 TXT（>255 字节），应自动分段"""
        long_text = "x" * 300
        rdata_bytes = dns_coder.encode_rdata(long_text, 16, "TXT")
        # 第一段: 1 字节长度 + 255 内容; 第二段: 1 字节长度 + 45 内容
        assert len(rdata_bytes) == (1 + 255) + (1 + 45)

    def test_soa(self):
        rdata_bytes = dns_coder.encode_rdata(
            {"mname": "ns1.example.com", "rname": "admin.example.com",
             "serial": 20240101, "refresh": 3600, "retry": 600,
             "expire": 86400, "minimum": 60}, 6, "SOA"
        )
        # 长度应至少包含两个域名 + 5 个 uint32
        assert len(rdata_bytes) > 20
        # 最后 20 字节是 5 个 uint32
        serial, refresh, retry, expire, minimum = struct.unpack('!IIIII',
                                                                  rdata_bytes[-20:])
        assert serial == 20240101
        assert refresh == 3600
        assert retry == 600
        assert expire == 86400
        assert minimum == 60

    def test_unknown_type_hex_rdata(self):
        """未知类型且 rdata 是 hex 字符串时，应直接解码"""
        rdata_bytes = dns_coder.encode_rdata("de ad be ef", 99, "Unknown")
        assert rdata_bytes == b'\xde\xad\xbe\xef'


# ══════════════════════════════════════════════════════════════
# 测试 5：Coder 完整报文编码
# ══════════════════════════════════════════════════════════════

class TestCoderMessage:
    """验证完整报文编码函数"""

    def test_encode_simple_query(self):
        data = load_hex("query_a.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed)
        assert reencoded == data

    def test_encode_mx_query(self):
        data = load_hex("query_mx.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed)
        assert reencoded == data

    def test_encode_header_preserves_counts(self):
        data = load_hex("response_a.hex")
        parsed = dns_decoder.decode(data)
        h = parsed.header.to_dict()
        h['qdcount'] = parsed.qdcount
        h['ancount'] = parsed.ancount
        h['nscount'] = parsed.nscount
        h['arcount'] = parsed.arcount
        header_bytes = dns_coder.encode_header(h)
        _, _, qd, an, ns, ar = struct.unpack('!HHHHHH', header_bytes)
        assert qd == 1
        assert an == 1
        assert ns == 0
        assert ar == 0

    def test_encode_question(self):
        data = load_hex("query_a.hex")
        parsed = dns_decoder.decode(data)
        q_bytes = dns_coder.encode_question(parsed.questions[0].to_dict())
        # question = encoded_name + 4 bytes (qtype+qclass)
        assert len(q_bytes) >= 4 + 4

    def test_encode_record(self):
        data = load_hex("response_a.hex")
        parsed = dns_decoder.decode(data)
        r_bytes = dns_coder.encode_record(parsed.answers[0].to_dict())
        assert len(r_bytes) > 0
        # 应包含 IP
        assert b'\xc0\xa8\x00\x01' in r_bytes


# ══════════════════════════════════════════════════════════════
# 测试 6：build_query
# ══════════════════════════════════════════════════════════════

class TestBuildQuery:
    """验证 dns_client.build_query"""

    def test_query_a_length(self):
        data = dns_common.build_query("www.baidu.com", "A")
        # 12 header + 15 name + 4 qtype/qclass = 31
        assert len(data) == 31

    def test_query_mx_length(self):
        data = dns_common.build_query("baidu.com", "MX")
        # 12 header + 11 name + 4 = 27
        assert len(data) == 27

    def test_query_header_fields(self):
        data = dns_common.build_query("test.com", "A")
        txid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
        assert txid == 0x1234
        assert flags == 0x0100  # standard query with RD
        assert qd == 1
        assert an == ns == ar == 0

    def test_query_decodes_correctly(self):
        """build_query 的输出应能被 decoder 正确解析"""
        data = dns_common.build_query("www.baidu.com", "A")
        parsed = dns_decoder.decode(data)
        assert parsed.questions[0].qname == 'www.baidu.com'
        assert parsed.questions[0].qtype_str == 'A'
        assert parsed.qdcount == 1

    def test_build_query_types(self):
        for qtype in ('A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT'):
            data = dns_common.build_query("example.com", qtype)
            parsed = dns_decoder.decode(data)
            assert parsed.questions[0].qtype_str == qtype, \
                f"QTYPE {qtype} 不匹配"


# ══════════════════════════════════════════════════════════════
# 测试 7：Client ↔ Server 集成（UDP 环回）
# ══════════════════════════════════════════════════════════════

class TestServerIntegration:
    """验证 client 发送的 DNS 查询能被 server 正确捕获并保存"""

    PORT = 15354  # 使用非标准端口避免冲突

    @pytest.fixture
    def server_fixture(self, tmp_path):
        """启动一个 server 线程，返回 (port, output_file_path)"""
        output_file = tmp_path / "test_captured.hex"

        stop_event = threading.Event()

        def run_server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', self.PORT))
            sock.settimeout(2.0)
            while not stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                    hex_str = ' '.join(f'{b:02x}' for b in data)
                    with open(str(output_file), 'w', encoding='utf-8') as f:
                        f.write(hex_str)
                    # AUTO_REPLY: 把原数据发回
                    sock.sendto(data, addr)
                except socket.timeout:
                    continue
                except OSError:
                    break
            sock.close()

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        time.sleep(0.3)  # 等待 server 启动

        yield self.PORT, output_file

        stop_event.set()
        server_thread.join(timeout=2)

    def test_server_captures_a_query(self, server_fixture):
        port, output_file = server_fixture

        query = dns_common.build_query("www.baidu.com", "A")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(query, ('127.0.0.1', port))

        time.sleep(0.5)
        assert output_file.exists(), "Server 未创建捕获文件"

        captured_hex = output_file.read_text(encoding='utf-8')
        captured_bytes = bytes.fromhex(''.join(captured_hex.split()))
        assert captured_bytes == query, "捕获数据与发送数据不匹配"

        # 验证能收到 AUTO_REPLY 响应
        response, addr = sock.recvfrom(1024)
        assert response == query, "AUTO_REPLY 响应不匹配"
        sock.close()

    def test_server_captures_mx_query(self, server_fixture):
        port, output_file = server_fixture

        query = dns_common.build_query("baidu.com", "MX")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(query, ('127.0.0.1', port))

        time.sleep(0.5)
        captured_hex = output_file.read_text(encoding='utf-8')
        captured_bytes = bytes.fromhex(''.join(captured_hex.split()))
        assert captured_bytes == query

        response, addr = sock.recvfrom(1024)
        assert response == query
        sock.close()

    def test_server_captured_hex_decodes(self, server_fixture):
        """验证 server 捕获的 hex 文件能被 decoder 正确解析"""
        port, output_file = server_fixture

        query = dns_common.build_query("www.baidu.com", "A")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(query, ('127.0.0.1', port))

        time.sleep(0.5)
        sock.close()

        captured_hex = output_file.read_text(encoding='utf-8')
        captured_bytes = bytes.fromhex(''.join(captured_hex.split()))
        parsed = dns_decoder.decode(captured_bytes)
        assert parsed.questions[0].qname == 'www.baidu.com'
        assert parsed.questions[0].qtype_str == 'A'


# ══════════════════════════════════════════════════════════════
# 测试 8：端到端管道
# ══════════════════════════════════════════════════════════════

class TestEndToEndPipeline:
    """所有 fixture 通过 decode → encode → decode 验证语义一致性"""

    @pytest.mark.parametrize("filename", [
        "query_a.hex",
        "response_a.hex",
        "query_mx.hex",
        "response_mx.hex",
        "response_cname.hex",
        "compressed.hex",
    ])
    def test_all_fixtures_roundtrip(self, filename):
        """所有 fixtures 经过 decode → encode → decode 后语义一致"""
        data = load_hex(filename)
        parsed1 = dns_decoder.decode(data)

        # 验证消息结构完整性
        assert parsed1.header is not None
        assert len(parsed1.questions) >= 0
        h = parsed1.header
        assert h.id is not None
        assert h.qr is not None
        assert h.rcode is not None
        assert parsed1.qdcount >= 0

        # 编码
        reencoded = dns_coder.encode_message(parsed1)

        # 再次解码（编码后的）
        parsed2 = dns_decoder.decode(reencoded)

        # 语义对比
        assert_semantic_equal(parsed1, parsed2)

    @pytest.mark.parametrize("filename,expected_qname,expected_qtype", [
        ("query_a.hex",         "www.baidu.com", "A"),
        ("response_a.hex",      "www.baidu.com", "A"),
        ("query_mx.hex",        "baidu.com",     "MX"),
        ("response_mx.hex",     "baidu.com",     "MX"),
        ("response_cname.hex",  "www.baidu.com", "A"),
        ("compressed.hex",      "www.baidu.com", "A"),
    ])
    def test_question_preserved_across_pipeline(self, filename,
                                                expected_qname, expected_qtype):
        """验证 question 在 decode → encode → decode 后保持不变"""
        parsed = decode_hex(filename)
        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        q = reparsed.questions[0]
        assert q.qname == expected_qname
        assert q.qtype_str == expected_qtype

    def test_pipeline_multi_answer_preserved(self):
        """compressed.hex 有 2 个 answers，管道后仍保留"""
        parsed = decode_hex("compressed.hex")
        assert len(parsed.answers) == 2

        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        assert len(reparsed.answers) == 2

    def test_pipeline_header_counts_match(self):
        """验证 header 中的计数值与实际的 section 数量一致"""
        for fname in ["response_a.hex", "response_mx.hex",
                       "response_cname.hex", "compressed.hex"]:
            parsed = decode_hex(fname)
            h = parsed.header
            assert parsed.qdcount == len(parsed.questions)
            assert parsed.ancount == len(parsed.answers)


# ══════════════════════════════════════════════════════════════
# 测试 9：Authorities / Additionals 段落编解码
# ══════════════════════════════════════════════════════════════

class TestAuthoritiesAdditionals:
    """验证 authorities 和 additionals 段落的编解码（P0 补全）"""

    def _build_full_response(self) -> dict:
        """构造包含所有 4 个 section 的解析结果"""
        return DnsMessage.from_dict({
            'header': {
                'id': '0x1234', 'qr': 1, 'opcode': 0, 'aa': 0, 'tc': 0,
                'rd': 1, 'ra': 1, 'rcode': 0, 'rcode_str': 'NoError',
                'qdcount': 1, 'ancount': 1, 'nscount': 2, 'arcount': 2
            },
            'questions': [
                {'qname': 'example.com', 'qtype': 1, 'qtype_str': 'A',
                 'qclass': 1, 'qclass_str': 'IN'}
            ],
            'answers': [
                {'name': 'example.com', 'type': 1, 'type_str': 'A',
                 'class': 1, 'ttl': 60, 'rdata': '1.2.3.4'}
            ],
            'authorities': [
                {'name': 'example.com', 'type': 2, 'type_str': 'NS',
                 'class': 1, 'ttl': 300, 'rdata': 'ns1.example.com'},
                {'name': 'example.com', 'type': 2, 'type_str': 'NS',
                 'class': 1, 'ttl': 300, 'rdata': 'ns2.example.com'}
            ],
            'additionals': [
                {'name': 'ns1.example.com', 'type': 1, 'type_str': 'A',
                 'class': 1, 'ttl': 300, 'rdata': '1.2.3.4'},
                {'name': 'ns2.example.com', 'type': 1, 'type_str': 'A',
                 'class': 1, 'ttl': 300, 'rdata': '5.6.7.8'}
            ]
        })

    def test_full_message_encode_decode(self):
        """完整 4-section 报文编码后解码应内容一致"""
        parsed = self._build_full_response()
        encoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(encoded)

        assert reparsed.nscount == 2
        assert reparsed.arcount == 2
        assert len(reparsed.authorities) == 2
        assert len(reparsed.additionals) == 2
        assert reparsed.authorities[0].type_str == 'NS'
        assert reparsed.additionals[0].type_str == 'A'

    def test_authorities_roundtrip(self):
        """authorities 段编解码语义等价"""
        parsed = self._build_full_response()
        encoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(encoded)
        for i in range(2):
            assert parsed.authorities[i].name == reparsed.authorities[i].name
            assert parsed.authorities[i].rdata == reparsed.authorities[i].rdata

    def test_additionals_roundtrip(self):
        """additionals 段编解码语义等价"""
        parsed = self._build_full_response()
        encoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(encoded)
        for i in range(2):
            assert parsed.additionals[i].name == reparsed.additionals[i].name
            assert parsed.additionals[i].rdata == reparsed.additionals[i].rdata

    def test_nscount_arcount_consistency(self):
        """nscount/arcount 与实际 section 长度一致"""
        parsed = self._build_full_response()
        encoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(encoded)
        assert reparsed.nscount == len(reparsed.authorities)
        assert reparsed.arcount == len(reparsed.additionals)

    def test_empty_authorities_additionals(self):
        """空的 authorities/additionals 不应影响编解码"""
        parsed = {
            'header': {'id': '0x1234', 'qr': 0, 'rd': 1, 'rcode': 0,
                       'qdcount': 1, 'ancount': 0, 'nscount': 0, 'arcount': 0},
            'questions': [{'qname': 'test.com', 'qtype': 1, 'qtype_str': 'A',
                           'qclass': 1, 'qclass_str': 'IN'}],
            'answers': [],
            'authorities': [],
            'additionals': []
        }
        encoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(encoded)
        assert len(reparsed.authorities) == 0
        assert len(reparsed.additionals) == 0
        assert reparsed.nscount == 0
        assert reparsed.arcount == 0


# ══════════════════════════════════════════════════════════════
# 测试 10：__main__ 关键路径
# ══════════════════════════════════════════════════════════════

class TestMainPaths:
    """测试 __main__ 关键路径（P0 补全）"""

    def test_decoder_main_stdin_query_a(self, monkeypatch, capsys):
        """dns_decoder stdin 模式：输入 hex，输出包含 www.baidu.com"""
        import dns_decoder as dd
        monkeypatch.setattr(dd, 'INPUT_MODE', 'stdin')
        monkeypatch.setattr(dd, 'OUTPUT_MODE', 'stdout')
        monkeypatch.setattr(dd, 'PRINT_RAW_HEX', True)
        hex_input = ("12 34 01 00 00 01 00 00 00 00 00 00 "
                     "03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01")
        monkeypatch.setattr(sys, 'stdin', io.StringIO(hex_input))
        dd.main()
        captured = capsys.readouterr()
        assert "www.baidu.com" in captured.out
        assert "1234" in captured.out or "0x1234" in captured.out

    def test_decoder_main_file(self, monkeypatch, capsys, tmp_path):
        """dns_decoder file 模式：读取 hex 文件，输出解析结果"""
        import dns_decoder as dd
        hex_file = tmp_path / "test.hex"
        hex_file.write_text(
            "12 34 01 00 00 01 00 00 00 00 00 00 "
            "03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01"
        )
        monkeypatch.setattr(dd, 'INPUT_MODE', 'file')
        monkeypatch.setattr(dd, 'INPUT_FILE', str(hex_file))
        monkeypatch.setattr(dd, 'OUTPUT_MODE', 'stdout')
        monkeypatch.setattr(dd, 'PRINT_RAW_HEX', True)
        dd.main()
        captured = capsys.readouterr()
        assert "www.baidu.com" in captured.out

    def test_decoder_main_file_output_both(self, monkeypatch, capsys, tmp_path):
        """dns_decoder file 模式 OUTPUT_MODE=both：输出到 stdout 和文件"""
        import dns_decoder as dd
        hex_file = tmp_path / "test.hex"
        hex_file.write_text(
            "12 34 01 00 00 01 00 00 00 00 00 00 "
            "03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01"
        )
        json_file = tmp_path / "parsed.json"
        monkeypatch.setattr(dd, 'INPUT_MODE', 'file')
        monkeypatch.setattr(dd, 'INPUT_FILE', str(hex_file))
        monkeypatch.setattr(dd, 'OUTPUT_MODE', 'both')
        monkeypatch.setattr(dd, 'OUTPUT_JSON_FILE', str(json_file))
        monkeypatch.setattr(dd, 'PRINT_RAW_HEX', False)
        dd.main()
        captured = capsys.readouterr()
        assert "www.baidu.com" in captured.out
        assert json_file.exists()
        content = json_file.read_text()
        assert "www.baidu.com" in content

    def test_decoder_main_invalid_hex(self, monkeypatch, capsys):
        """无效 hex 输入应优雅退出"""
        import dns_decoder as dd
        monkeypatch.setattr(dd, 'INPUT_MODE', 'stdin')
        monkeypatch.setattr(dd, 'OUTPUT_MODE', 'stdout')
        monkeypatch.setattr(dd, 'PRINT_RAW_HEX', True)
        monkeypatch.setattr(sys, 'stdin', io.StringIO("zz yy xx"))
        with pytest.raises(SystemExit):
            dd.main()

    def test_coder_main_stdin_query_a(self, monkeypatch, capsys):
        """dns_coder stdin 模式：输入 JSON，输出 hex"""
        import dns_coder as dc
        monkeypatch.setattr(dc, 'INPUT_MODE', 'stdin')
        monkeypatch.setattr(dc, 'OUTPUT_MODE', 'stdout')
        monkeypatch.setattr(dc, 'PRINT_PROGRESS', False)
        parsed = decode_hex("query_a.hex")
        json_input = json.dumps(parsed.to_dict())
        monkeypatch.setattr(sys, 'stdin', io.StringIO(json_input))
        dc.main()
        captured = capsys.readouterr()
        assert "1234" in captured.out.replace(' ', '')

    def test_coder_main_file(self, monkeypatch, capsys, tmp_path):
        """dns_coder file 模式：读取 JSON 文件，输出 hex"""
        import dns_coder as dc
        parsed = decode_hex("query_a.hex")
        json_file = tmp_path / "test.json"
        json_file.write_text(json.dumps(parsed.to_dict()))
        monkeypatch.setattr(dc, 'INPUT_MODE', 'file')
        monkeypatch.setattr(dc, 'INPUT_JSON_FILE', str(json_file))
        monkeypatch.setattr(dc, 'OUTPUT_MODE', 'stdout')
        monkeypatch.setattr(dc, 'PRINT_PROGRESS', False)
        dc.main()
        captured = capsys.readouterr()
        assert "12 34" in captured.out

    def test_coder_verify_roundtrip_match(self, capsys):
        """verify_roundtrip 当 raw_hex 完全匹配时应打印成功消息"""
        parsed = decode_hex("query_a.hex")
        encoded = load_hex("query_a.hex")
        dns_coder.verify_roundtrip(parsed, encoded)
        captured = capsys.readouterr()
        assert "通过" in captured.out or "完全一致" in captured.out

    def test_coder_verify_roundtrip_mismatch(self, capsys):
        """verify_roundtrip 当 raw_hex 不匹配时应提示差异"""
        parsed = decode_hex("query_a.hex")
        encoded = b'\x00' * 12
        dns_coder.verify_roundtrip(parsed, encoded)
        captured = capsys.readouterr()
        assert "不完全一致" in captured.out or "语义等价" in captured.out

    def test_coder_main_invalid_json(self, monkeypatch):
        """无效 JSON 输入应退出"""
        import dns_coder as dc
        monkeypatch.setattr(dc, 'INPUT_MODE', 'stdin')
        monkeypatch.setattr(dc, 'OUTPUT_MODE', 'stdout')
        monkeypatch.setattr(dc, 'PRINT_PROGRESS', False)
        monkeypatch.setattr(sys, 'stdin', io.StringIO("not valid json"))
        with pytest.raises(SystemExit):
            dc.main()


# ══════════════════════════════════════════════════════════════
# 测试 11：压缩指针异常路径
# ══════════════════════════════════════════════════════════════

class TestCompressionErrors:
    """测试压缩指针异常路径（P1 补全）"""

    def test_max_jumps_exceeded(self):
        """链式压缩指针超过 MAX_JUMPS(10) 应抛出 ValueError('循环引用')"""
        data = bytes(b''.join(
            bytes([0xC0, (i + 1) * 2]) for i in range(11)
        ))
        with pytest.raises(ValueError, match="循环引用"):
            dns_common.decode_domain(data, 0)

    def test_ptr_out_of_bounds(self):
        """压缩指针目标偏移超出数据长度应抛出 ValueError('超出')"""
        data = b'\xc0\x10\x00'
        with pytest.raises(ValueError, match="超出"):
            dns_common.decode_domain(data, 0)

    def test_ptr_self_reference(self):
        """压缩指针指向自身应抛出 ValueError('自引用')"""
        data = b'\xc0\x00'
        with pytest.raises(ValueError, match="自引用"):
            dns_common.decode_domain(data, 0)


# ══════════════════════════════════════════════════════════════
# 测试 12：压缩模式控制
# ══════════════════════════════════════════════════════════════

class TestCompressionModes:
    """测试 use_compression={{True,False}}（P1 补全）"""

    def test_uncompressed_semantic_equiv_response_a(self):
        """use_compression=False 时语义等价"""
        data = load_hex("response_a.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed, use_compression=False)
        reparsed = dns_decoder.decode(reencoded)
        assert_semantic_equal(parsed, reparsed)

    def test_uncompressed_semantic_equiv_compressed(self):
        """多 answer 且禁用压缩时语义等价"""
        data = load_hex("compressed.hex")
        parsed = dns_decoder.decode(data)
        reencoded = dns_coder.encode_message(parsed, use_compression=False)
        reparsed = dns_decoder.decode(reencoded)
        assert_semantic_equal(parsed, reparsed)
        assert len(reparsed.answers) == 2

    def test_uncompressed_vs_compressed_question(self):
        """禁用/启用压缩都不影响 question 解析"""
        data = load_hex("response_a.hex")
        parsed = dns_decoder.decode(data)
        u_parsed = dns_decoder.decode(
            dns_coder.encode_message(parsed, use_compression=False))
        c_parsed = dns_decoder.decode(
            dns_coder.encode_message(parsed, use_compression=True))
        assert u_parsed.questions == c_parsed.questions

    def test_uncompressed_longer_than_compressed(self):
        """禁用压缩时报文更长（域名完整而非指针）"""
        data = load_hex("response_a.hex")
        parsed = dns_decoder.decode(data)
        uncompressed = dns_coder.encode_message(parsed, use_compression=False)
        compressed = dns_coder.encode_message(parsed, use_compression=True)
        assert len(uncompressed) > len(compressed)

    def test_uncompressed_with_authorities(self):
        """禁用压缩时 authorities/additionals 依然语义等价"""
        parsed = TestAuthoritiesAdditionals()._build_full_response()
        encoded = dns_coder.encode_message(parsed, use_compression=False)
        reparsed = dns_decoder.decode(encoded)
        assert len(reparsed.authorities) == 2
        assert len(reparsed.additionals) == 2
        for i in range(2):
            assert reparsed.authorities[i].rdata == parsed.authorities[i].rdata
            assert reparsed.additionals[i].rdata == parsed.additionals[i].rdata


# ══════════════════════════════════════════════════════════════
# 测试 13：SRV 记录编解码
# ══════════════════════════════════════════════════════════════

class TestSRVRecord:
    """测试 SRV 记录（type=33）编解码（P2 补全）"""

    def test_encode_srv_as_hex(self):
        """SRV rdata 以 hex 字符串传入应正确解码为字节"""
        priority = struct.pack('!H', 10)
        weight = struct.pack('!H', 20)
        port = struct.pack('!H', 80)
        target = dns_coder.encode_domain('www.example.com')
        rdata_bytes = priority + weight + port + target
        hex_rdata = rdata_bytes.hex()
        encoded = dns_coder.encode_rdata(hex_rdata, 33, 'SRV')
        assert encoded == rdata_bytes

    def test_decode_srv_returns_hex(self):
        """SRV 记录无专用解析器，解析返回 hex 字符串"""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        question = dns_coder.encode_domain('example.com') + struct.pack('!HH', 33, 1)
        name = dns_coder.encode_domain('example.com')
        rdata = struct.pack('!HHH', 10, 20, 80) + dns_coder.encode_domain('target.com')
        rdlen = len(rdata)
        answer = name + struct.pack('!HHIH', 33, 1, 300, rdlen) + rdata
        data = header + question + answer

        parsed = dns_decoder.decode(data)
        assert parsed.answers[0].type == 33
        assert parsed.answers[0].type_str == 'SRV'
        assert isinstance(parsed.answers[0].rdata, str)

    def test_srv_roundtrip(self):
        """SRV 记录 decode --> encode --> decode 语义一致"""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        question = dns_coder.encode_domain('example.com') + struct.pack('!HH', 33, 1)
        name = dns_coder.encode_domain('example.com')
        rdata = struct.pack('!HHH', 10, 20, 80) + dns_coder.encode_domain('target.com')
        rdlen = len(rdata)
        answer = name + struct.pack('!HHIH', 33, 1, 300, rdlen) + rdata
        original = header + question + answer

        parsed = dns_decoder.decode(original)
        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        assert reparsed.answers[0].rdata == parsed.answers[0].rdata


# ══════════════════════════════════════════════════════════════
# 测试 14：RCODE 值覆盖
# ══════════════════════════════════════════════════════════════

class TestRCODEValues:
    """验证所有 RCODE 值的解析（P2 补全）"""

    @pytest.mark.parametrize("rcode,expected_str", [
        (0, 'NoError'),
        (1, 'FormErr'),
        (2, 'ServFail'),
        (3, 'NXDomain'),
        (4, 'NotImp'),
        (5, 'Refused'),
        (6, 'Unknown'),
        (15, 'Unknown'),
    ])
    def test_rcode_parsing(self, rcode, expected_str):
        """修改 query_a.hex 的 rcode 位验证解析"""
        data = bytearray(load_hex("query_a.hex"))
        orig_flags = struct.unpack('!H', data[2:4])[0]
        new_flags = (orig_flags & 0xFFF0) | rcode
        data[2:4] = struct.pack('!H', new_flags)
        parsed = dns_decoder.decode(bytes(data))
        assert parsed.header.rcode == rcode
        assert parsed.header.rcode_str == expected_str


# ══════════════════════════════════════════════════════════════
# 测试 15：encode_rdata fallback 分支 + parse_rdata 未知类型
# ══════════════════════════════════════════════════════════════

class TestFallbackBranches:
    """测试 encode_rdata 各类型的 fallback 分支及 parse_rdata 未知类型（P3 补全）"""

    def test_a_fallback_non_string(self):
        """A 记录 rdata 非字符串时返回 b'\\x00\\x00\\x00\\x00'"""
        assert dns_coder.encode_rdata(123, 1, 'A') == b'\x00\x00\x00\x00'

    def test_aaaa_fallback_non_string(self):
        """AAAA 记录 rdata 非字符串时返回 b'\\x00' * 16"""
        assert dns_coder.encode_rdata(None, 28, 'AAAA') == b'\x00' * 16

    def test_cname_fallback_non_string(self):
        assert dns_coder.encode_rdata(42, 5, 'CNAME') == b'\x00'

    def test_ns_fallback_non_string(self):
        assert dns_coder.encode_rdata([], 2, 'NS') == b'\x00'

    def test_ptr_fallback_non_string(self):
        assert dns_coder.encode_rdata({}, 12, 'PTR') == b'\x00'

    def test_mx_fallback_non_dict(self):
        """MX 记录 rdata 非 dict 时返回 b'\\x00\\x00\\x00'"""
        assert dns_coder.encode_rdata("string_not_dict", 15, 'MX') == b'\x00\x00\x00'

    def test_txt_fallback_non_string(self):
        assert dns_coder.encode_rdata(True, 16, 'TXT') == b'\x00'

    def test_soa_fallback_non_dict(self):
        """SOA 记录 rdata 非 dict 时返回 b'\\x00' * 20"""
        assert dns_coder.encode_rdata("bad", 6, 'SOA') == b'\x00' * 20

    @pytest.mark.parametrize("bad_rdata,expected", [
        (None, b''),
        (123, b''),
        ({}, b''),
    ])
    def test_unknown_type_fallback(self, bad_rdata, expected):
        """未知类型且非 hex 字符串时返回空字节"""
        assert dns_coder.encode_rdata(bad_rdata, 99, 'Unknown') == expected

    def test_parse_unknown_type_returns_hex(self):
        """parse_rdata 对未知类型应返回 hex 字符串"""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        question = dns_coder.encode_domain('test.com') + struct.pack('!HH', 1, 1)
        name = dns_coder.encode_domain('test.com')
        rdata = b'\xde\xad\xbe\xef'
        answer = name + struct.pack('!HHIH', 99, 1, 300, 4) + rdata
        data = header + question + answer

        parsed = dns_decoder.decode(bytes(data))
        assert parsed.answers[0].rdata == 'deadbeef'

    def test_unknown_type_roundtrip(self):
        """未知类型通过 hex 字符串可往返"""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        question = dns_coder.encode_domain('test.com') + struct.pack('!HH', 1, 1)
        name = dns_coder.encode_domain('test.com')
        rdata = b'\xde\xad\xbe\xef'
        answer = name + struct.pack('!HHIH', 99, 1, 300, 4) + rdata
        original = header + question + answer

        parsed = dns_decoder.decode(original)
        reencoded = dns_coder.encode_message(parsed)
        reparsed = dns_decoder.decode(reencoded)
        assert reparsed.answers[0].rdata == 'deadbeef'
        assert reparsed.answers[0].type == 99


# ══════════════════════════════════════════════════════════════
# 测试 16：dns_resolver.build_query
# ══════════════════════════════════════════════════════════════

class TestResolverBuildQuery:
    """验证 dns_resolver.build_query 构造的查询报文"""

    def test_query_a_length(self):
        data = dns_common.build_query("www.baidu.com", "A")
        # 12 header + 15 name + 4 qtype/qclass = 31
        assert len(data) == 31

    def test_query_mx_length(self):
        data = dns_common.build_query("baidu.com", "MX")
        # 12 header + 11 name + 4 = 27
        assert len(data) == 27

    def test_query_header_fields(self):
        data = dns_common.build_query("test.com", "A")
        txid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
        assert txid == 0x1234
        assert flags == 0x0100
        assert qd == 1
        assert an == ns == ar == 0

    def test_query_decodes_correctly(self):
        data = dns_common.build_query("www.baidu.com", "A")
        parsed = dns_decoder.decode(data)
        assert parsed.questions[0].qname == 'www.baidu.com'
        assert parsed.questions[0].qtype_str == 'A'
        assert parsed.qdcount == 1

    def test_all_query_types(self):
        for qtype in ('A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT'):
            data = dns_common.build_query("example.com", qtype)
            parsed = dns_decoder.decode(data)
            assert parsed.questions[0].qtype_str == qtype, \
                f"QTYPE {qtype} 不匹配"


# ══════════════════════════════════════════════════════════════
# 测试 17：dns_resolver.resolve（mock socket）
# ══════════════════════════════════════════════════════════════

class TestResolver:
    """通过 mock socket 验证 dns_resolver.resolve 核心逻辑"""

    RESPONSE_BYTES = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' \
                     b'\x03www\x05baidu\x03com\x00\x00\x01\x00\x01' \
                     b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\xa8\x00\x01'
    QUERY_BYTES = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                  b'\x03www\x05baidu\x03com\x00\x00\x01\x00\x01'

    @patch('socket.socket')
    def test_resolve_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (self.RESPONSE_BYTES, ('8.8.8.8', 53))
        mock_socket_cls.return_value = mock_sock

        result = dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)
        assert result == self.RESPONSE_BYTES

    @patch('socket.socket')
    def test_resolve_sends_correct_data(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (self.RESPONSE_BYTES, ('8.8.8.8', 53))
        mock_socket_cls.return_value = mock_sock

        dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)
        mock_sock.sendto.assert_called_once_with(
            self.QUERY_BYTES, ('8.8.8.8', 53))

    @patch('socket.socket')
    def test_resolve_timeout(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout('timed out')
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(socket.timeout):
            dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)

    @patch('socket.socket')
    def test_resolve_os_error(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = OSError('Network unreachable')
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(OSError):
            dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)

    @patch('socket.socket')
    def test_resolve_empty_response(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b'', ('8.8.8.8', 53))
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(ValueError, match='空响应'):
            dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)

    @patch('socket.socket')
    def test_resolve_large_response(self, mock_socket_cls):
        mock_sock = MagicMock()
        large = b'\x00' * 512
        mock_sock.recvfrom.return_value = (large, ('8.8.8.8', 53))
        mock_socket_cls.return_value = mock_sock

        result = dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)
        assert len(result) == 512

    @patch('socket.socket')
    def test_resolve_socket_closed(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (self.RESPONSE_BYTES, ('8.8.8.8', 53))
        mock_socket_cls.return_value = mock_sock

        dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)
        mock_sock.close.assert_called_once()

    @patch('socket.socket')
    def test_resolve_socket_closed_on_error(self, mock_socket_cls):
        """即使异常退出，socket 也应关闭"""
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = OSError('fail')
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(OSError):
            dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 5)
        mock_sock.close.assert_called_once()

    @patch('socket.socket')
    def test_resolve_timeout_set(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (self.RESPONSE_BYTES, ('8.8.8.8', 53))
        mock_socket_cls.return_value = mock_sock

        dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53, 3.0)
        mock_sock.settimeout.assert_called_once_with(3.0)

    @patch('socket.socket')
    def test_resolve_timeout_set_default(self, mock_socket_cls):
        """不传 timeout 应使用默认值 5.0"""
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (self.RESPONSE_BYTES, ('8.8.8.8', 53))
        mock_socket_cls.return_value = mock_sock

        dns_resolver.resolve(self.QUERY_BYTES, '8.8.8.8', 53)
        mock_sock.settimeout.assert_called_once_with(5.0)


# ══════════════════════════════════════════════════════════════
# 测试 18：dns_resolver.main（主入口路径）
# ══════════════════════════════════════════════════════════════

class TestResolverMain:
    """通过 monkeypatch 验证 dns_resolver.main 各路径"""

    RESPONSE_BYTES = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' \
                     b'\x03www\x05baidu\x03com\x00\x00\x01\x00\x01' \
                     b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\xa8\x00\x01'

    def _patch_resolve(self, monkeypatch, return_value=None, side_effect=None):
        """将 dns_resolver.resolve 替换为 mock"""
        mock_resolve = MagicMock()
        if side_effect is not None:
            mock_resolve.side_effect = side_effect
        else:
            mock_resolve.return_value = return_value or self.RESPONSE_BYTES
        monkeypatch.setattr(dns_resolver, 'resolve', mock_resolve)
        return mock_resolve

    def test_main_success_prints_hex(self, monkeypatch, capsys):
        self._patch_resolve(monkeypatch)
        monkeypatch.setattr(dns_resolver, 'OUTPUT_FILE', '')
        monkeypatch.setattr(dns_resolver, 'QUERY_DOMAIN', 'test.com')
        monkeypatch.setattr(dns_resolver, 'QUERY_TYPE', 'A')

        dns_resolver.main()

        captured = capsys.readouterr()
        assert '收到响应' in captured.out
        assert '12 34' in captured.out

    def test_main_success_prints_length(self, monkeypatch, capsys):
        self._patch_resolve(monkeypatch)
        monkeypatch.setattr(dns_resolver, 'OUTPUT_FILE', '')

        dns_resolver.main()

        captured = capsys.readouterr()
        assert '47 字节' in captured.out

    def test_main_timeout_exits(self, monkeypatch, capsys):
        self._patch_resolve(monkeypatch, side_effect=socket.timeout('timed out'))
        monkeypatch.setattr(dns_resolver, 'OUTPUT_FILE', '')

        with pytest.raises(SystemExit):
            dns_resolver.main()

        captured = capsys.readouterr()
        assert '超时' in captured.out

    def test_main_os_error_exits(self, monkeypatch, capsys):
        self._patch_resolve(monkeypatch, side_effect=OSError('Network error'))
        monkeypatch.setattr(dns_resolver, 'OUTPUT_FILE', '')

        with pytest.raises(SystemExit):
            dns_resolver.main()

        captured = capsys.readouterr()
        assert '网络错误' in captured.out

    def test_main_value_error_exits(self, monkeypatch, capsys):
        self._patch_resolve(monkeypatch, side_effect=ValueError('bad data'))
        monkeypatch.setattr(dns_resolver, 'OUTPUT_FILE', '')

        with pytest.raises(SystemExit):
            dns_resolver.main()

        captured = capsys.readouterr()
        assert '数据错误' in captured.out

    def test_main_saves_output_file(self, monkeypatch, tmp_path):
        self._patch_resolve(monkeypatch)
        out_file = tmp_path / 'resp.hex'
        monkeypatch.setattr(dns_resolver, 'OUTPUT_FILE', str(out_file))

        dns_resolver.main()

        assert out_file.exists()
        content = out_file.read_text(encoding='utf-8')
        assert '12 34' in content

    def test_main_displays_query_info(self, monkeypatch, capsys):
        self._patch_resolve(monkeypatch)
        monkeypatch.setattr(dns_resolver, 'OUTPUT_FILE', '')
        monkeypatch.setattr(dns_resolver, 'QUERY_DOMAIN', 'example.org')
        monkeypatch.setattr(dns_resolver, 'QUERY_TYPE', 'MX')

        dns_resolver.main()

        captured = capsys.readouterr()
        assert 'example.org' in captured.out
        assert 'MX' in captured.out
