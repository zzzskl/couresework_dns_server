#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Hex 解码器 - 将 Hex 文本解析为人类可读的数据结构（JSON）

核心 API: decode(), _parse_rdata(), _parse_rr()
CLI 入口: 运行 `python dns_decoder.py` 或调用 main()
"""


import json
import struct
import sys
import os
from typing import Tuple, Any, Dict, List

# ---------- 常量映射（从公共模块导入）---------
from dns_common import QTYPE_REVERSE, QCLASS_REVERSE, RCODE_MAP, decode_domain
from dns_types import DnsMessage

# ══════════════════════════════════════════════════════════════════
# 核心 API — 解码函数
# ══════════════════════════════════════════════════════════════════


def _parse_rdata(data: bytes, offset: int, rtype: int, rdlength: int) -> Tuple[Any, int]:
    end = offset + rdlength
    if rtype == 1:  # A
        return '.'.join(str(b) for b in data[offset:end]), end
    elif rtype == 28:  # AAAA
        return ':'.join(f'{data[offset+i]:02x}{data[offset+i+1]:02x}' for i in range(0,16,2)), end
    elif rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = decode_domain(data, offset)
        return name, end
    elif rtype == 15:  # MX
        pref = struct.unpack('!H', data[offset:offset+2])[0]
        exchange, _ = decode_domain(data, offset+2)
        return {'preference': pref, 'exchange': exchange}, end
    elif rtype == 16:  # TXT — 解析若干 length-prefixed 字符段
        chunks = []
        pos = offset
        while pos < end:
            chunk_len = data[pos]
            pos += 1
            chunks.append(data[pos:pos + chunk_len].decode('utf-8', errors='replace'))
            pos += chunk_len
        return ''.join(chunks), end
    elif rtype == 6:   # SOA — mname, rname, 5 × uint32
        mname, pos = decode_domain(data, offset)
        rname, pos = decode_domain(data, pos)
        serial, refresh, retry, expire, minimum = struct.unpack('!IIIII', data[pos:pos + 20])
        return {
            'mname': mname,
            'rname': rname,
            'serial': serial,
            'refresh': refresh,
            'retry': retry,
            'expire': expire,
            'minimum': minimum
        }, end
    else:
        return data[offset:end].hex(), end

def _parse_rr(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    """解析单条 Resource Record，返回 (dict, new_offset)"""
    name, offset = decode_domain(data, offset)
    rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset + 10])
    offset += 10
    rdata, offset = _parse_rdata(data, offset, rtype, rdlen)
    record = {
        'name': name,
        'type': rtype,
        'type_str': QTYPE_REVERSE.get(rtype, 'Unknown'),
        'class': rclass,
        'class_str': QCLASS_REVERSE.get(rclass, 'Unknown'),
        'ttl': ttl,
        'rdata': rdata
    }
    return record, offset


def decode(data: bytes, include_raw_hex: bool = False) -> DnsMessage:
    if len(data) < 12:
        raise ValueError("数据太短")
    
    # Header
    txid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
    header = {
        'id': hex(txid),
        'qr': (flags>>15)&1,
        'opcode': (flags>>11)&0xF,
        'aa': (flags>>10)&1,
        'tc': (flags>>9)&1,
        'rd': (flags>>8)&1,
        'ra': (flags>>7)&1,
        'rcode': flags & 0xF,
        'rcode_str': RCODE_MAP.get(flags & 0xF, 'Unknown'),
        'qdcount': qd, 'ancount': an, 'nscount': ns, 'arcount': ar
    }
    
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = decode_domain(data, offset)
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        offset += 4
        questions.append({
            'qname': name,
            'qtype': qtype,
            'qtype_str': QTYPE_REVERSE.get(qtype, 'Unknown'),
            'qclass': qclass,
            'qclass_str': QCLASS_REVERSE.get(qclass, 'Unknown')
        })
    
    answers = []
    for _ in range(an):
        rr, offset = _parse_rr(data, offset)
        answers.append(rr)

    authorities = []
    for _ in range(ns):
        rr, offset = _parse_rr(data, offset)
        authorities.append(rr)

    additionals = []
    for _ in range(ar):
        rr, offset = _parse_rr(data, offset)
        additionals.append(rr)

    result = {
        'header': header,
        'questions': questions,
        'answers': answers,
        'authorities': authorities,
        'additionals': additionals
    }
    if include_raw_hex:
        result['raw_hex'] = ' '.join(f'{b:02x}' for b in data)
    return DnsMessage.from_dict(result)



# ══════════════════════════════════════════════════════════════════
# CLI 配置与入口（模块级变量作为默认值，可通过 main() 参数覆盖）
# ══════════════════════════════════════════════════════════════════

INPUT_MODE = "file"            # "file" 或 "stdin"
INPUT_FILE = "server/captured.hex"    # INPUT_MODE="file" 时读取此文件
OUTPUT_MODE = "both"           # "stdout", "file", "both"
OUTPUT_JSON_FILE = "decoder/parsed.json"
PRINT_RAW_HEX = True           # 输出中是否包含原始 Hex（CLI 模式）


# ---------- 加载与输出 ----------
def load_data(
    input_mode: str = INPUT_MODE,
    input_file: str = INPUT_FILE,
) -> bytes:
    if input_mode == "stdin":
        print("[*] 请粘贴 Hex 文本（支持空格/换行），按 Ctrl+D 结束:")
        content = sys.stdin.read()
        return bytes.fromhex(''.join(content.split()))
    elif input_mode == "file":
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        return bytes.fromhex(''.join(content.split()))
    else:
        raise ValueError("INPUT_MODE 必须是 'file' 或 'stdin'")

def output_result(
    result: Dict,
    output_mode: str = OUTPUT_MODE,
    output_json_file: str = OUTPUT_JSON_FILE,
    print_raw_hex: bool = PRINT_RAW_HEX,
):
    indent = 2 if print_raw_hex else None
    json_str = json.dumps(result, indent=indent, ensure_ascii=False)
    
    if output_mode in ("stdout", "both"):
        print("\n" + "="*60)
        print("解析结果:")
        print("="*60)
        print(json_str)
    if output_mode in ("file", "both"):
        out_dir = os.path.dirname(output_json_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_json_file, 'w', encoding='utf-8') as f:
            f.write(json_str)
        print(f"\n[+] 已保存到 {output_json_file}")

# ---------- 主入口 ----------
def main(
    input_mode: str = INPUT_MODE,
    input_file: str = INPUT_FILE,
    output_mode: str = OUTPUT_MODE,
    output_json_file: str = OUTPUT_JSON_FILE,
    print_raw_hex: bool = PRINT_RAW_HEX,
):
    """解码器主入口：加载 hex → 解码 → 输出"""
    try:
        raw = load_data(input_mode, input_file)
        print(f"[+] 加载 {len(raw)} 字节")
        parsed = decode(raw, include_raw_hex=print_raw_hex)
        output_result(parsed.to_dict(), output_mode, output_json_file, print_raw_hex)
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()