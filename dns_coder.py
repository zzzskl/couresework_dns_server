#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 编码器 - 将 decoder 输出的 JSON 数据结构重新编码为二进制 DNS 报文

核心 API: encode_message(), NameCompressor, encode_record()
CLI 入口: 运行 `python dns_coder.py` 或调用 main()
"""


import json
import struct
import sys
import os
from typing import Dict, Any, List, Union, Tuple

# ---------- 常量映射（从公共模块导入）---------
from dns_common import QTYPE_MAP, QCLASS_MAP, encode_domain
from dns_types import DnsMessage


class NameCompressor:
    """DNS 名称压缩表 — 跟踪已编码域名在报文中的偏移量，输出 2 字节压缩指针"""

    def __init__(self, base_offset: int = 12):
        self._table: dict[str, int] = {}  # 域名 → 偏移量

    def register_name(self, name: str, offset: int):
        """注册完整域名及其所有后缀到压缩表（用于 question 域名等）"""
        if not name or name.endswith('.'):
            return
        labels = name.split('.')
        for i in range(len(labels)):
            suffix = '.'.join(labels[i:])
            if suffix not in self._table:
                prefix_len = sum(1 + len(labels[j]) for j in range(i))
                self._table[suffix] = offset + prefix_len

    def encode_name(self, name: str, current_offset: int) -> bytes:
        """
        编码域名：优先输出 2 字节压缩指针 (0xC0 | offset)，否则完整编码并注册。
        current_offset: 此域名在最终报文中的起始位置。
        """
        if not name:
            return b'\x00'
        if name.endswith('.'):
            name = name[:-1]

        # 1. 精确匹配 → 2 字节指针
        if name in self._table:
            ptr = self._table[name]
            return struct.pack('!H', 0xC000 | ptr)

        # 2. 后缀匹配（从最长后缀开始）
        labels = name.split('.')
        for i in range(1, len(labels)):
            suffix = '.'.join(labels[i:])
            if suffix in self._table:
                prefix_bytes = b''
                for label in labels[:i]:
                    prefix_bytes += bytes([len(label)]) + label.encode('ascii')
                ptr = self._table[suffix]
                result = prefix_bytes + struct.pack('!H', 0xC000 | ptr)
                self.register_name(name, current_offset)
                return result

        # 3. 无匹配 → 完整编码并注册全部后缀
        result = encode_domain(name)
        self.register_name(name, current_offset)
        return result


# ---------- 核心编码函数 ----------


def encode_header(header: Dict[str, Any]) -> bytes:
    """
    从 JSON header 还原 12 字节 DNS 头部
    优先使用 flags_raw，若无则根据 qr/opcode/aa/tc/rd/ra/rcode 组合
    """
    # 取各计数值（如果 JSON 中有，否则默认 0）
    qdcount = header.get('qdcount', 0)
    ancount = header.get('ancount', 0)
    nscount = header.get('nscount', 0)
    arcount = header.get('arcount', 0)

    # Transaction ID
    txid_str = header.get('id', '0x1234')
    if isinstance(txid_str, str) and txid_str.startswith('0x'):
        txid = int(txid_str, 16)
    else:
        txid = int(txid_str)

    # Flags: 优先使用 raw
    if 'flags_raw' in header:
        flags_raw = header['flags_raw']
        if isinstance(flags_raw, str) and flags_raw.startswith('0x'):
            flags = int(flags_raw, 16)
        else:
            flags = int(flags_raw)
    else:
        # 手动组合 flags
        flags = 0
        flags |= (header.get('qr', 0) & 1) << 15
        flags |= (header.get('opcode', 0) & 0xF) << 11
        flags |= (header.get('aa', 0) & 1) << 10
        flags |= (header.get('tc', 0) & 1) << 9
        flags |= (header.get('rd', 0) & 1) << 8
        flags |= (header.get('ra', 0) & 1) << 7
        flags |= (header.get('z', 0) & 0x7) << 4
        flags |= (header.get('rcode', 0) & 0xF)

    return struct.pack('!HHHHHH', txid, flags, qdcount, ancount, nscount, arcount)


def encode_question(q: Dict[str, Any]) -> bytes:
    """编码单个 Question"""
    name = q.get('qname', '')
    qtype = q.get('qtype', 1)
    qclass = q.get('qclass', 1)
    # 如果 qtype 是字符串，转成数值
    if isinstance(qtype, str):
        qtype = QTYPE_MAP.get(qtype.upper(), 1)
    if isinstance(qclass, str):
        qclass = QCLASS_MAP.get(qclass.upper(), 1)
    return encode_domain(name) + struct.pack('!HH', qtype, qclass)


def encode_rdata(rdata: Any, rtype: int, rtype_str: str = 'Unknown') -> bytes:
    """
    根据记录类型编码 RDATA
    """
    # 如果 rdata 已经是 hex 字符串（未知类型），直接解码
    if isinstance(rdata, str) and rtype_str == 'Unknown':
        try:
            return bytes.fromhex(rdata.replace(' ', ''))
        except:
            pass

    # 根据类型处理
    rtype_str_upper = rtype_str.upper()

    # A 记录 (IPv4)
    if rtype == 1 or rtype_str_upper == 'A':
        if isinstance(rdata, str):
            parts = rdata.split('.')
            if len(parts) == 4:
                return bytes([int(p) for p in parts])
        return b'\x00\x00\x00\x00'

    # AAAA 记录 (IPv6)
    if rtype == 28 or rtype_str_upper == 'AAAA':
        if isinstance(rdata, str):
            # 支持完整 8 段格式和 RFC 5952 简写格式（如 ::1、2001:db8::1）
            parts = rdata.split(':')
            # 处理 :: 简写 — 计数空段位置并补零
            empty_count = parts.count('')
            if empty_count > 2:  # 最多两个连续冒号
                return b'\x00' * 16
            if empty_count == 1:
                # :: 出现在开头 (parts[0]=='') 或中间 (parts[i]=='')
                idx = parts.index('')
                # 移除空段，补入应有的零段
                parts.pop(idx)
                zeros_needed = 9 - len(parts)
                parts[idx:idx] = ['0'] * zeros_needed
            elif empty_count == 2:
                # :: 单独出现（只有一个元素且为空）
                parts = ['0'] * 8
            if len(parts) == 8:
                result = b''
                for p in parts:
                    if not p:
                        result += b'\x00\x00'
                    else:
                        result += bytes.fromhex(p.zfill(4))
                return result
        return b'\x00' * 16

    # CNAME, NS, PTR (域名)
    if rtype in (2, 5, 12) or rtype_str_upper in ('CNAME', 'NS', 'PTR'):
        if isinstance(rdata, str):
            return encode_domain(rdata)
        return b'\x00'

    # MX 记录
    if rtype == 15 or rtype_str_upper == 'MX':
        if isinstance(rdata, dict):
            pref = rdata.get('preference', 10)
            exchange = rdata.get('exchange', '')
            return struct.pack('!H', pref) + encode_domain(exchange)
        return b'\x00\x00\x00'

    # TXT 记录
    if rtype == 16 or rtype_str_upper == 'TXT':
        if isinstance(rdata, str):
            txt_bytes = rdata.encode('utf-8')
            if len(txt_bytes) > 255:
                # 分段
                result = b''
                for i in range(0, len(txt_bytes), 255):
                    chunk = txt_bytes[i:i+255]
                    result += bytes([len(chunk)]) + chunk
                return result
            return bytes([len(txt_bytes)]) + txt_bytes
        return b'\x00'

    # SOA 记录
    if rtype == 6 or rtype_str_upper == 'SOA':
        if isinstance(rdata, dict):
            result = encode_domain(rdata.get('mname', ''))
            result += encode_domain(rdata.get('rname', ''))
            result += struct.pack('!IIIII',
                rdata.get('serial', 0),
                rdata.get('refresh', 0),
                rdata.get('retry', 0),
                rdata.get('expire', 0),
                rdata.get('minimum', 0)
            )
            return result
        return b'\x00' * 20

    # 未知: 尝试 hex 解码或直接返回空
    if isinstance(rdata, str):
        try:
            return bytes.fromhex(rdata.replace(' ', ''))
        except:
            return b''
    return b''


def encode_record(record: Dict[str, Any]) -> bytes:
    """编码单条 Resource Record (Answer/Authority/Additional)"""
    # Name
    name = record.get('name', '')
    name_bytes = encode_domain(name)

    # Type & Class
    rtype = record.get('type', 1)
    rclass = record.get('class', 1)
    if isinstance(rtype, str):
        rtype = QTYPE_MAP.get(rtype.upper(), 1)
    if isinstance(rclass, str):
        rclass = QCLASS_MAP.get(rclass.upper(), 1)

    # TTL
    ttl = record.get('ttl', 300)

    # RDATA
    rdata = record.get('rdata', '')
    rtype_str = record.get('type_str', 'Unknown')
    rdata_bytes = encode_rdata(rdata, rtype, rtype_str)

    # RDLength
    rdlength = len(rdata_bytes)

    return name_bytes + struct.pack('!HHIH', rtype, rclass, ttl, rdlength) + rdata_bytes


def _encode_rdata_compressed(rdata: Any, rtype: int, rtype_str: str,
                              compressor: NameCompressor, offset: int) -> Tuple[bytes, int]:
    """编码 RDATA，其中的域名走压缩。返回 (bytes, new_offset)"""
    rtype_str_upper = rtype_str.upper()

    # CNAME, NS, PTR — rdata 是域名
    if rtype in (2, 5, 12) or rtype_str_upper in ('CNAME', 'NS', 'PTR'):
        if isinstance(rdata, str):
            result = compressor.encode_name(rdata, offset)
            return result, offset + len(result)
        return b'\x00', offset + 1

    # MX — exchange 是域名
    if rtype == 15 or rtype_str_upper == 'MX':
        if isinstance(rdata, dict):
            pref = rdata.get('preference', 10)
            exchange = rdata.get('exchange', '')
            pref_bytes = struct.pack('!H', pref)
            exch_bytes = compressor.encode_name(exchange, offset + 2)
            return pref_bytes + exch_bytes, offset + 2 + len(exch_bytes)
        return b'\x00\x00\x00', offset + 3

    # SOA — mname, rname 是域名
    if rtype == 6 or rtype_str_upper == 'SOA':
        if isinstance(rdata, dict):
            mname_bytes = compressor.encode_name(rdata.get('mname', ''), offset)
            rname_bytes = compressor.encode_name(rdata.get('rname', ''),
                                                  offset + len(mname_bytes))
            five_ints = struct.pack('!IIIII',
                rdata.get('serial', 0), rdata.get('refresh', 0),
                rdata.get('retry', 0), rdata.get('expire', 0),
                rdata.get('minimum', 0))
            result = mname_bytes + rname_bytes + five_ints
            return result, offset + len(result)
        return b'\x00' * 20, offset + 20

    # 其他类型（A, AAAA, TXT 等）保持原样
    result = encode_rdata(rdata, rtype, rtype_str)
    return result, offset + len(result)


def _encode_record_compressed(record: Dict[str, Any],
                               compressor: NameCompressor,
                               offset: int) -> Tuple[bytes, int]:
    """编码单条 RR，名称和 RDATA 域名走压缩。返回 (bytes, new_offset)"""
    name = record.get('name', '')
    name_bytes = compressor.encode_name(name, offset)
    offset += len(name_bytes)

    rtype = record.get('type', 1)
    rclass = record.get('class', 1)
    if isinstance(rtype, str):
        rtype = QTYPE_MAP.get(rtype.upper(), 1)
    if isinstance(rclass, str):
        rclass = QCLASS_MAP.get(rclass.upper(), 1)

    ttl = record.get('ttl', 300)
    rdata = record.get('rdata', '')
    rtype_str = record.get('type_str', 'Unknown')

    # RDATA 开始于 offset + 10（跳过 type/class/ttl/rdlen 头部）
    rdata_bytes, _ = _encode_rdata_compressed(rdata, rtype, rtype_str, compressor, offset + 10)

    rdlength = len(rdata_bytes)
    header10 = struct.pack('!HHIH', rtype, rclass, ttl, rdlength)
    offset += 10 + rdlength

    return name_bytes + header10 + rdata_bytes, offset


def encode_message(parsed: Union['DnsMessage', Dict[str, Any]],
                  use_compression: bool = True) -> bytes:
    """
    主编码函数: 将 DNS 报文 dict 或 DnsMessage 对象转为二进制 DNS 报文
    use_compression=True 时启用域名压缩
    """
    # 统一为 dict（DnsMessage → to_dict，dict 则拷贝 header 避免副作用）
    if isinstance(parsed, DnsMessage):
        d = parsed.to_dict()
    else:
        # 浅拷贝 header，不修改调用方传入的 dict
        d = dict(parsed)
        if 'header' in d:
            h = dict(d['header'])
            h['qdcount'] = len(d.get('questions', []))
            h['ancount'] = len(d.get('answers', []))
            h['nscount'] = len(d.get('authorities', []))
            h['arcount'] = len(d.get('additionals', []))
            d['header'] = h

    # 编码 header（此时 counts 已正确）
    header_bytes = encode_header(d.get('header', {}))
    result = bytearray(header_bytes)
    offset = 12

    # 压缩器（仅 use_compression=True 时生效）
    compressor = NameCompressor(base_offset=12) if use_compression else None

    # 1. Questions（不压缩，但注册域名供后续 section 引用）
    for q in d.get('questions', []):
        qb = encode_question(q)
        if compressor:
            compressor.register_name(q.get('qname', ''), offset)
        result += qb
        offset += len(qb)

    # 2-4. Answers, Authorities, Additionals（走压缩）
    for section_name in ('answers', 'authorities', 'additionals'):
        for item in d.get(section_name, []):
            if compressor:
                encoded, offset = _encode_record_compressed(item, compressor, offset)
            else:
                encoded = encode_record(item)
                offset += len(encoded)
            result += encoded

    return bytes(result)


# ══════════════════════════════════════════════════════════════════
# CLI 配置与入口（模块级变量作为默认值，可通过 main() 参数覆盖）
# ══════════════════════════════════════════════════════════════════

INPUT_MODE = "file"                 # "file" 或 "stdin"
INPUT_JSON_FILE = "decoder/parsed.json"  # INPUT_MODE="file" 时读取此 JSON 文件
OUTPUT_MODE = "both"                # "stdout", "file_hex", "file_bin", "both"
OUTPUT_HEX_FILE = "coder/output.hex"      # 十六进制文本输出（空格分隔）
OUTPUT_BIN_FILE = "coder/output.bin"      # 原始二进制输出
PRINT_PROGRESS = True               # 是否打印编码过程


# ---------- 输入加载 ----------
def load_input(
    input_mode: str = INPUT_MODE,
    input_json_file: str = INPUT_JSON_FILE,
) -> Dict[str, Any]:
    """根据配置加载 JSON 数据"""
    if input_mode == "stdin":
        print("[*] 等待从标准输入 (stdin) 粘贴 JSON，按 Ctrl+D 结束...")
        content = sys.stdin.read()
        return json.loads(content)
    elif input_mode == "file":
        if not os.path.exists(input_json_file):
            raise FileNotFoundError(f"找不到输入文件: {input_json_file}")
        with open(input_json_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        raise ValueError("INPUT_MODE 必须是 'file' 或 'stdin'")


# ---------- 输出导出 ----------
def export_output(
    binary_data: bytes,
    output_mode: str = OUTPUT_MODE,
    output_hex_file: str = OUTPUT_HEX_FILE,
    output_bin_file: str = OUTPUT_BIN_FILE,
):
    """根据配置输出编码结果"""
    hex_str = ' '.join(f'{b:02x}' for b in binary_data)

    if output_mode in ("stdout", "both"):
        print("\n" + "=" * 60)
        print("编码结果 (Hex):")
        print("=" * 60)
        print(hex_str)
        print(f"\n[+] 总长度: {len(binary_data)} 字节")

    if output_mode in ("file_hex", "both"):
        out_dir = os.path.dirname(output_hex_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_hex_file, 'w', encoding='utf-8') as f:
            f.write(hex_str)
        print(f"\n[+] Hex 已保存至: {output_hex_file}")

    if output_mode in ("file_bin", "both"):
        out_dir = os.path.dirname(output_bin_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_bin_file, 'wb') as f:
            f.write(binary_data)
        print(f"[+] 二进制已保存至: {output_bin_file}")


# ---------- 可选：往返校验 ----------
def verify_roundtrip(original_parsed, encoded_data: bytes):
    """
    如果原始数据中包含 raw_hex，对比编码后的 hex 是否一致
    （use_compression=True 时，支持压缩指针的精确往返）
    """
    # 兼容 DnsMessage 和 dict
    if hasattr(original_parsed, 'raw_hex'):
        raw_hex = original_parsed.raw_hex
    else:
        raw_hex = original_parsed.get('raw_hex')

    if not raw_hex:
        return

    original_hex = raw_hex.replace(' ', '')
    encoded_hex = encoded_data.hex()

    if original_hex == encoded_hex:
        print("\n[✓] 往返校验通过: 编码结果与原始 Hex 完全一致！")
    else:
        print("\n[!] 往返校验: 编码结果与原始 Hex 不完全一致（可能因域名压缩格式不同，但语义等价）")
        print(f"    原始长度: {len(original_hex)//2} 字节，编码长度: {len(encoded_hex)//2} 字节")


# ---------- 主入口 ----------
def main(
    input_mode: str = INPUT_MODE,
    input_json_file: str = INPUT_JSON_FILE,
    output_mode: str = OUTPUT_MODE,
    output_hex_file: str = OUTPUT_HEX_FILE,
    output_bin_file: str = OUTPUT_BIN_FILE,
    print_progress: bool = PRINT_PROGRESS,
):
    """编码器主入口：加载 JSON → 编码 → 导出 → 校验"""
    try:
        print("[*] DNS 编码器启动...")
        if print_progress:
            print(f"[*] 输入模式: {input_mode}, 输出模式: {output_mode}")

        # 1. 加载 JSON
        parsed_data = load_input(input_mode, input_json_file)
        if print_progress:
            print(f"[+] JSON 加载成功")

        # 2. 编码为二进制
        binary_output = encode_message(parsed_data)
        if print_progress:
            print(f"[+] 编码完成，生成 {len(binary_output)} 字节")

        # 3. 导出
        export_output(binary_output, output_mode, output_hex_file, output_bin_file)

        # 4. 可选校验
        verify_roundtrip(parsed_data, binary_output)

        print("\n[*] 编码器执行完毕")

    except json.JSONDecodeError as e:
        print(f"[-] JSON 解析错误: {e}")
        print("    请确保输入的 JSON 格式正确")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()