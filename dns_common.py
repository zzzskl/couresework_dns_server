#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 公共模块 — 提供 coder / decoder / client / resolver 共享的
常量映射、域名编码/解码、查询报文构造等基础 API。

所有模块统一从此文件导入，避免重复实现。
"""

import struct
from typing import Any, Dict, List, Tuple

# ══════════════════════════════════════════════════════════════════
# 类型/类/响应码 常量映射
# ══════════════════════════════════════════════════════════════════

QTYPE_MAP = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15,
    'TXT': 16, 'AAAA': 28, 'SRV': 33, 'ANY': 255
}
QTYPE_REVERSE = {v: k for k, v in QTYPE_MAP.items()}

QCLASS_MAP = {'IN': 1, 'CS': 2, 'CH': 3, 'HS': 4, 'ANY': 255}
QCLASS_REVERSE = {v: k for k, v in QCLASS_MAP.items()}

RCODE_MAP = {
    0: 'NoError', 1: 'FormErr', 2: 'ServFail',
    3: 'NXDomain', 4: 'NotImp', 5: 'Refused'
}

# ══════════════════════════════════════════════════════════════════
# 域名编码 / 解码
# ══════════════════════════════════════════════════════════════════


def encode_domain(domain: str) -> bytes:
    """
    将 'www.baidu.com' 转为 DNS 标签格式: b'\\x03www\\x05baidu\\x03com\\x00'
    """
    if not domain:
        return b'\x00'
    # 处理可能的末尾点（如 "www.baidu.com."）
    if domain.endswith('.'):
        domain = domain[:-1]
    # 按点分割，逐标签编码
    result = b''
    for part in domain.split('.'):
        if not part:
            continue
        result += bytes([len(part)]) + part.encode('ascii')
    result += b'\x00'
    return result


def decode_domain(data: bytes, offset: int) -> Tuple[str, int]:
    """
    解析域名（含压缩指针 0xC0 处理），返回 (域名, 新偏移量)。

    对应 decoder 中原 parse_name 函数，改名后统一放在公共模块。
    """
    parts = []
    jumped = False
    jump_back_offset = 0
    jump_count = 0
    MAX_JUMPS = 10

    while offset < len(data):
        length = data[offset]

        # 压缩指针
        if (length & 0xC0) == 0xC0:
            jump_count += 1
            if jump_count > MAX_JUMPS:
                raise ValueError(
                    f"压缩指针跳转次数超过上限 ({MAX_JUMPS})，可能存在循环引用")
            if offset + 1 >= len(data):
                raise ValueError(
                    f"压缩指针越界：偏移 {offset} 处需 2 字节，数据仅 {len(data)} 字节")
            if not jumped:
                jump_back_offset = offset + 2
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr >= len(data):
                raise ValueError(
                    f"压缩指针目标偏移量 {ptr} 超出数据长度 {len(data)}")
            if ptr == offset:
                raise ValueError(
                    f"压缩指针自引用：偏移量 {ptr} 指向自身")
            offset = ptr
            jumped = True
            continue

        # 结束
        if length == 0:
            offset += 1
            if jumped:
                return '.'.join(parts), jump_back_offset
            return '.'.join(parts), offset

        # 普通标签
        offset += 1
        parts.append(data[offset:offset + length].decode('ascii', errors='ignore'))
        offset += length

    return '.'.join(parts), offset


# ══════════════════════════════════════════════════════════════════
# 查询报文构造
# ══════════════════════════════════════════════════════════════════


def build_query(domain: str, qtype: str = "A") -> bytes:
    # noqa: D401
    """
    构造 DNS 查询报文。

    .. deprecated::
        Use ``DnsMessage.create_query(domain, qtype).to_bytes()`` instead.
        此函数保留用于向后兼容，新代码请使用对象层 API。
    """
    import warnings
    warnings.warn(
        "build_query() 已废弃，请使用 DnsMessage.create_query(domain, qtype).to_bytes()",
        DeprecationWarning, stacklevel=2,
    )
    qtype_code = QTYPE_MAP.get(qtype.upper(), 1)

    # Header: ID (0x1234) + Flags (标准查询) + QDCOUNT=1
    header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    # Question: 域名 + QTYPE + QCLASS(IN=1)
    question = encode_domain(domain) + struct.pack('!HH', qtype_code, 1)
    return header + question


def extract_ns_glue_pairs(
    authorities: List[Any],
    additionals: List[Any],
) -> Dict[str, List[Any]]:
    """
    从 DNS 响应的 Authority / Additional 段提取 NS 胶水对。

    遍历 authorities 中的 NS 记录，在 additionals 中匹配同名的 A/AAAA 胶水。
    返回 {ns_domain: [matching_a_aaaa_records]} 映射。

    Args:
        authorities: 权威段的 RR 列表（DnsResourceRecord 或兼容对象）
        additionals: 附加段的 RR 列表（DnsResourceRecord 或兼容对象）

    Returns:
        {ns_domain_lower: [glue_A_AAAA_records]} 每个 NS 域名对应的胶水记录列表
    """
    # 收集 Authority 中的 NS 记录目标域名
    ns_targets: set[str] = set()
    for rr in authorities:
        if rr.rr_type == 2:  # NS
            ns_targets.add(rr.rdata.lower())

    if not ns_targets:
        return {}

    # 收集 Additional 中与 NS 目标域名匹配的 A/AAAA 胶水
    result: Dict[str, List[Any]] = {}
    for rec in additionals:
        if rec.rr_type in (1, 28) and rec.name.lower() in ns_targets:
            result.setdefault(rec.name.lower(), []).append(rec)

    return result


# 各模块请直接从 logger 模块导入 setup_logger，保持职责单一
