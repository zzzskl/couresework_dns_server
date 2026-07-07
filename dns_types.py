#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 类型系统 — 基于 dataclass 的 DNS 报文结构化表示。

提供 DnsHeader / DnsQuestion / DnsResourceRecord / DnsMessage 类型，
以及 <-> dict 的桥接方法，保持与现有 coder/decoder 的 dict 接口完全兼容。

用法:
    msg = DnsMessage.from_dict(decode(raw_bytes))
    msg.header.qr = 1
    msg.answers.append(...)
    data = encode_message(msg.to_dict())
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional, Union

from dns_common import QTYPE_MAP, QCLASS_MAP, RCODE_MAP, encode_domain


# ══════════════════════════════════════════════════════════════════
# 辅助工具
# ══════════════════════════════════════════════════════════════════


def _hex_id(value: Any) -> str:
    """将 id 字段统一转为 '0x....' 格式的字符串"""
    if isinstance(value, str):
        if value.startswith('0x') or value.startswith('0X'):
            return value.lower()
        return f'0x{int(value):04x}'
    return f'0x{int(value):04x}'


def _parse_id(value: Any) -> int:
    """从字符串或 int 解析 id 字段为 int"""
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.startswith('0x'):
        return int(value, 16)
    return int(value)



# ══════════════════════════════════════════════════════════════════
# 类型定义
# ══════════════════════════════════════════════════════════════════


@dataclass
class DnsHeader:
    """DNS 报文头部 (12 字节 + 衍生字段)"""
    id: int = 0x1234
    qr: int = 0
    opcode: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 1
    ra: int = 0
    z: int = 0
    rcode: int = 0
    rcode_str: str = ''

    def to_dict(self) -> Dict[str, Any]:
        """转为 dict，兼容现有 decoder→encoder 管道"""
        return {
            'id': _hex_id(self.id),
            'qr': self.qr,
            'opcode': self.opcode,
            'aa': self.aa,
            'tc': self.tc,
            'rd': self.rd,
            'ra': self.ra,
            'z': self.z,
            'rcode': self.rcode,
            'rcode_str': self.rcode_str or RCODE_MAP.get(self.rcode, 'Unknown'),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'DnsHeader':
        """从 dict 构建（兼容 decode 输出）"""
        id_val = _parse_id(d.get('id', '0x1234'))
        rcode_val = int(d.get('rcode', 0))
        rcode_str_val = d.get('rcode_str', RCODE_MAP.get(rcode_val, 'Unknown'))
        return cls(
            id=id_val,
            qr=int(d.get('qr', 0)),
            opcode=int(d.get('opcode', 0)),
            aa=int(d.get('aa', 0)),
            tc=int(d.get('tc', 0)),
            rd=int(d.get('rd', 1)),
            ra=int(d.get('ra', 0)),
            z=int(d.get('z', 0)),
            rcode=rcode_val,
            rcode_str=rcode_str_val,
        )


@dataclass
class DnsQuestion:
    """DNS Question section"""
    qname: str = ''
    qtype: int = 1
    qtype_str: str = ''
    qclass: int = 1
    qclass_str: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'qname': self.qname,
            'qtype': self.qtype,
            'qtype_str': self.qtype_str or QTYPE_MAP.get(self.qtype, 'Unknown'),
            'qclass': self.qclass,
            'qclass_str': self.qclass_str or QCLASS_MAP.get(self.qclass, 'Unknown'),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'DnsQuestion':
        return cls(
            qname=d.get('qname', ''),
            qtype=int(d.get('qtype', 1)),
            qtype_str=d.get('qtype_str', ''),
            qclass=int(d.get('qclass', 1)),
            qclass_str=d.get('qclass_str', ''),
        )


@dataclass
class DnsResourceRecord:
    """DNS Resource Record (Answer / Authority / Additional)"""
    name: str = ''
    type: int = 1
    type_str: str = ''
    rr_class: int = 1
    class_str: str = ''
    ttl: int = 300
    rdata: Any = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.type,
            'type_str': self.type_str or QTYPE_MAP.get(self.type, 'Unknown'),
            'class': self.rr_class,              # 用 'class' 键名兼容现有 pipeline
            'class_str': self.class_str or QCLASS_MAP.get(self.rr_class, 'Unknown'),
            'ttl': self.ttl,
            'rdata': self.rdata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'DnsResourceRecord':
        return cls(
            name=d.get('name', ''),
            type=int(d.get('type', 1)),
            type_str=d.get('type_str', ''),
            rr_class=int(d.get('class', 1)),      # dict 键 'class' → 属性 rr_class
            class_str=d.get('class_str', ''),
            ttl=int(d.get('ttl', 300)),
            rdata=d.get('rdata', ''),
        )

    # ── 工厂方法 ──────────────────────────────────

    @classmethod
    def create_a(cls, name: str, ip: str, ttl: int = 300) -> 'DnsResourceRecord':
        """创建 A 记录"""
        return cls(name=name, type=1, type_str='A', rr_class=1,
                   class_str='IN', ttl=ttl, rdata=ip)

    @classmethod
    def create_aaaa(cls, name: str, ip6: str, ttl: int = 300) -> 'DnsResourceRecord':
        """创建 AAAA 记录"""
        return cls(name=name, type=28, type_str='AAAA', rr_class=1,
                   class_str='IN', ttl=ttl, rdata=ip6)

    @classmethod
    def create_cname(cls, name: str, alias: str, ttl: int = 300) -> 'DnsResourceRecord':
        """创建 CNAME 记录"""
        return cls(name=name, type=5, type_str='CNAME', rr_class=1,
                   class_str='IN', ttl=ttl, rdata=alias)

    @classmethod
    def create_ns(cls, name: str, ns_domain: str, ttl: int = 300) -> 'DnsResourceRecord':
        """创建 NS 记录"""
        return cls(name=name, type=2, type_str='NS', rr_class=1,
                   class_str='IN', ttl=ttl, rdata=ns_domain)

    @classmethod
    def create_mx(cls, name: str, preference: int, exchange: str,
                  ttl: int = 300) -> 'DnsResourceRecord':
        """创建 MX 记录"""
        return cls(name=name, type=15, type_str='MX', rr_class=1,
                   class_str='IN', ttl=ttl,
                   rdata={'preference': preference, 'exchange': exchange})


@dataclass
class DnsMessage:
    """完整的 DNS 报文"""
    header: DnsHeader = field(default_factory=DnsHeader)
    questions: List[DnsQuestion] = field(default_factory=list)
    answers: List[DnsResourceRecord] = field(default_factory=list)
    authorities: List[DnsResourceRecord] = field(default_factory=list)
    additionals: List[DnsResourceRecord] = field(default_factory=list)
    raw_hex: Optional[str] = None

    # ── 计数值：计算属性而非存储字段 ────────────────

    @property
    def qdcount(self) -> int:
        return len(self.questions)

    @property
    def ancount(self) -> int:
        return len(self.answers)

    @property
    def nscount(self) -> int:
        return len(self.authorities)

    @property
    def arcount(self) -> int:
        return len(self.additionals)

    # ── dict 桥接 ──────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """转为完整的 dict（兼容 encode_message 输入）"""
        result: Dict[str, Any] = {}

        # header：包含 count 字段供 encode_header 读取
        hd = self.header.to_dict()
        hd['qdcount'] = self.qdcount
        hd['ancount'] = self.ancount
        hd['nscount'] = self.nscount
        hd['arcount'] = self.arcount
        result['header'] = hd

        result['questions'] = [q.to_dict() for q in self.questions]
        result['answers'] = [a.to_dict() for a in self.answers]
        result['authorities'] = [a.to_dict() for a in self.authorities]
        result['additionals'] = [a.to_dict() for a in self.additionals]

        if self.raw_hex is not None:
            result['raw_hex'] = self.raw_hex

        return result

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'DnsMessage':
        """从 decode 输出的 dict 构建"""
        header = DnsHeader.from_dict(d.get('header', {}))
        questions = [DnsQuestion.from_dict(q) for q in d.get('questions', [])]
        answers = [DnsResourceRecord.from_dict(a) for a in d.get('answers', [])]
        authorities = [DnsResourceRecord.from_dict(a) for a in d.get('authorities', [])]
        additionals = [DnsResourceRecord.from_dict(a) for a in d.get('additionals', [])]
        raw_hex = d.get('raw_hex')

        msg = cls(
            header=header,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
            raw_hex=raw_hex,
        )
        return msg

    # ── 工厂方法 ──────────────────────────────────

    @classmethod
    def create_query(cls, domain: str, qtype: str = 'A') -> 'DnsMessage':
        """
        构造标准 DNS 查询报文（等价于 dns_common.build_query 的对象版）。

        参数:
            domain: 查询域名，如 'www.baidu.com'
            qtype:  查询类型，如 'A', 'AAAA', 'MX', 'NS', 'TXT'

        返回:
            DnsMessage 对象，encode 后即为完整 DNS 查询 bytes
        """
        qtype_code = QTYPE_MAP.get(qtype.upper(), 1)
        return cls(
            header=DnsHeader(
                id=0x1234,
                qr=0,
                opcode=0,
                rd=1,
                rcode=0,
            ),
            questions=[
                DnsQuestion(
                    qname=domain,
                    qtype=qtype_code,
                    qclass=1,
                ),
            ],
            answers=[],
            authorities=[],
            additionals=[],
        )

    @classmethod
    def create_response(cls, query: 'DnsMessage',
                        answers: Optional[List[DnsResourceRecord]] = None,
                        authorities: Optional[List[DnsResourceRecord]] = None,
                        additionals: Optional[List[DnsResourceRecord]] = None,
                        rcode: int = 0,
                        ra: int = 1) -> 'DnsMessage':
        """
        根据查询报文构造标准 DNS 响应报文。

        自动复制查询的 id、opcode、rd，设置 qr=1、ra、rcode。
        questions 列表也从 query 复制，保证响应与查询对应。
        """
        return cls(
            header=DnsHeader(
                id=query.header.id,
                qr=1,
                opcode=query.header.opcode,
                rd=query.header.rd,
                ra=ra,
                rcode=rcode,
            ),
            questions=list(query.questions),
            answers=list(answers or []),
            authorities=list(authorities or []),
            additionals=list(additionals or []),
        )

    def to_bytes(self, use_compression: bool = True) -> bytes:
        """将此报文编码为二进制 DNS 报文（延迟导入避免循环引用）"""
        from dns_coder import encode_message
        return encode_message(self, use_compression=use_compression)


