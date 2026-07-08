#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 缓存层 — 答案缓存 + 负缓存 + 委派缓存。

提供 CacheEntry 数据类和 DnsCache 容器，支持 TTL 过期、并发安全、
负缓存（NXDOMAIN/SERVFAIL），以及从 DnsMessage 提取缓存数据的工具函数。

用法:
    cache = DnsCache()
    # 查缓存
    entry = await cache.get("www.example.com", 1, 1)
    if entry and not entry.is_expired:
        msg = entry.to_message()
    # 写缓存
    await cache.set_answer("www.example.com", 1, 1, response_msg)
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from dns_types import DnsMessage, DnsResourceRecord

# ══════════════════════════════════════════════════════════════════
# 缓存条目
# ══════════════════════════════════════════════════════════════════


@dataclass
class CacheEntry:
    """一条 DNS 缓存条目。"""

    domain: str  # 查询域名（小写）
    qtype: int  # 查询类型
    qclass: int  # 查询类别（通常 1=IN）
    answers: List[DnsResourceRecord] = field(default_factory=list)
    authorities: List[DnsResourceRecord] = field(default_factory=list)
    additionals: List[DnsResourceRecord] = field(default_factory=list)
    rcode: int = 0
    expires_at: float = 0.0  # time.time() + ttl
    is_negative: bool = False

    # ── 属性 ──────────────────────────────────────────────────────

    @property
    def is_expired(self) -> bool:
        """是否已过期。"""
        return time.time() >= self.expires_at

    @property
    def ttl_remaining(self) -> float:
        """剩余存活秒数（<=0 表示已过期）。"""
        return max(0.0, self.expires_at - time.time())

    # ── 序列化 ────────────────────────────────────────────────────

    def to_message(self, query_msg: Optional[DnsMessage] = None) -> DnsMessage:
        """
        重建为 DnsMessage 响应报文。

        若提供 query_msg，则复制其 header.id / opcode / rd 等字段，
        并填充 questions 列表，使得重建的报文可作为合法 DNS 响应发送。
        """
        if query_msg is not None:
            return DnsMessage.create_response(
                query_msg,
                answers=self.answers,
                authorities=self.authorities,
                additionals=self.additionals,
                rcode=self.rcode,
            )
        # 没有原始查询时构造一个最小响应
        msg = DnsMessage(
            answers=list(self.answers),
            authorities=list(self.authorities),
            additionals=list(self.additionals),
        )
        msg.header.qr = 1
        msg.header.rcode = self.rcode
        msg.header.ra = 1
        return msg

    @classmethod
    def from_message(
        cls,
        msg: DnsMessage,
        ttl: Optional[int] = None,
        is_negative: bool = False,
    ) -> 'CacheEntry':
        """
        从 DnsMessage 构建缓存条目。

        Args:
            msg:         DNS 响应报文
            ttl:         缓存 TTL（秒），默认取 msg 中所有 RR 的最小 TTL
            is_negative: 是否为负缓存
        """
        if ttl is None:
            ttl = min_ttl_from_message(msg)

        # 从第一个 question 提取 key 信息
        domain = msg.questions[0].qname.lower() if msg.questions else ''
        qtype = msg.questions[0].qtype if msg.questions else 1
        qclass = msg.questions[0].qclass if msg.questions else 1

        return cls(
            domain=domain,
            qtype=qtype,
            qclass=qclass,
            answers=list(msg.answers),
            authorities=list(msg.authorities),
            additionals=list(msg.additionals),
            rcode=msg.header.rcode,
            expires_at=time.time() + ttl,
            is_negative=is_negative,
        )


# ══════════════════════════════════════════════════════════════════
# 缓存容器
# ══════════════════════════════════════════════════════════════════


def _make_key(domain: str, qtype: int, qclass: int = 1) -> str:
    """将 (domain, qtype, qclass) 三元组编码为字典键。"""
    return f"{domain.lower()}|{qtype}|{qclass}"


class DnsCache:
    """
    DNS 缓存容器。

    线程安全（asyncio.Lock），支持 TTL 过期懒清理、负缓存。
    同一容器可同时用作 Answer Cache 和 Delegation Cache。
    """

    def __init__(self) -> None:
        self._store: Dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    # ── 核心读写 ──────────────────────────────────────────────────

    async def get(
        self,
        domain: str,
        qtype: int,
        qclass: int = 1,
    ) -> Optional[CacheEntry]:
        """
        获取缓存条目。

        若条目已过期则自动删除并返回 None（懒清理）。
        """
        key = _make_key(domain, qtype, qclass)
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry.is_expired:
                del self._store[key]
                return None
            return entry

    async def set(
        self,
        domain: str,
        qtype: int,
        qclass: int,
        entry: CacheEntry,
    ) -> None:
        """写入缓存条目。"""
        key = _make_key(domain, qtype, qclass)
        async with self._lock:
            self._store[key] = entry

    async def delete(
        self,
        domain: str,
        qtype: int,
        qclass: int = 1,
    ) -> bool:
        """删除缓存条目，返回是否存在。"""
        key = _make_key(domain, qtype, qclass)
        async with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    # ── 批量操作 ──────────────────────────────────────────────────

    async def clear_expired(self) -> int:
        """
        清理所有已过期的条目。

        Returns:
            被清理的条目数量。
        """
        now = time.time()
        async with self._lock:
            expired_keys = [k for k, v in self._store.items() if now >= v.expires_at]
            for k in expired_keys:
                del self._store[k]
            return len(expired_keys)

    async def clear(self) -> None:
        """清空全部缓存。"""
        async with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        """当前缓存条目数（含已过期但尚未清理的）。"""
        return len(self._store)

    # ── 答案缓存便捷方法 ─────────────────────────────────────────

    async def get_answer(
        self,
        domain: str,
        qtype: int,
        qclass: int = 1,
    ) -> Optional[DnsMessage]:
        """
        获取缓存的 DNS 答案。

        返回重建的 DnsMessage，或 None。
        """
        entry = await self.get(domain, qtype, qclass)
        if entry is None:
            return None
        return entry.to_message()

    async def set_answer(
        self,
        domain: str,
        qtype: int,
        qclass: int,
        msg: DnsMessage,
        ttl: Optional[int] = None,
        is_negative: bool = False,
    ) -> None:
        """
        从 DnsMessage 写入答案缓存。

        Args:
            domain:      查询域名
            qtype:       查询类型
            qclass:      查询类别
            msg:         DNS 响应报文
            ttl:         缓存 TTL（秒），默认取 msg 中最小 TTL
            is_negative: 是否为负缓存
        """
        entry = CacheEntry.from_message(msg, ttl=ttl, is_negative=is_negative)
        # 确保 key 与实际数据一致（可能 msg.questions 为空）
        entry.domain = domain.lower()
        entry.qtype = qtype
        entry.qclass = qclass
        await self.set(domain, qtype, qclass, entry)

    # ── 委派缓存便捷方法 ─────────────────────────────────────────

    async def get_delegation(
        self,
        domain: str,
    ) -> Optional[Tuple[List[DnsResourceRecord], List[DnsResourceRecord]]]:
        """
        获取委派缓存（NS 记录 + glue A/AAAA）。

        Returns:
            (ns_records, glue_records) 或 None。
        """
        entry = await self.get(domain, 2, 1)  # qtype=2=NS
        if entry is None:
            return None
        return (list(entry.answers), list(entry.additionals))

    async def set_delegation(
        self,
        domain: str,
        ns_records: List[DnsResourceRecord],
        glue_records: List[DnsResourceRecord],
        ttl: int = 3600,
    ) -> None:
        """
        写入委派缓存。

        Args:
            domain:       域名
            ns_records:   NS 记录列表
            glue_records: 对应的 A/AAAA glue 记录列表
            ttl:          缓存 TTL（默认 3600s = 1h）
        """
        entry = CacheEntry(
            domain=domain.lower(),
            qtype=2,
            qclass=1,
            answers=ns_records,
            authorities=[],
            additionals=glue_records,
            rcode=0,
            expires_at=time.time() + ttl,
            is_negative=False,
        )
        await self.set(domain, 2, 1, entry)


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════


def min_ttl_from_message(msg: DnsMessage) -> int:
    """
    从 DNS 响应中取所有 RR 的最小 TTL。

    如果没有记录（空响应），返回 60（安全默认值）。
    负缓存（NXDOMAIN）的调用方应单独传入 SOA MINIMUM 或默认值。
    """
    all_rrs = msg.answers + msg.authorities + msg.additionals
    if not all_rrs:
        return 60
    return min(rr.ttl for rr in all_rrs)


def extract_ns_delegations(
    msg: DnsMessage,
) -> Dict[str, Tuple[List[DnsResourceRecord], List[DnsResourceRecord]]]:
    """
    从 DNS 响应中提取 NS 委派信息。

    遍历 Authority 中的 NS 记录，匹配 Additional 中的 A/AAAA glue，
    返回 {domain_lower: (ns_records, glue_records)} 字典。

    Args:
        msg: DNS 响应报文

    Returns:
        字典：域名小写 → (NS 记录列表, glue A/AAAA 记录列表)
    """
    # 收集 Authority 中的 NS 记录
    ns_map: Dict[str, List[DnsResourceRecord]] = defaultdict(list)
    for rr in msg.authorities:
        if rr.type == 2:  # NS
            ns_map[rr.name.lower()].append(rr)

    if not ns_map:
        return {}

    # 收集 Additional 中的 A/AAAA 记录（潜在 glue）
    glue_by_name: Dict[str, List[DnsResourceRecord]] = defaultdict(list)
    for rr in msg.additionals:
        if rr.type in (1, 28):  # A or AAAA
            glue_by_name[rr.name.lower()].append(rr)

    result: Dict[str, Tuple[List[DnsResourceRecord], List[DnsResourceRecord]]] = {}
    for domain, nss in ns_map.items():
        # 找这些 NS 目标域名对应的 glue
        glue: List[DnsResourceRecord] = []
        for ns_rr in nss:
            ns_target = ns_rr.rdata.lower() if isinstance(ns_rr.rdata, str) else ''
            if ns_target in glue_by_name:
                glue.extend(glue_by_name[ns_target])
        result[domain] = (nss, glue)

    return result
