#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 迭代解析器 — ResolutionEngine（系统边界）。

Engine 是单次迭代解析请求的系统边界：
1. 检查答案缓存（Answer Cache），命中直接返回
2. 检查委派缓存（Delegation Cache），尝试从缓存的 NS 开始迭代
3. 创建 Task Stack 和 Query Stack，注入 check_cache 回调
4. push 初始域名作为第一个 Task
5. 通过 task_stack.run() 将控制权交给双栈状态机
6. 将解析结果写入缓存

控制权流转：
    Engine → task_stack.run() → query_stack.run() → transport.query()
                                                      ↓ (await 返回)
                                 query_stack.run() ← ─┘
                                   ↓ (FINISHED)
    Engine ← task_stack.run() ← ──┘

缓存集成：
    • resolve() 入口查 Answer Cache，命中直接跳至 ⑥
    • resolve() 成功后写 Answer Cache（取所有 RR 的最小 TTL）
    • resolve() 成功后提取 NS+glue 写 Delegation Cache
    • 注入 _check_cache() 回调，TaskStack 在 CNAME/PAUSED 分支查缓存
"""

from __future__ import annotations

from typing import Optional

from dns_cache import DnsCache, extract_ns_delegations, min_ttl_from_message
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_transport import DnsMessage, Transport


class ResolutionEngine:
    """
    迭代解析器引擎。

    用法:
        transport = AsyncUdpTransport()
        engine = ResolutionEngine(transport, cache=DnsCache())
        result = await engine.resolve("www.baidu.com")
    """

    def __init__(
        self,
        transport: Transport,
        cache: Optional[DnsCache] = None,
    ):
        """
        Args:
            transport: 传输层实例
            cache:     可选的 DnsCache 实例。传入后引擎会自动
                       查/写答案缓存和委派缓存。
        """
        self._transport = transport
        self._cache = cache

    # ── 缓存回调（供 TaskStack 使用） ──────────────────────────

    async def _check_cache(
        self,
        domain: str,
        qtype: int,
    ) -> Optional[DnsMessage]:
        """
        缓存查询回调 — 由 TaskStack 在 CNAME/PAUSED 分支中调用。

        Args:
            domain: 待查域名
            qtype:  查询类型

        Returns:
            命中时返回重建的 DnsMessage，未命中返回 None。
        """
        if self._cache is None:
            return None
        entry = await self._cache.get(domain, qtype, 1)
        if entry is None or entry.is_expired:
            return None
        return entry.to_message()

    # ── 初始化目标查询（支持委派缓存加速） ──────────────────────

    async def _resolve_initial_targets(self, domain: str) -> Optional[list[str]]:
        """
        从委派缓存查找初始目标 IP。

        检查目标域名及其各级父域名的缓存 NS 记录，找到则返回
        对应的 glue A/AAAA IP 列表；未找到返回 None。

        Args:
            domain: 待解析域名

        Returns:
            目标服务器 IP 列表，或 None。
        """
        if self._cache is None:
            return None

        parts = domain.lower().rstrip('.').split('.')
        # 从最长开始匹配（先查完整域名，再逐级缩短）
        for i in range(len(parts)):
            candidate = '.'.join(parts[i:])
            delegation = await self._cache.get_delegation(candidate)
            if delegation is not None:
                ns_records, glue_records = delegation
                targets = [
                    r.rdata for r in glue_records
                    if isinstance(r.rdata, str)
                ]
                if targets:
                    return targets
        return None

    # ── 主入口 ────────────────────────────────────────────────

    async def resolve(self, domain: str, qtype: int = 1) -> Optional[DnsMessage]:
        """
        对指定域名执行迭代解析（带缓存）。

        流程:
            ① 查 Answer Cache → 命中直接返回
            ② 查 Delegation Cache → 命中则跳过根服务器阶段
            ③ 创建 QueryStack + TaskStack（注入 check_cache 回调）
            ④ task_stack.run()
            ⑤ 写 Answer Cache + Delegation Cache
            ⑥ 返回结果

        Args:
            domain: 待解析的域名
            qtype:  查询类型数值（1=A, 28=AAAA 等，默认 1）

        Returns:
            成功时返回 DNS 响应报文（DnsMessage）；
            失败时返回 None。
        """
        # ── ① Answer Cache ────────────────────────────────────
        if self._cache is not None:
            cached = await self._cache.get_answer(domain, qtype)
            if cached is not None:
                return cached

        # ── ② Delegation Cache ────────────────────────────────
        initial_targets = await self._resolve_initial_targets(domain)

        # ── ③ 创建双栈 ────────────────────────────────────────
        query_stack = QueryStack(self._transport)
        task_stack = TaskStack(
            cache_callback=self._check_cache if self._cache else None,
            initial_targets=initial_targets,
        )
        task_stack.push(domain)

        # ── ④ 迭代解析 ────────────────────────────────────────
        result = await task_stack.run(query_stack, qtype)

        # ── ⑤ 写缓存 ──────────────────────────────────────────
        if self._cache is not None and result is not None:
            # 答案缓存
            ttl = min_ttl_from_message(result)
            await self._cache.set_answer(domain, qtype, 1, result, ttl=ttl)
            # 委派缓存（从 Authority 提取 NS+glue）
            delegations = extract_ns_delegations(result)
            for ns_domain, (ns_records, glue_records) in delegations.items():
                await self._cache.set_delegation(
                    ns_domain, ns_records, glue_records,
                )

        # ── ⑥ 返回 ────────────────────────────────────────────
        return result
