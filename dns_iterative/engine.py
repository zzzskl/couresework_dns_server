#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 迭代解析器 — ResolutionEngine（系统边界 + 方法级增强代理）。

Engine 是单次迭代解析请求的系统边界：
1. 检查答案缓存（Answer Cache），命中直接返回
2. 检查委派缓存（Delegation Cache），尝试从缓存的 NS 开始迭代
3. 创建纯 TaskStack 和 QueryStack 实例
4. 通过 _enhance_* 覆写栈的实例方法，注入缓存检测和日志
5. 压初始域名，调用 task_stack.run() 将控制权交给双栈状态机
6. 从 task_stack._result_data 读取结果，写入缓存

控制权流转：
    Engine → task_stack.run() → query_stack.run() → transport.query()
                                                      ↓ (await 返回)
                                 query_stack.run() ← ─┘
                                   ↓ (FINISHED)
    Engine ← task_stack.run() ← ──┘

分层归属:
    Layer 2 — DNS 解析引擎横切增强
    - 实例方法覆写代理（_enhance_task_stack / _enhance_query_stack）
    - 缓存/日志实现
"""

from __future__ import annotations

import logging
from typing import Optional

from dns_common import (
    extract_ns_delegations,
    min_ttl_from_message,
)
from dns_cache import DnsCache
from dns_iterative.consts import ROOT_SERVERS
from dns_iterative.models import TaskResult
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_transport import DnsMessage, Transport

log = logging.getLogger(__name__)


class ResolutionEngine:
    """
    迭代解析器引擎。

    创建纯栈、增强栈实例方法、编排解析流程。

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
            cache:     可选的 DnsCache 实例（同步）。传入后引擎自动
                       查/写答案缓存和委派缓存。
        """
        self._transport = transport
        self._cache = cache

    # ══════════════════════════════════════════════════════════════
    # 方法级增强代理 — 实例方法覆写
    # ══════════════════════════════════════════════════════════════

    def _enhance_task_stack(self, ts: TaskStack) -> None:
        """
        增强 TaskStack 实例。

        覆写方法：
            push(domain)  — 先查同步缓存，命中直接写 _result_data 并 return
            run()         — 进出加日志
        """
        engine = self  # ResolutionEngine 引用（闭包捕获）

        # ── push: 加缓存检测 ────────────────────────────────
        original_push = ts.push

        def cached_push(domain: str) -> None:
            if engine._cache:
                msg = engine._cache.get_answer(domain, ts._qtype)
                if msg is not None:
                    answer_ip = next(
                        (r.rdata for r in msg.answers if r.rr_type in (1, 28)),
                        None,
                    )
                    ts._result_data = TaskResult(response=msg, answer_ip=answer_ip)
                    log.info("Cache HIT for %s", domain)
                    return  # 不压栈，不再将控制权返回栈的 push 流程
            log.info("Queue task: %s", domain)
            original_push(domain)

        ts.push = cached_push

        # ── run: 进出日志 ──────────────────────────────────
        original_run = ts.run

        async def logged_run() -> None:
            log.info("TaskStack.run() start")
            await original_run()
            result_data = ts._result_data
            if result_data and result_data.response:
                log.info(
                    "TaskStack.run() done: %d answers",
                    len(result_data.response.answers),
                )
            elif result_data and result_data.error:
                log.warning("TaskStack.run() error: %s", result_data.error)
            else:
                log.info("TaskStack.run() done: no result")

        ts.run = logged_run

    def _enhance_query_stack(self, qs: QueryStack) -> None:
        """
        增强 QueryStack 实例。

        覆写方法：
            push(frame, targets)  — 加日志
            run()                 — 进出加日志
        """
        # ── push: 加日志 ───────────────────────────────────
        original_push = qs.push

        def logged_push(frame, targets=None) -> None:
            log.info("Query → %s %s", frame.target_ip, frame.domain)
            original_push(frame, targets)

        qs.push = logged_push

        # ── run: 进出日志 ──────────────────────────────────
        original_run = qs.run

        async def logged_run() -> None:
            log.info("QueryStack.run() start")
            await original_run()
            result = qs.consume_result()
            if result and result.response:
                log.info(
                    "QueryStack done: %d answers from %s",
                    len(result.response.answers),
                    result.response.answers[0].name if result.response.answers else "?",
                )
            elif result and result.error:
                log.warning("QueryStack error: %s", result.error)
            else:
                log.info("QueryStack done: no result")

        qs.run = logged_run

    # ══════════════════════════════════════════════════════════════
    # 缓存操作
    # ══════════════════════════════════════════════════════════════

    def _cache_lookup(self, domain: str, qtype: int) -> Optional[DnsMessage]:
        """同步缓存查询（跳过已过期条目）。"""
        if self._cache is None:
            return None
        entry = self._cache.get(domain, qtype, 1)
        if entry is None or entry.is_expired:
            return None
        return entry.to_message()

    def _resolve_initial_targets(self, domain: str) -> Optional[list[str]]:
        """
        从委派缓存查找初始目标 IP。

        检查目标域名及其各级父域名的缓存 NS 记录，找到则返回
        对应的 glue A/AAAA IP 列表；未找到返回 None。
        """
        if self._cache is None:
            return None

        parts = domain.lower().rstrip('.').split('.')
        for i in range(len(parts)):
            candidate = '.'.join(parts[i:])
            delegation = self._cache.get_delegation(candidate)
            if delegation is not None:
                ns_records, glue_records = delegation
                targets = [
                    r.rdata for r in glue_records
                    if isinstance(r.rdata, str)
                ]
                if targets:
                    return targets
        return None

    # ══════════════════════════════════════════════════════════════
    # 主入口
    # ══════════════════════════════════════════════════════════════

    async def resolve(self, domain: str, qtype: int = 1) -> Optional[DnsMessage]:
        """
        对指定域名执行迭代解析（带缓存）。

        流程:
            ① 查 Answer Cache → 命中直接返回
            ② 查 Delegation Cache → 命中则跳过根服务器阶段
            ③ 创建纯 TaskStack + QueryStack
            ④ 注入属性 + 增强栈实例方法
            ⑤ 压初始任务并调用 task_stack.run()
            ⑥ 从 _result_data 读取结果
            ⑦ 写 Answer Cache + Delegation Cache
            ⑧ 返回结果

        Args:
            domain: 待解析的域名
            qtype:  查询类型数值（1=A, 28=AAAA 等，默认 1）

        Returns:
            成功时返回 DNS 响应报文（DnsMessage）；
            失败时返回 None。
        """
        # ── ① Answer Cache ────────────────────────────────────
        if self._cache is not None:
            cached = self._cache.get_answer(domain, qtype)
            if cached is not None:
                return cached

        # ── ② Delegation Cache ────────────────────────────────
        initial_targets = self._resolve_initial_targets(domain)

        # ── ③ 创建纯栈 ───────────────────────────────────────
        query_stack = QueryStack(self._transport)
        task_stack = TaskStack()

        # ── ④ 注入属性 + 增强 ────────────────────────────────
        task_stack._query_stack = query_stack
        task_stack._qtype = qtype
        task_stack._initial_targets = (
            list(initial_targets) if initial_targets else list(ROOT_SERVERS)
        )

        self._enhance_task_stack(task_stack)
        self._enhance_query_stack(query_stack)

        # ── ⑤ 压初始任务并运行 ───────────────────────────────
        task_stack.push(domain)
        await task_stack.run()

        # ── ⑥ 读取结果寄存器 ─────────────────────────────────
        result_data = task_stack._result_data
        result = result_data.response if result_data and result_data.response else None

        # ── ⑦ 写缓存 ─────────────────────────────────────────
        if self._cache is not None and result is not None:
            ttl = min_ttl_from_message(result)
            self._cache.set_answer(domain, qtype, 1, result, ttl=ttl)
            delegations = extract_ns_delegations(result)
            for ns_domain, (ns_records, glue_records) in delegations.items():
                self._cache.set_delegation(
                    ns_domain, ns_records, glue_records,
                )

        # ── ⑧ 返回 ───────────────────────────────────────────
        return result
