#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 迭代解析器 — Task Stack（任务栈）。

Task Stack 是一个有状态的复合对象：
- 传统栈容器，存储 Task 元素
- 自身状态字段（resultData、visited 集、步数计数）
- resultData 用于跨任务数据传递（子→父）

状态机运行逻辑（peek 栈顶 → 按状态执行 → 可能转换状态）：
    NEW     → 构造初始帧 → push 到 Query Stack → PENDING → await query
    PENDING → 读取 Query 的 resultData → 分析 → FINISHED/CNAME/PAUSED
    CNAME   → 读取 Task Stack 的 resultData → pop 自身（瞬移）
    PAUSED  → 读取 Task Stack 的 resultData → 构造新帧 → PENDING → await query
    FINISHED → pop 自身

缓存集成（Phase 3）：
    TaskStack 不直接使用 dns_cache 模块，而是通过 engine 注入的
    cache_callback(domain, qtype) → DnsMessage | None 在 CNAME/
    PAUSED 分支中查缓存，命中则跳过子任务压栈，直接使用缓存结果。
"""

from __future__ import annotations

import logging
from typing import Callable, Coroutine, Optional

from dns_iterative.consts import MAX_DEPTH, MAX_STEPS, ROOT_SERVERS
from dns_iterative.models import Task, TaskResult, TaskStatus
from dns_iterative.query_stack import QueryStack
from dns_transport import DnsMessage, QueryFrame

log = logging.getLogger(__name__)

# 缓存回调类型签名
CacheCallback = Callable[[str, int], Coroutine[None, None, Optional[DnsMessage]]]


class TaskStack:
    """
    任务栈状态机。

    通过 run() 启动主循环，内部通过 peek 栈顶、按状态执行、
    可能转换状态、继续循环的方式驱动解析流程。
    """

    def __init__(
        self,
        cache_callback: Optional[CacheCallback] = None,
        initial_targets: Optional[list[str]] = None,
    ):
        """
        Args:
            cache_callback: engine 传入的缓存查询回调。
                            async (domain, qtype) → DnsMessage | None
            initial_targets: 初始目标服务器 IP 列表（来自委派缓存）。
                            None 表示从根服务器开始。
        """
        self._stack: list[Task] = []
        self._result_data: TaskResult | None = None
        self._visited: set[str] = set()
        self._step_count: int = 0
        self._cache_callback = cache_callback
        self._initial_targets = (
            list(initial_targets) if initial_targets else list(ROOT_SERVERS)
        )

    # ── 外部接口 ──────────────────────────────────────────

    def push(self, domain: str) -> None:
        """
        将域名作为 NEW 任务压入栈顶。

        Raises:
            RuntimeError: 栈深度超过 MAX_DEPTH 上限。
        """
        if len(self._stack) >= MAX_DEPTH:
            raise RuntimeError(
                f"Task Stack 深度超过上限 ({MAX_DEPTH})，"
                f"可能因 CNAME 链或 NS 委派链过长引起。域名: {domain}"
            )
        self._stack.append(Task(domain=domain, status=TaskStatus.NEW))
        self._mark_visited(domain)

    async def run(self, query_stack: QueryStack, qtype: int = 1) -> DnsMessage | None:
        """
        运行任务栈状态机主循环。

        每次循环 peek 栈顶，根据 Task 状态执行对应动作。
        需要网络查询时调用 query_stack.run() 显式交权。

        Args:
            query_stack: Query Stack 实例
            qtype:       查询类型（1=A, 28=AAAA 等）

        Returns:
            成功时返回最终响应的 DnsMessage；
            失败/异常时返回 None。
        """
        while not self._is_empty() and self._step_count < MAX_STEPS:
            self._step_count += 1
            task = self._peek()

            # ── NEW ──────────────────────────────────────
            if task.status == TaskStatus.NEW:
                frame = QueryFrame(self._initial_targets[0], task.domain, qtype)
                query_stack.push(frame, list(self._initial_targets))
                task.status = TaskStatus.PENDING
                await query_stack.run()
                # 交权返回，下一轮 peek 处理 PENDING

            # ── PENDING ──────────────────────────────────
            elif task.status == TaskStatus.PENDING:
                qresult = query_stack.consume_result()
                if qresult is None or qresult.error is not None:
                    self._result_data = TaskResult(
                        error=qresult.error if qresult else "Query Stack 无结果",
                    )
                    task.status = TaskStatus.FINISHED
                    continue
                response = qresult.response

                if self._has_answer(response):
                    self._handle_answer(response, task)
                elif self._has_cname(response):
                    await self._handle_cname(response, task, qtype)
                elif self._has_referral(response):
                    await self._handle_referral(response, task)
                else:
                    # 无法识别的响应（NXDOMAIN、SERVFAIL 等）
                    self._result_data = TaskResult(error="无法识别的 DNS 响应类型")
                    task.status = TaskStatus.FINISHED

            # ── CNAME ────────────────────────────────────
            elif task.status == TaskStatus.CNAME:
                last_task_result = self._consume_last_task_result()
                if last_task_result and last_task_result.response:
                    self._result_data = TaskResult(response=last_task_result.response, answer_ip=last_task_result.answer_ip)
                else:
                    self._result_data = TaskResult(error="CNAME 子任务无有效响应")
                self._pop()  # 瞬移：直接弹栈，继承 IP

            # ── PAUSED ───────────────────────────────────
            elif task.status == TaskStatus.PAUSED:
                last_task_result = self._consume_last_task_result()
                if last_task_result and last_task_result.answer_ip:
                    frame = QueryFrame(last_task_result.answer_ip, task.domain, qtype)
                    query_stack.push(frame)
                    task.status = TaskStatus.PENDING
                    await query_stack.run()
                elif last_task_result and last_task_result.response:
                    # answer_ip 不可用时回退到传播响应本身
                    self._result_data = TaskResult(response=last_task_result.response)
                    task.status = TaskStatus.FINISHED
                else:
                    # 子任务未能获取胶水 IP
                    self._result_data = TaskResult(error="子任务未能解析 NS 服务器 IP")
                    task.status = TaskStatus.FINISHED
                # 下一轮 peek 处理 PENDING

            # ── FINISHED ─────────────────────────────────
            elif task.status == TaskStatus.FINISHED:
                self._pop()

        # 循环结束
        if self._is_empty():
            return self._build_result()
        return None

    # ── 内部栈操作 ──────────────────────────────────────

    def _peek(self) -> Task:
        """查看栈顶元素。"""
        if not self._stack:
            raise RuntimeError("peek 空栈")
        return self._stack[-1]

    def _pop(self) -> Task:
        """弹出栈顶元素并返回。"""
        if not self._stack:
            raise RuntimeError("pop 空栈")
        return self._stack.pop()

    def _is_empty(self) -> bool:
        return len(self._stack) == 0

    def _consume_last_task_result(self) -> TaskResult | None:
        """读取并清空 resultData（栈上最近一次写入的 TaskResult）。"""
        data = self._result_data
        self._result_data = None
        return data

    # ── CNAME 循环检测 ──────────────────────────────────

    def _mark_visited(self, domain: str) -> None:
        self._visited.add(domain)

    def _was_visited(self, domain: str) -> bool:
        return domain in self._visited

    # ── 响应分析 ────────────────────────────────────────

    def _has_answer(self, response: DnsMessage) -> bool:
        """答案段是否有非 CNAME 的有效答案记录。"""
        return any(rec.type != 5 for rec in response.answers)

    def _has_cname(self, response: DnsMessage) -> bool:
        """答案段是否有 CNAME 记录。"""
        return any(rec.type == 5 for rec in response.answers)

    def _has_referral(self, response: DnsMessage) -> bool:
        """权威段是否有 NS 记录（且无胶水——胶水已在 Query 层处理）。"""
        return response.nscount > 0

    # ── 状态转换处理 ────────────────────────────────────

    def _handle_answer(self, response: DnsMessage, task: Task) -> None:
        """PENDING + 收到 A/AAAA 答案 → FINISHED。"""
        task.status = TaskStatus.FINISHED
        # 不变量：确保不会意外覆盖尚未消费的子任务结果
        if self._result_data is not None:
            raise RuntimeError(
                f"_handle_answer 准备覆盖未消费的 _result_data: "
                f"{self._result_data}"
            )
        # 从 answer 段提取第一个 A/AAAA 记录的 IP
        answer_ip = None
        for rec in response.answers:
            if rec.type in (1, 28):  # A or AAAA
                answer_ip = rec.rdata
                break
        self._result_data = TaskResult(response=response, answer_ip=answer_ip)

    async def _handle_cname(self, response: DnsMessage, task: Task,
                            qtype: int) -> None:
        """
        PENDING + 收到 CNAME → 查缓存或压入子任务。

        先通过 cache_callback 查询 CNAME 目标域名是否在缓存中。
        命中则直接使用缓存结果（不压子任务），未命中则正常压栈。
        """
        task.status = TaskStatus.CNAME
        for rec in response.answers:
            if rec.type == 5:  # CNAME
                target = rec.rdata
                if not self._was_visited(target):
                    # ── 查缓存 ──────────────────────────────
                    if self._cache_callback is not None:
                        cached = await self._cache_callback(target, qtype)
                        if cached is not None:
                            # 缓存命中：提取 answer_ip，直接 FINISHED
                            answer_ip = None
                            for r in cached.answers:
                                if r.type in (1, 28):
                                    answer_ip = r.rdata
                                    break
                            self._result_data = TaskResult(
                                response=cached,
                                answer_ip=answer_ip,
                            )
                            task.status = TaskStatus.FINISHED
                            return
                    # ── 缓存未命中：正常压子任务 ────────────
                    self._mark_visited(target)
                    self.push(target)  # NEW
                break

    async def _handle_referral(self, response: DnsMessage,
                               task: Task) -> None:
        """
        PENDING + 收到 NS 无胶水 → 查缓存或压入子任务。

        先通过 cache_callback 查询 NS 目标域名的 IP 是否在缓存中。
        命中则直接使用缓存 IP 恢复查询，未命中则正常压栈解析。
        """
        task.status = TaskStatus.PAUSED
        for rec in response.authorities:
            if rec.type == 2:  # NS
                ns_domain = rec.rdata
                # ── 查缓存 ──────────────────────────────────
                if self._cache_callback is not None:
                    cached = await self._cache_callback(ns_domain, 1)  # 查 A 记录
                    if cached is not None:
                        answer_ip = None
                        for r in cached.answers:
                            if r.type in (1, 28):
                                answer_ip = r.rdata
                                break
                        if answer_ip is not None:
                            self._result_data = TaskResult(
                                response=cached,
                                answer_ip=answer_ip,
                            )
                            return  # 不压子任务，PAUSED 状态会读取 answer_ip
                # ── 缓存未命中：正常压子任务 ────────────────
                self.push(ns_domain)  # NEW
                break

    # ── 结果组装 ────────────────────────────────────────

    def _build_result(self) -> DnsMessage | None:
        """从 resultData 提取最终结果 DnsMessage 并返回。"""
        if self._result_data is None:
            return None
        return self._result_data.response
