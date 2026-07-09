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

Engine 在 run() 前注入属性：
    self._query_stack      — QueryStack 实例
    self._qtype            — 查询类型（默认 1）
    self._initial_targets  — 初始目标服务器 IP 列表
Engine 覆写 self.push() 方法以插入缓存检测。

分层归属:
    Layer 3 — 具体栈状态机（纯化，不含缓存/日志逻辑）
"""

from __future__ import annotations

import logging

from dns_iterative.consts import MAX_DEPTH, MAX_STEPS
from dns_iterative.engine_infra import StackBase, transition_status
from dns_iterative.models import Task, TaskResult, TaskStatus
from dns_transport import DnsMessage, QueryFrame
from dns_types import DnsHeader


class TaskStack(StackBase[Task]):
    """
    纯化任务栈状态机。

    不含缓存查询、日志记录、回调注入。所有横切关注点由 Engine
    通过实例方法覆写（_enhance）在外部增强。
    """

    def __init__(self) -> None:
        """初始化空任务栈。"""
        StackBase.__init__(self, max_depth=MAX_DEPTH)
        self._result_data: TaskResult | None = None
        self._visited: set[str] = set()
        self._step_count: int = 0

        # ── CNAME 链合并暂存 ────────────────────────────
        self._cname_parent_response: DnsMessage | None = None

        # ── NS fallback 队列 ─────────────────────────────
        self._referral_ns_queue: list[str] = []

        # ── Engine 在 run() 前注入 ─────────────────────
        self._initial_targets: list[str] = []
        self._qtype: int = 1
        self._query_stack = None

    # ── _result_data 保护写入 ────────────────────────────────

    def _set_result(self, value: TaskResult) -> None:
        """写入 _result_data，若已有未消费数据则抛异常防止静默覆盖。"""
        if self._result_data is not None:
            raise RuntimeError(
                f"准备覆盖未消费的 _result_data: {self._result_data}"
            )
        self._result_data = value

    # ── 外部接口 ──────────────────────────────────────────

    def push(self, domain: str, qtype: int | None = None) -> None:
        """
        将域名作为 NEW 任务压入栈顶。

        Args:
            domain: 查询域名。
            qtype:  查询类型，None 表示使用栈级 self._qtype。

        Raises:
            RuntimeError: 栈深度超过 MAX_DEPTH 上限（由 _push 守卫）。
        """
        actual_qtype = self._qtype if qtype is None else qtype
        self._push(Task(domain=domain, status=TaskStatus.NEW, qtype=actual_qtype))
        self._mark_visited(domain)

    async def run(self) -> None:
        """
        运行任务栈状态机主循环。

        无参数、无返回值。依赖 Engine 在 run() 前设置的属性：
            self._query_stack, self._qtype, self._initial_targets
        结果写入 self._result_data，由 Engine 在外部读取。
        """
        qs = self._query_stack
        while not self._is_empty() and self._step_count < MAX_STEPS:
            self._step_count += 1
            task = self._peek()

            # ── NEW ──────────────────────────────────────
            if task.status == TaskStatus.NEW:
                frame = QueryFrame(self._initial_targets[0], task.domain, task.qtype)
                qs.push(frame, list(self._initial_targets))
                transition_status(task, TaskStatus.PENDING, TaskStatus.NEW)
                await qs.run()
                # 交权返回，下一轮 peek 处理 PENDING

            # ── PENDING ──────────────────────────────────
            elif task.status == TaskStatus.PENDING:
                qresult = qs.consume_result()
                if qresult is None or qresult.error is not None:
                    self._set_result(TaskResult(
                        error=qresult.error if qresult else "Query Stack 无结果",
                    ))
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PENDING)
                    continue
                response = qresult.response

                # 上游返回非零 rcode（NXDOMAIN/SERVFAIL 等），透传原始响应及其 rcode
                if response.header.rcode != 0:
                    self._set_result(TaskResult(response=response, answer_ip=None))
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PENDING)

                elif self._has_answer(response):
                    self._handle_answer(response, task)
                elif self._has_cname(response):
                    self._handle_cname(response, task)
                elif self._has_referral(response):
                    self._handle_referral(response, task)
                else:
                    # rcode=0 但无匹配答案/CNAME/推荐
                    # 合法场景：域名存在但请求类型无记录
                    # （如查 AAAA 但域名只有 A 记录）
                    self._handle_noerror_empty(response, task)

            # ── CNAME ────────────────────────────────────
            elif task.status == TaskStatus.CNAME:
                last_task_result = self._consume_last_task_result()
                if last_task_result and last_task_result.response:
                    child = last_task_result.response
                    # 合并父 CNAME 记录到最终响应（保留完整 CNAME 链）
                    if self._cname_parent_response is not None:
                        merged_answers = list(self._cname_parent_response.answers) + list(child.answers)
                        merged = DnsMessage(
                            header=DnsHeader(
                                id=child.header.id, qr=1,
                                rcode=child.header.rcode, ra=1,
                            ),
                            questions=list(child.questions),
                            answers=merged_answers,
                            authorities=list(child.authorities),
                            additionals=list(child.additionals),
                        )
                        self._set_result(TaskResult(
                            response=merged,
                            answer_ip=last_task_result.answer_ip,
                        ))
                    else:
                        self._set_result(TaskResult(
                            response=child,
                            answer_ip=last_task_result.answer_ip,
                        ))
                else:
                    self._set_result(TaskResult(error="CNAME 子任务无有效响应"))
                self._cname_parent_response = None
                self._pop()  # 瞬移：直接弹栈，继承 IP

            # ── PAUSED ───────────────────────────────────
            elif task.status == TaskStatus.PAUSED:
                last_task_result = self._consume_last_task_result()
                if last_task_result and last_task_result.answer_ip:
                    self._referral_ns_queue.clear()  # 成功，清空 NS 队列
                    frame = QueryFrame(last_task_result.answer_ip, task.domain, self._qtype)
                    qs.push(frame)
                    transition_status(task, TaskStatus.PENDING, TaskStatus.PAUSED)
                    await qs.run()
                elif self._referral_ns_queue:
                    # 当前 NS 失败，尝试队列中的下一个 NS
                    next_ns = self._referral_ns_queue.pop(0)
                    log = logging.getLogger(__name__)
                    log.warning(
                        "NS resolution failed for %s, trying next NS: %s",
                        task.domain, next_ns,
                    )
                    self.push(next_ns, qtype=1)
                    # 保持 PAUSED — 下一轮迭代会处理新的子任务
                elif last_task_result and last_task_result.response:
                    # 无更多 NS 可重试，回退到传播响应
                    self._set_result(TaskResult(response=last_task_result.response))
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PAUSED)
                else:
                    # 子任务未能获取胶水 IP
                    self._set_result(TaskResult(error="子任务未能解析 NS 服务器 IP"))
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PAUSED)
                # 下一轮 peek 处理 PENDING 或新的子任务

            # ── FINISHED ─────────────────────────────────
            elif task.status == TaskStatus.FINISHED:
                self._pop()

        if self._step_count >= MAX_STEPS and not self._is_empty():
            log = logging.getLogger(__name__)
            log.warning(
                "TaskStack 达到最大步数限制 (%d)，"
                "可能仍有未完成的任务",
                MAX_STEPS,
            )

    # ── 内部栈操作 ──────────────────────────────────────

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
        """答案段是否有匹配查询类型 (qtype) 的答案记录。

        检查 answer 段中是否存在 rr_type 等于 self._qtype 的记录。
        对于 CNAME 查询 (qtype=5)，CNAME 记录就是答案。
        对于其他类型，CNAME 记录不算答案（由 _has_cname 处理）。
        """
        if self._qtype == 5:
            return len(response.answers) > 0
        return any(rec.rr_type == self._qtype for rec in response.answers)

    def _has_cname(self, response: DnsMessage) -> bool:
        """答案段是否有 CNAME 记录。"""
        return any(rec.rr_type == 5 for rec in response.answers)

    def _has_referral(self, response: DnsMessage) -> bool:
        """权威段是否有 NS 记录（而非 SOA 等其他记录）。"""
        return any(rec.rr_type == 2 for rec in response.authorities)

    # ── 状态转换处理（纯逻辑，无缓存意识） ──────────────

    def _handle_answer(self, response: DnsMessage, task: Task) -> None:
        """PENDING + 收到 A/AAAA 答案 → FINISHED。"""
        transition_status(task, TaskStatus.FINISHED, TaskStatus.PENDING)
        answer_ip = None
        for rec in response.answers:
            if rec.rr_type in (1, 28):  # A or AAAA
                answer_ip = rec.rdata
                break
        self._set_result(TaskResult(response=response, answer_ip=answer_ip))

    def _handle_cname(self, response: DnsMessage, task: Task) -> None:
        """
        PENDING + 收到 CNAME → 压入子任务。

        保存父 CNAME 响应以便后续合并到最终结果。
        不再查缓存 — 缓存检测由 Engine 增强的 push() 完成。
        """
        transition_status(task, TaskStatus.CNAME, TaskStatus.PENDING)
        # 保存原始 CNAME 响应（用于 CNAME 态合并链）
        self._cname_parent_response = response
        for rec in response.answers:
            if rec.rr_type == 5:  # CNAME
                target = rec.rdata
                if not self._was_visited(target):
                    self._mark_visited(target)
                    self.push(target)  # 由 Engine 增强版处理缓存
                break

    def _handle_referral(self, response: DnsMessage, task: Task) -> None:
        """
        PENDING + 收到 NS 无胶水 → 压入子任务解析 NS IP。

        收集所有 NS 记录，优先处理第一个；其余存入 _referral_ns_queue
        供 PAUSED handler 在失败时 fallback。
        不再查缓存 — 缓存检测由 Engine 增强的 push() 完成。
        """
        transition_status(task, TaskStatus.PAUSED, TaskStatus.PENDING)
        ns_domains = []
        for rec in response.authorities:
            if rec.rr_type == 2:  # NS
                ns_domain = rec.rdata
                if not self._was_visited(ns_domain):
                    ns_domains.append(ns_domain)
        if ns_domains:
            self._referral_ns_queue = ns_domains[1:]  # 后续留待 fallback
            self.push(ns_domains[0], qtype=1)  # NS 解析始终用 A 记录

    def _handle_noerror_empty(self, response: DnsMessage, task: Task) -> None:
        """
        rcode=0 但无匹配记录 → 返回空答案（非错误）。

        合法场景：域名存在但请求类型无记录（如 AAAA 查询但域名只有 A 记录）。
        保持 rcode=0，客户端应视为 NODATA（无该类型记录）。
        """
        transition_status(task, TaskStatus.FINISHED, TaskStatus.PENDING)
        self._set_result(TaskResult(response=response))
