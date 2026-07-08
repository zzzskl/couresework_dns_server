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

from dns_iterative.consts import MAX_DEPTH, MAX_STEPS
from dns_iterative.engine_infra import StackBase, transition_status
from dns_iterative.models import Task, TaskResult, TaskStatus
from dns_transport import DnsMessage, QueryFrame


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

        # ── Engine 在 run() 前注入 ─────────────────────
        self._initial_targets: list[str] = []
        self._qtype: int = 1
        self._query_stack = None

    # ── 外部接口 ──────────────────────────────────────────

    def push(self, domain: str) -> None:
        """
        将域名作为 NEW 任务压入栈顶。

        Raises:
            RuntimeError: 栈深度超过 MAX_DEPTH 上限（由 _push 守卫）。
        """
        self._push(Task(domain=domain, status=TaskStatus.NEW))
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
                frame = QueryFrame(self._initial_targets[0], task.domain, self._qtype)
                qs.push(frame, list(self._initial_targets))
                transition_status(task, TaskStatus.PENDING, TaskStatus.NEW)
                await qs.run()
                # 交权返回，下一轮 peek 处理 PENDING

            # ── PENDING ──────────────────────────────────
            elif task.status == TaskStatus.PENDING:
                qresult = qs.consume_result()
                if qresult is None or qresult.error is not None:
                    self._result_data = TaskResult(
                        error=qresult.error if qresult else "Query Stack 无结果",
                    )
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PENDING)
                    continue
                response = qresult.response

                if self._has_answer(response):
                    self._handle_answer(response, task)
                elif self._has_cname(response):
                    self._handle_cname(response, task)
                elif self._has_referral(response):
                    self._handle_referral(response, task)
                else:
                    # 无法识别的响应（NXDOMAIN、SERVFAIL 等）
                    self._result_data = TaskResult(error="无法识别的 DNS 响应类型")
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PENDING)

            # ── CNAME ────────────────────────────────────
            elif task.status == TaskStatus.CNAME:
                last_task_result = self._consume_last_task_result()
                if last_task_result and last_task_result.response:
                    self._result_data = TaskResult(
                        response=last_task_result.response,
                        answer_ip=last_task_result.answer_ip,
                    )
                else:
                    self._result_data = TaskResult(error="CNAME 子任务无有效响应")
                self._pop()  # 瞬移：直接弹栈，继承 IP

            # ── PAUSED ───────────────────────────────────
            elif task.status == TaskStatus.PAUSED:
                last_task_result = self._consume_last_task_result()
                if last_task_result and last_task_result.answer_ip:
                    frame = QueryFrame(last_task_result.answer_ip, task.domain, self._qtype)
                    qs.push(frame)
                    transition_status(task, TaskStatus.PENDING, TaskStatus.PAUSED)
                    await qs.run()
                elif last_task_result and last_task_result.response:
                    # answer_ip 不可用时回退到传播响应本身
                    self._result_data = TaskResult(response=last_task_result.response)
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PAUSED)
                else:
                    # 子任务未能获取胶水 IP
                    self._result_data = TaskResult(error="子任务未能解析 NS 服务器 IP")
                    transition_status(task, TaskStatus.FINISHED, TaskStatus.PAUSED)
                # 下一轮 peek 处理 PENDING

            # ── FINISHED ─────────────────────────────────
            elif task.status == TaskStatus.FINISHED:
                self._pop()

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
        """答案段是否有非 CNAME 的有效答案记录。"""
        return any(rec.rr_type != 5 for rec in response.answers)

    def _has_cname(self, response: DnsMessage) -> bool:
        """答案段是否有 CNAME 记录。"""
        return any(rec.rr_type == 5 for rec in response.answers)

    def _has_referral(self, response: DnsMessage) -> bool:
        """权威段是否有 NS 记录（且无胶水——胶水已在 Query 层处理）。"""
        return response.nscount > 0

    # ── 状态转换处理（纯逻辑，无缓存意识） ──────────────

    def _handle_answer(self, response: DnsMessage, task: Task) -> None:
        """PENDING + 收到 A/AAAA 答案 → FINISHED。"""
        transition_status(task, TaskStatus.FINISHED, TaskStatus.PENDING)
        if self._result_data is not None:
            raise RuntimeError(
                f"_handle_answer 准备覆盖未消费的 _result_data: "
                f"{self._result_data}"
            )
        answer_ip = None
        for rec in response.answers:
            if rec.rr_type in (1, 28):  # A or AAAA
                answer_ip = rec.rdata
                break
        self._result_data = TaskResult(response=response, answer_ip=answer_ip)

    def _handle_cname(self, response: DnsMessage, task: Task) -> None:
        """
        PENDING + 收到 CNAME → 压入子任务。

        不再查缓存 — 缓存检测由 Engine 增强的 push() 完成。
        """
        transition_status(task, TaskStatus.CNAME, TaskStatus.PENDING)
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

        不再查缓存 — 缓存检测由 Engine 增强的 push() 完成。
        """
        transition_status(task, TaskStatus.PAUSED, TaskStatus.PENDING)
        for rec in response.authorities:
            if rec.rr_type == 2:  # NS
                ns_domain = rec.rdata
                self.push(ns_domain)  # 由 Engine 增强版处理缓存
                break
