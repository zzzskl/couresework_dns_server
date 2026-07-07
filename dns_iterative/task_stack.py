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
"""

from __future__ import annotations

from dns_iterative.consts import MAX_DEPTH, MAX_STEPS, ROOT_SERVERS
from dns_iterative.models import Task, TaskResult, TaskStatus
from dns_iterative.query_stack import QueryStack
from dns_transport import DnsMessage, QueryFrame


class TaskStack:
    """
    任务栈状态机。

    通过 run() 启动主循环，内部通过 peek 栈顶、按状态执行、
    可能转换状态、继续循环的方式驱动解析流程。
    """

    def __init__(self):
        self._stack: list[Task] = []
        self._result_data: TaskResult | None = None
        self._visited: set[str] = set()
        self._step_count: int = 0

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
                frame = QueryFrame(ROOT_SERVERS[0], task.domain, qtype)
                query_stack.push(frame, list(ROOT_SERVERS))
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
                    self._handle_cname(response, task, qtype)
                elif self._has_referral(response):
                    self._handle_referral(response, task)
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

    def _handle_cname(self, response: DnsMessage, task: Task,
                      qtype: int) -> None:
        """PENDING + 收到 CNAME → CNAME + 压入子任务。"""
        task.status = TaskStatus.CNAME
        for rec in response.answers:
            if rec.type == 5:  # CNAME
                target = rec.rdata
                if not self._was_visited(target):
                    self._mark_visited(target)
                    self.push(target)  # NEW
                break

    def _handle_referral(self, response: DnsMessage, task: Task) -> None:
        """PENDING + 收到 NS 无胶水 → PAUSED + 压入子任务。"""
        task.status = TaskStatus.PAUSED
        for rec in response.authorities:
            if rec.type == 2:  # NS
                ns_domain = rec.rdata
                self.push(ns_domain)  # NEW
                break

    # ── 结果组装 ────────────────────────────────────────

    def _build_result(self) -> DnsMessage | None:
        """从 resultData 提取最终结果 DnsMessage 并返回。"""
        if self._result_data is None:
            return None
        return self._result_data.response
