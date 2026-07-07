#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 迭代解析器 — ResolutionEngine（系统边界）。

Engine 是单次迭代解析请求的系统边界：
1. 创建 Task Stack 和 Query Stack
2. push 初始域名作为第一个 Task
3. 通过 task_stack.run() 将控制权交给双栈状态机
4. 返回最终结果

控制权流转：
    Engine → task_stack.run() → query_stack.run() → transport.query()
                                                      ↓ (await 返回)
                                 query_stack.run() ← ─┘
                                   ↓ (FINISHED)
    Engine ← task_stack.run() ← ──┘
"""

from __future__ import annotations

from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_transport import DnsMessage, Transport


class ResolutionEngine:
    """
    迭代解析器引擎。

    用法:
        transport = AsyncUdpTransport()
        engine = ResolutionEngine(transport)
        result = await engine.resolve("www.example.com")
    """

    def __init__(self, transport: Transport):
        self._transport = transport

    async def resolve(self, domain: str, qtype: int = 1) -> DnsMessage | None:
        """
        对指定域名执行迭代解析。

        Args:
            domain: 待解析的域名
            qtype:  查询类型数值（1=A, 28=AAAA 等，默认 1）

        Returns:
            成功时返回 DNS 响应报文（DnsMessage）；
            失败时返回 None。
        """
        query_stack = QueryStack(self._transport)
        task_stack = TaskStack()
        task_stack.push(domain)
        return await task_stack.run(query_stack, qtype)
