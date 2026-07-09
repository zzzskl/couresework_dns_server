#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 迭代解析器 — 双栈状态机核心模型定义。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from dns_types import DnsMessage


class TaskStatus(Enum):
    """Task 的状态枚举。"""
    NEW = auto()        # 新入栈，尚未处理
    PENDING = auto()    # 已发出查询，等待 Query Stack 结果
    CNAME = auto()      # 收到 CNAME 响应，等待子任务解析目标域名
    PAUSED = auto()     # 收到 NS 无胶水，等待子任务解析 NS IP
    FINISHED = auto()   # 任务完成，可弹栈


class QueryStatus(Enum):
    """Query Stack 的状态。"""
    READY = auto()      # 槽内有待发送的指令帧
    SENT = auto()       # 已发送，等待网络响应或超时（内部状态）
    FINISHED = auto()   # 当前查询回合终结


@dataclass
class Task:
    """
    Task 元素（栈内对象）。

    只包含两个字段，不携带 resultData——跨任务数据传递由
    Task Stack 对象的 resultData 字段负责。
    qtype 字段表示该任务的查询类型，默认 1 (A)。
    """
    domain: str
    status: TaskStatus = TaskStatus.NEW
    qtype: int = 1


@dataclass
class TaskResult:
    """
    Task Stack 跨任务结果传递 — 严格类型包装。

    子任务完成时，根据场景填充不同字段：
    - 正常 A/AAAA 答案: response + answer_ip
    - CNAME 链传递:     response（由父任务沿栈向上传递）
    - 错误:             error（子任务完全失败时设置）

    字段说明:
        response:  完整的 DNS 响应报文（CNAME 链传递 / _build_result 终态用）
        answer_ip: 从 answer 段提取的 IP 字符串（PAUSED 缺胶水恢复用）
        error:     错误描述，None 表示成功
    """
    response: DnsMessage | None = None
    answer_ip: str | None = None
    error: str | None = None


@dataclass
class QueryResult:
    """
    Query Stack 结果 — 严格类型包装。

    字段说明:
        response:  完整的 DNS 响应报文（成功时设置）
        error:     错误描述，None 表示成功（全部目标失败时设置）
    """
    response: DnsMessage | None = None
    error: str | None = None
