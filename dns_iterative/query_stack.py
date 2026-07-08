#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 迭代解析器 — Query Stack（查询栈）。

Query Stack 是一个有状态的复合对象：
- 单槽栈（容量固定为 1），存储待发送的查询帧
- 自身状态字段（READY / SENT / FINISHED）
- resultData 字段（记录异步回调填入的结果）
- 目标服务器队列 + 重试计数

自旋逻辑：
    当收到 NS + 胶水响应时，Query Stack 内部提取胶水 IP、
    构造新帧、转为 READY，继续发送。Task 对此无感知。

控制权流转：
    READY → SENT → await transport.query() →
        NS+胶水 → READY（自旋，控制权不离开 Query）
        其他   → FINISHED（交权给 Task）
"""

from __future__ import annotations

import logging

from dns_common import QTYPE_REVERSE
from dns_iterative.models import QueryResult, QueryStatus
from dns_transport import (
    DnsMessage,
    QueryFrame,
    Transport,
    TransportError,
)

log = logging.getLogger(__name__)


class QueryStack:
    """
    单槽查询栈，自带状态机运行循环。

    每次 run() 完成一个完整的查询回合，内部可能多次自旋
    （NS+胶水→提取胶水 IP→构造新帧→继续查询）。
    """

    def __init__(self, transport: Transport):
        self._transport = transport

        # 单槽：当前待发送/已发送的查询帧
        self._frame: QueryFrame | None = None

        # 目标服务器列表及当前尝试索引（用于超时重试）
        self._targets: list[str] = []
        self._target_idx: int = 0

        # 结果
        self._result_data: QueryResult | None = None

        # 状态
        self._status: QueryStatus = QueryStatus.FINISHED

    # ── 外部接口 ──────────────────────────────────────────

    def push(self, frame: QueryFrame,
             targets: list[str] | None = None) -> None:
        """
        压入查询帧，开始新的查询回合。

        Args:
            frame:   待查询的目标 IP、域名、类型
            targets: 可用的目标服务器 IP 列表（用于超时重试）。
                     不传则仅用 frame.target_ip。
        """
        self._frame = frame
        self._targets = targets or [frame.target_ip]
        self._target_idx = 0
        self._result_data = None
        self._status = QueryStatus.READY

    async def run(self) -> None:
        """
        运行查询栈状态机，直到 FINISHED。

        结果写入 _result_data，外部通过 consume_result() 读取。

        内部流程：
            while READY:
                SENT → await transport.query()
                ├─ 成功 + NS+胶水 → 自旋（继续 READY）
                ├─ 成功 + 其他    → FINISHED
                └─ 失败 → 切换目标重试 / 耗尽 → FINISHED
        """
        while self._status == QueryStatus.READY:
            self._status = QueryStatus.SENT

            target_ip = self._frame.target_ip
            qtype_name = QTYPE_REVERSE.get(self._frame.qtype, str(self._frame.qtype))
            log.info("→ %s %s %s", target_ip, qtype_name, self._frame.domain)

            try:
                response = await self._transport.query(self._frame)
            except TransportError as exc:
                # 当前目标失败，尝试下一个
                if self._switch_target():
                    log.warning(
                        "← Error from %s: %s → retry %s",
                        target_ip, exc, self._frame.target_ip,
                    )
                    self._status = QueryStatus.READY
                    continue
                # 所有目标均失败
                log.error(
                    "← All %d targets exhausted for %s",
                    len(self._targets), self._frame.domain,
                )
                self._result_data = QueryResult(error="所有目标服务器均无响应")
                self._status = QueryStatus.FINISHED
                continue

            # 检查是否 NS + 胶水（自旋条件）
            if self._has_ns_glue(response):
                self._frame = self._build_glue_frame(response)
                log.info("← NS+glue from %s → spin to %s", target_ip, self._frame.target_ip)
                self._status = QueryStatus.READY
                continue

            # 非自旋结果：存入 resultData，结束
            log.info("← Answer from %s (%d records)", target_ip, len(response.answers))
            self._result_data = QueryResult(response=response)
            self._status = QueryStatus.FINISHED

    def consume_result(self) -> QueryResult | None:
        """
        读取 Query Stack 的 resultData（不清除）。

        由 Task Stack 在 PENDING 状态时调用。
        """
        return self._result_data

    # ── 内部方法 ──────────────────────────────────────────

    def _switch_target(self) -> bool:
        """切换到目标列表中的下一个服务器。成功返回 True。"""
        self._target_idx += 1
        if self._target_idx < len(self._targets):
            new_ip = self._targets[self._target_idx]
            self._frame = QueryFrame(
                new_ip, self._frame.domain, self._frame.qtype,
            )
            return True
        return False

    def _has_ns_glue(self, response: DnsMessage) -> bool:
        """
        判断响应是否为 NS + 胶水（自旋条件）。

        判断标准：
            权威段有 NS 记录，且附加段有对应的 A/AAAA 胶水记录。
            仅检查 arcount>0 不够（EDNS OPT 伪记录也会计入），
            必须验证附加段 A/AAAA 记录的 name 匹配某个 NS 目标域名。
        """
        if response.nscount == 0:
            return False
        ns_targets = {
            rec.rdata for rec in response.authorities
            if rec.type == 2  # NS
        }
        if not ns_targets:
            return False
        for rec in response.additionals:
            if rec.type in (1, 28) and rec.name in ns_targets:  # A/AAAA + 匹配 NS 目标
                return True
        return False

    def _build_glue_frame(self, response: DnsMessage) -> QueryFrame:
        """
        从附加段提取匹配 NS 目标域名的第一个胶水 IP，构造新查询帧。
        域名和类型与原帧相同，仅目标 IP 替换为胶水 IP。

        Raises:
            AssertionError: _has_ns_glue 返回 True 但未找到胶水 IP（不应发生）。
        """
        ns_targets = {
            rec.rdata for rec in response.authorities if rec.type == 2
        }
        for rec in response.additionals:
            if rec.type in (1, 28) and rec.name in ns_targets:
                return QueryFrame(
                    rec.rdata,
                    self._frame.domain,
                    self._frame.qtype,
                )
        raise AssertionError(
            f"_has_ns_glue 返回 True 但未在附加段找到匹配的胶水 A/AAAA 记录"
        )
