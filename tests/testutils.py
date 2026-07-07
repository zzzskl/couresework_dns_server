"""
测试工具模块：MockTransport 及构建测试用 DnsMessage 的辅助函数。
"""

from __future__ import annotations

import sys
from pathlib import Path

# 将项目根目录加入 sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dns_transport import (
    DnsMessage,
    QueryFrame,
    Transport,
    TransportError,
)
from dns_types import DnsResourceRecord


class MockTransport(Transport):
    """
    可编程 Mock Transport — 按预设顺序返回响应或抛出异常。

    用法:
        transport = MockTransport()
        transport.add_response(response_a)
        transport.add_error(TransportTimeoutError("timeout"))
        result = await transport.query(QueryFrame(...))
        assert len(transport.call_history) == 2
    """

    def __init__(self):
        self._responses: list[DnsMessage | TransportError] = []
        self.call_history: list[QueryFrame] = []

    def add_response(self, response: DnsMessage) -> None:
        """添加一条预设响应。"""
        self._responses.append(response)

    def add_error(self, error: TransportError) -> None:
        """添加一个预设异常。"""
        self._responses.append(error)

    async def query(self, frame: QueryFrame) -> DnsMessage:
        self.call_history.append(frame)
        if not self._responses:
            raise TransportError("MockTransport 预设响应已耗尽")
        next_item = self._responses.pop(0)
        if isinstance(next_item, Exception):
            raise next_item
        return next_item


def make_dns_message(
    answers: list | None = None,
    authorities: list | None = None,
    additionals: list | None = None,
    rcode: int = 0,
) -> DnsMessage:
    """
    构造一个用于测试的 DnsMessage。
    默认返回空响应（无答案、无权威、无附加）。
    """
    from dns_types import DnsHeader

    header = DnsHeader(rcode=rcode)
    return DnsMessage(
        header=header,
        questions=[],
        answers=answers or [],
        authorities=authorities or [],
        additionals=additionals or [],
    )
