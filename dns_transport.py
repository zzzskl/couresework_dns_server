#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 传输层抽象 — 定义 DNS 查询传输的接口契约。

职责:
    给定 QueryFrame（目标 IP + 域名 + 查询类型），
    执行一次完整的 DNS 查询-响应周期，
    返回解析后的 DnsMessage 对象。

设计原则:
    - 纯抽象：Transport 是 ABC，不包含任何具体 IO 实现
    - 单次语义：一次 query() 调用 = 一个 UDP 请求 + 一个响应，
      重试/多目标由调用方（如 ResolutionEngine）负责
    - 对象层：输入输出均为结构化类型，调用方不接触 bytes
    - 可测试：通过继承 Transport 并 mock 返回即可测试上层逻辑

用法:
    class MyTransport(Transport):
        async def query(self, frame: QueryFrame) -> DnsMessage:
            ...
"""

from __future__ import annotations

import abc
import asyncio
import logging
import os
import socket
import struct
from dataclasses import dataclass

from dns_common import QTYPE_REVERSE
from dns_decoder import decode
from dns_types import DnsMessage

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
# QueryFrame — 传输层的输入单元
# ══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class QueryFrame:
    """
    描述一次 DNS 查询的参数。

    Attributes:
        target_ip:  目标 DNS 服务器的 IP 地址（如 '8.8.8.8'）
        domain:     待查询的域名（如 'www.baidu.com'）
        qtype:      查询类型数值（1=A, 28=AAAA, 2=NS, 5=CNAME, 15=MX 等）
                    调用方负责从字符串到数值的转换，传输层只处理数值。
    """
    target_ip: str
    domain: str
    qtype: int = 1

    def __post_init__(self):
        if not self.target_ip:
            raise ValueError("target_ip 不能为空")
        if not self.domain:
            raise ValueError("domain 不能为空")
        if self.qtype < 0 or self.qtype > 65535:
            raise ValueError(f"qtype 超出有效范围: {self.qtype}")


# ══════════════════════════════════════════════════════════════════
# TransportError 体系 — 传输层异常
# ══════════════════════════════════════════════════════════════════


class TransportError(Exception):
    """传输层异常的基类。所有传输层异常均应继承此类。"""
    pass


class TransportTimeoutError(TransportError):
    """查询超时：在指定时间内未收到响应。"""
    pass


class TransportNetworkError(TransportError):
    """网络不可用：socket 创建失败、目标不可达、连接被拒等。"""
    pass


class TransportBadResponseError(TransportError):
    """
    响应无法解析：收到的 bytes 无法被 decode() 正确解析，
    或响应格式不符合预期。
    """
    pass


# ══════════════════════════════════════════════════════════════════
# Transport — 抽象基类
# ══════════════════════════════════════════════════════════════════


class Transport(abc.ABC):
    """
    DNS 查询传输层的抽象基类。

    子类必须实现 :meth:`query`，完成以下流程：
        1. 用 DnsMessage.create_query() 构造查询报文
        2. 序列化为 bytes
        3. 通过具体传输协议（UDP/TCP）发送
        4. 接收响应 bytes
        5. 用 dns_decoder.decode() 解析
        6. 返回 DnsMessage

    异常处理:
        - 超时: 抛出 TransportTimeoutError
        - 网络错误: 抛出 TransportNetworkError
        - 响应解析失败: 抛出 TransportBadResponseError
    """

    @abc.abstractmethod
    async def query(self, frame: QueryFrame) -> DnsMessage:
        """
        执行一次 DNS 查询并返回解析后的响应。

        Args:
            frame: 查询参数（目标 IP、域名、类型）

        Returns:
            解析后的 DnsMessage 对象

        Raises:
            TransportTimeoutError:     请求超时
            TransportNetworkError:     网络层错误
            TransportBadResponseError: 响应无法解析
        """
        ...


# ══════════════════════════════════════════════════════════════════
# AsyncUdpTransport — 基于 asyncio 的 UDP 默认实现
# ══════════════════════════════════════════════════════════════════


class AsyncUdpTransport(Transport):
    """
    基于 asyncio 非阻塞 socket 的 UDP 传输实现。

    每次 query() 调用会：
        1. 生成随机 TxID
        2. 用 DnsMessage.create_query() 构造查询报文
        3. 通过非阻塞 UDP socket 发送
        4. 等待响应（带超时）
        5. 验证 TxID 一致性
        6. 用 dns_decoder.decode() 解析并返回 DnsMessage

    用法:
        transport = AsyncUdpTransport(timeout=5.0)
        result = await transport.query(
            QueryFrame('8.8.8.8', 'www.baidu.com', 1)
        )
    """

    def __init__(self, timeout: float = 5.0, port: int = 53):
        """
        Args:
            timeout: 单次查询超时秒数（默认 5）
            port:    目标 DNS 服务器端口（默认 53）
        """
        self.timeout = timeout
        self.port = port

    async def query(self, frame: QueryFrame) -> DnsMessage:
        """执行一次异步 UDP DNS 查询。"""
        # 1. 生成随机 TxID
        tx_id = struct.unpack('!H', os.urandom(2))[0]

        # 2. 构造查询并设 TxID
        qtype_str = QTYPE_REVERSE.get(frame.qtype, 'A')
        query_msg = DnsMessage.create_query(frame.domain, qtype_str)
        query_msg.header.id = tx_id

        # 3. 序列化
        query_bytes = query_msg.to_bytes()

        # 4. 创建非阻塞 UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()

        try:
            # 5. 发送
            await loop.sock_sendto(
                sock, query_bytes, (frame.target_ip, self.port)
            )

            # 6. 接收（带超时）
            try:
                response_bytes, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                log.warning(
                    "UDP TIMEOUT %.1fs: %s \u2192 %s:%d",
                    self.timeout, frame.domain, frame.target_ip, self.port,
                )
                raise TransportTimeoutError(
                    f"查询超时 ({self.timeout}s): "
                    f"{frame.domain} → {frame.target_ip}:{self.port}"
                )

            if not response_bytes:
                raise TransportBadResponseError(
                    f"空响应: {frame.domain} → {frame.target_ip}:{self.port}"
                )

            # 7. 验证 TxID
            response_tx_id = struct.unpack('!H', response_bytes[:2])[0]
            if response_tx_id != tx_id:
                log.warning(
                    "UDP TxID mismatch: sent=%#06x recv=%#06x, "
                    "%s \u2192 %s:%d",
                    tx_id, response_tx_id,
                    frame.domain, frame.target_ip, self.port,
                )
                raise TransportBadResponseError(
                    f"TxID 不匹配: 发送 {tx_id:#06x}, "
                    f"收到 {response_tx_id:#06x}"
                )

            # 8. 解码
            try:
                return decode(response_bytes)
            except Exception as e:
                raise TransportBadResponseError(
                    f"响应解析失败 ({e}): "
                    f"{frame.domain} → {frame.target_ip}:{self.port}"
                )

        except TransportError:
            raise
        except OSError as e:
            log.warning(
                "UDP NETWORK ERROR: %s \u2192 %s:%d: %s",
                frame.domain, frame.target_ip, self.port, e,
            )
            raise TransportNetworkError(
                f"网络错误 ({e}): "
                f"{frame.domain} → {frame.target_ip}:{self.port}"
            )
        finally:
            sock.close()
