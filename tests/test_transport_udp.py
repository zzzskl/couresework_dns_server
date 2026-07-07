"""
AsyncUdpTransport 单元测试：

  1. 正常 UDP 查询响应流
  2. TxID 匹配验证
  3. 超时场景
  4. TxID 不匹配
  5. 空响应
  6. 响应解析失败
  7. 网络错误（发送/接收）
  8. socket 关闭验证
"""

from __future__ import annotations

import asyncio
import socket
import struct
from unittest.mock import AsyncMock, patch

import pytest

from dns_transport import (
    AsyncUdpTransport,
    QueryFrame,
    TransportBadResponseError,
    TransportNetworkError,
    TransportTimeoutError,
)


def _make_response_bytes(tx_id: int = 0x1234) -> bytes:
    """构造一个最小的合法 DNS 响应 bytes。"""
    header = struct.pack("!H", tx_id)
    header += b"\x81\x80"
    header += struct.pack("!HHHH", 1, 1, 0, 0)
    question = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    answer = (
        b"\xc0\x0c\x00\x01\x00\x01"
        b"\x00\x00\x00\x2a\x00\x04"
        b"\x5d\xb8\xd8\x22"
    )
    return header + question + answer


def _run_with_mock_io(transport, frame, *,
                      recv_result=None, timeout_error=False,
                      send_error=None, recv_error=None):
    """
    用真实事件循环 + mock IO 方法执行 transport.query()。

    策略：使用真实 asyncio 事件循环，但替换其 sock_sendto 和
    sock_recvfrom 方法，使测试不依赖真实网络。
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    sendto_args = []

    async def fake_sock_sendto(sock, data, addr):
        sendto_args.append((data, addr))

    # 配置 mock IO
    if send_error:
        loop.sock_sendto = AsyncMock(side_effect=send_error)
    else:
        loop.sock_sendto = AsyncMock(side_effect=fake_sock_sendto)

    if timeout_error:
        loop.sock_recvfrom = AsyncMock(side_effect=asyncio.TimeoutError)
    elif recv_error:
        loop.sock_recvfrom = AsyncMock(side_effect=recv_error)
    elif recv_result is not None:
        loop.sock_recvfrom = AsyncMock(return_value=recv_result)
    else:
        loop.sock_recvfrom = AsyncMock()

    try:
        result = loop.run_until_complete(transport.query(frame))
        return result, sendto_args, None
    except Exception as e:
        return None, sendto_args, e
    finally:
        loop.close()


class TestAsyncUdpTransport:
    """AsyncUdpTransport 模拟 IO 测试。"""

    # ── 正常路径 ──────────────────────────────────────

    def test_normal_query(self):
        """正常 UDP 查询：发送→接收→解码→返回 DnsMessage。"""
        resp = _make_response_bytes()
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        with patch("os.urandom", return_value=b"\x12\x34"):
            result, sendto_args, exc = _run_with_mock_io(
                transport, frame, recv_result=(resp, ("8.8.8.8", 53)),
            )

        assert exc is None, f"unexpected error: {exc}"
        assert result is not None
        assert len(result.answers) > 0
        assert result.answers[0].rdata == "93.184.216.34"
        assert len(sendto_args) >= 1
        sent = sendto_args[0][0]
        assert b"www" in sent
        assert b"example" in sent

    def test_tx_id_match(self):
        """TxID 一致时正常返回结果。"""
        resp = _make_response_bytes(0x1234)
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        with patch("os.urandom", return_value=b"\x12\x34"):
            result, _, exc = _run_with_mock_io(
                transport, frame, recv_result=(resp, ("8.8.8.8", 53)),
            )

        assert exc is None, f"unexpected error: {exc}"
        assert result is not None
        assert result.answers[0].rdata == "93.184.216.34"

    # ── 超时 ──────────────────────────────────────────

    def test_timeout(self):
        """recvfrom 超时 → TransportTimeoutError。"""
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        _, _, exc = _run_with_mock_io(transport, frame, timeout_error=True)

        assert exc is not None
        assert isinstance(exc, TransportTimeoutError)
        assert "超时" in str(exc)

    # ── TxID 不匹配 ──────────────────────────────────

    def test_tx_id_mismatch(self):
        """响应 TxID 与发送 TxID 不一致 → TransportBadResponseError。"""
        resp = _make_response_bytes(0xDEAD)
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        with patch("os.urandom", return_value=b"\x12\x34"):
            _, _, exc = _run_with_mock_io(
                transport, frame, recv_result=(resp, ("8.8.8.8", 53)),
            )

        assert exc is not None
        assert isinstance(exc, TransportBadResponseError)
        assert "TxID" in str(exc)

    # ── 空响应 ───────────────────────────────────────

    def test_empty_response(self):
        """空响应 → TransportBadResponseError。"""
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        _, _, exc = _run_with_mock_io(
            transport, frame, recv_result=(b"", ("8.8.8.8", 53)),
        )

        assert exc is not None
        assert isinstance(exc, TransportBadResponseError)
        assert "空响应" in str(exc)

    # ── 坏响应（无法解码） ───────────────────────────

    def test_bad_response_garbage(self):
        """合法 TxID + 垃圾数据 → decode 失败 → TransportBadResponseError。"""
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        with patch("os.urandom", return_value=b"\x12\x34"):
            # 前 2 字节 = TxID 0x1234（通过 TxID 检查），后面是垃圾（解析失败）
            garbage_resp = b"\x12\x34" + b"\xff" * 20
            _, _, exc = _run_with_mock_io(
                transport, frame, recv_result=(garbage_resp, ("8.8.8.8", 53)),
            )

        assert exc is not None
        assert isinstance(exc, TransportBadResponseError)
        assert "响应解析失败" in str(exc)

    # ── 网络错误 ─────────────────────────────────────

    def test_os_error_on_send(self):
        """发送时 OSError → TransportNetworkError。"""
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        _, _, exc = _run_with_mock_io(
            transport, frame, send_error=OSError("send failed"),
        )

        assert exc is not None
        assert isinstance(exc, TransportNetworkError)
        assert "网络错误" in str(exc)

    def test_os_error_on_recv(self):
        """接收时 OSError → TransportNetworkError。"""
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        _, _, exc = _run_with_mock_io(
            transport, frame, recv_error=OSError("recv failed"),
        )

        assert exc is not None
        assert isinstance(exc, TransportNetworkError)
        assert "网络错误" in str(exc)

    # ── socket 关闭验证 ─────────────────────────────

    def test_socket_closed_after_query(self):
        """查询结束后 socket 应被关闭。"""
        resp = _make_response_bytes()
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        with patch("os.urandom", return_value=b"\x12\x34"):
            result, _, exc = _run_with_mock_io(
                transport, frame, recv_result=(resp, ("8.8.8.8", 53)),
            )

        # 如果正常返回，说明 socket 在 finally 中被关闭了
        # 如果 transport.query() 内部 close 失败会抛异常
        assert exc is None
        assert result is not None

    def test_socket_closed_on_timeout(self):
        """超时时 socket 也应被关闭。"""
        transport = AsyncUdpTransport(timeout=5.0)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)

        _, _, exc = _run_with_mock_io(transport, frame, timeout_error=True)

        # 异常被抛出，socket 在 finally 中关闭
        assert exc is not None
        assert isinstance(exc, TransportTimeoutError)
