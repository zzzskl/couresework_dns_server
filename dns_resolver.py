#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 解析器 (LEGACY) — 与上游真实 DNS 服务器通信。

.. deprecated::
    此模块仅为向后兼容保留。新代码请使用 ``dns_transport.AsyncUdpTransport``
    （异步对象层 API）或 ``dns_iterative.engine.ResolutionEngine``（完整迭代解析）。

遗留功能:
    - resolve(query_bytes, ...) → bytes   (bytes 级接口)
    - main()                              (命令行入口)

用法:
    新代码推荐:
        transport = AsyncUdpTransport()
        result = await transport.query(QueryFrame('8.8.8.8', 'www.baidu.com', 1))
"""

# ======================== 解析器配置区域 ========================
UPSTREAM_SERVER = "8.8.8.8"       # 上游 DNS 服务器地址
UPSTREAM_PORT = 53                # 上游 DNS 端口
TIMEOUT = 5                       # 超时秒数
QUERY_DOMAIN = "www.baidu.com"    # 要查询的域名
QUERY_TYPE = "A"                  # 记录类型: A, AAAA, MX, NS, CNAME, TXT
OUTPUT_FILE = "response.hex"      # 响应 hex 保存文件（空字符串则不保存）
PRINT_PARSED = True               # 是否打印解析后的结构化结果
# ================================================================

import socket
import time
import sys

from dns_types import DnsMessage
from dns_decoder import decode


# ---------- 公共 API ----------


def resolve(query_bytes: bytes,
            server: str = "8.8.8.8",
            port: int = 53,
            timeout: float = 5.0) -> bytes:
    """
    将 DNS 查询发送到上游服务器，接收并返回原始响应字节。

    参数:
        query_bytes: 原始 DNS 查询报文
        server:      上游 DNS 服务器地址
        port:        上游 DNS 端口
        timeout:     超时秒数

    返回:
        原始 DNS 响应报文

    抛出:
        socket.timeout: 上游服务器无响应
        OSError:        网络错误
        ValueError:     响应为空
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(query_bytes, (server, port))
        response_data, addr = sock.recvfrom(4096)

        if not response_data:
            raise ValueError("上游服务器返回空响应")

        return response_data

    finally:
        sock.close()


# ---------- 主入口（独立运行）----------

def main():
    """独立运行入口：构造查询 → 发送到上游 → 解析并打印"""
    print(f"[*] DNS 解析器启动")
    print(f"[*] 查询: {QUERY_DOMAIN} ({QUERY_TYPE})")
    print(f"[*] 上游: {UPSTREAM_SERVER}:{UPSTREAM_PORT}")
    print(f"[*] 超时: {TIMEOUT}s\n")

    # 1. 使用对象层构造查询
    query = DnsMessage.create_query(QUERY_DOMAIN, QUERY_TYPE)
    query_data = query.to_bytes()
    print(f"[*] 查询报文: {len(query_data)} 字节")
    print(f"    Hex: {' '.join(f'{b:02x}' for b in query_data)}\n")

    # 2. 发送并接收
    try:
        start_time = time.time()
        response = resolve(query_data, UPSTREAM_SERVER,
                           UPSTREAM_PORT, TIMEOUT)
        elapsed = (time.time() - start_time) * 1000

        print(f"[+] 收到响应: {len(response)} 字节，耗时 {elapsed:.2f} ms")

        # 3. 使用对象层解析
        if PRINT_PARSED:
            parsed = decode(response)
            h = parsed.header
            print(f"\n{'='*60}")
            print(f"  解析结果:")
            print(f"{'='*60}")
            print(f"  ID: 0x{h.id:04x}  QR={'Response' if h.qr else 'Query'}"
                  f"  RCODE={h.rcode} ({h.rcode_str})")
            print(f"  Questions: {parsed.qdcount}  Answers: {parsed.ancount}"
                  f"  Authority: {parsed.nscount}  Additional: {parsed.arcount}")

            for i, q in enumerate(parsed.questions):
                print(f"  Q[{i}]: {q.qname}  ({q.qtype_str})")
            for i, a in enumerate(parsed.answers):
                print(f"  A[{i}]: {a.name}  {a.type_str}  {a.rdata}  TTL={a.ttl}")
            for i, a in enumerate(parsed.authorities):
                print(f"  NS[{i}]: {a.name}  {a.type_str}  {a.rdata}  TTL={a.ttl}")
            for i, a in enumerate(parsed.additionals):
                print(f"  X[{i}]: {a.name}  {a.type_str}  {a.rdata}  TTL={a.ttl}")
            print(f"{'='*60}")

        hex_str = ' '.join(f'{b:02x}' for b in response)
        print(f"\n[响应 Hex]\n{hex_str}")

        # 4. 保存 hex 文件
        if OUTPUT_FILE:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(hex_str)
            print(f"\n[+] 响应已保存至 {OUTPUT_FILE}")

    except socket.timeout:
        print(f"[-] 请求超时（{TIMEOUT}s），{UPSTREAM_SERVER}:{UPSTREAM_PORT} 无响应")
        sys.exit(1)
    except OSError as e:
        print(f"[-] 网络错误: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"[-] 数据错误: {e}")
        sys.exit(1)

    print("\n[*] 解析器执行完毕")


if __name__ == "__main__":
    main()
