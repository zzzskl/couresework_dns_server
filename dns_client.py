#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 客户端 — 基于 DnsMessage 对象层构造查询并解析响应
用法: 修改下方配置后直接运行
"""

# ======================== 客户端配置区域 ========================
TARGET_SERVER = "127.0.0.1"      # 上游DNS服务器地址
TARGET_PORT = 5354               # DNS端口 (与server端一致，避免被系统mDNS拦截)
QUERY_DOMAIN = "www.baidu.com"   # 要查询的域名
QUERY_TYPE = "A"                 # 记录类型: A, AAAA, MX, NS 等
TIMEOUT = 10                     # 超时秒数
PRINT_RAW_HEX = True             # 是否同时打印原始 hex
# ================================================================

import socket
import time

# 使用对象层 API
from dns_types import DnsMessage
from dns_decoder import decode


def print_message(msg: DnsMessage, title: str = ""):
    """友好打印 DnsMessage 内容"""
    if title:
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")

    h = msg.header
    print(f"  ID: 0x{h.id:04x}  QR={'Response' if h.qr else 'Query'}"
          f"  OPCODE={h.opcode}  RCODE={h.rcode} ({h.rcode_str})")
    print(f"  Questions: {msg.qdcount}  Answers: {msg.ancount}"
          f"  Authority: {msg.nscount}  Additional: {msg.arcount}")

    for i, q in enumerate(msg.questions):
        print(f"  Q[{i}]: {q.qname}  ({q.qtype_str})")

    for i, a in enumerate(msg.answers):
        print(f"  A[{i}]: {a.name}  {a.type_str}  {a.rdata}  TTL={a.ttl}")

    for i, a in enumerate(msg.authorities):
        print(f"  NS[{i}]: {a.name}  {a.type_str}  {a.rdata}  TTL={a.ttl}")

    for i, a in enumerate(msg.additionals):
        print(f"  X[{i}]: {a.name}  {a.type_str}  {a.rdata}  TTL={a.ttl}")


def main():
    print(f"[*] 客户端启动，目标: {TARGET_SERVER}:{TARGET_PORT}")
    print(f"[*] 查询域名: {QUERY_DOMAIN} (类型: {QUERY_TYPE})")

    # 1. 使用对象层构造查询
    query = DnsMessage.create_query(QUERY_DOMAIN, QUERY_TYPE)
    query_data = query.to_bytes()
    print(f"[*] 查询报文: {len(query_data)} 字节")

    if PRINT_RAW_HEX:
        print(f"[*] Hex 预览: {' '.join(f'{b:02x}' for b in query_data[:32])}...")

    # 2. 创建 UDP Socket 并发送
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        start_time = time.time()
        sock.sendto(query_data, (TARGET_SERVER, TARGET_PORT))
        print(f"[*] 已发送，等待响应...")

        # 3. 接收并解析响应
        response_data, addr = sock.recvfrom(1024)
        elapsed = (time.time() - start_time) * 1000
        print(f"[+] 收到来自 {addr[0]}:{addr[1]} 的响应，"
              f"大小: {len(response_data)} 字节，耗时: {elapsed:.2f} ms")

        # 4. 使用对象层解析
        response = decode(response_data)
        print_message(response, "DNS 响应解析结果")

        if PRINT_RAW_HEX:
            hex_str = ' '.join(f'{b:02x}' for b in response_data)
            print(f"\n[响应 Hex 全文]\n{hex_str}")

    except socket.timeout:
        print("[-] 请求超时，目标服务器无响应")
    except Exception as e:
        print(f"[-] 发生错误: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
