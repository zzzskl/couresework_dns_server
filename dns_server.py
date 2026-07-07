#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 服务器（拦截器）— 基于 DnsMessage 对象层，解析请求并构造合法响应
用法: 修改下方配置后直接运行
"""

# ======================== 服务器配置区域 ========================
LISTEN_IP = "0.0.0.0"            # 监听地址 (0.0.0.0 表示所有网卡)
LISTEN_PORT = 5354               # 监听端口 (5353被系统mDNS占用，改用5354)
OUTPUT_FILE = "server/captured.hex"   # 保存的 Hex 文件名
AUTO_REPLY = True                # 是否自动回复（构造合法 DNS 响应）
SAMPLE_ANSWER = "10.0.0.1"       # AUTO_REPLY 时返回的 A 记录 IP
SAMPLE_ANSWER_AAAA = "::1"        # AUTO_REPLY 时返回的 AAAA 记录 IP
# ================================================================

import socket
import time
import os

from dns_decoder import decode
from dns_types import DnsMessage, DnsResourceRecord


def build_response(query: DnsMessage, answer_ip: str) -> DnsMessage:
    """
    根据收到的 DNS 查询构造对象层响应。
    先尝试 decode，若失败则 fallback 回原始 bytes。
    """
    # 为每个 question 构造一个 A 记录
    answers = []
    for q in query.questions:
        if q.qtype == 1:   # A 记录
            answers.append(
                DnsResourceRecord.create_a(q.qname, answer_ip)
            )
        elif q.qtype == 28:  # AAAA 记录
            answers.append(
                DnsResourceRecord.create_aaaa(q.qname, SAMPLE_ANSWER_AAAA)
            )
        elif q.qtype == 5:   # CNAME
            answers.append(
                DnsResourceRecord.create_cname(q.qname, f"alias.{q.qname}")
            )
        # 其他类型：返回空 answer（仍为合法响应）

    return DnsMessage.create_response(query, answers=answers)


def main():
    # 创建 UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(f"[*] DNS 拦截器已启动，监听 {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[*] 保存文件: {OUTPUT_FILE}")
    print(f"[*] AUTO_REPLY={'ON' if AUTO_REPLY else 'OFF'} "
          f"(A: {SAMPLE_ANSWER}, AAAA: {SAMPLE_ANSWER_AAAA})")
    print("[*] 等待客户端请求... (按 Ctrl+C 退出)\n")

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"[>] 拦截到来自 {addr[0]}:{addr[1]} 的请求，"
                  f"大小: {len(data)} 字节")

            # 转为标准 Hex 格式（空格分隔，每字节两位）
            hex_str = ' '.join(f'{b:02x}' for b in data)

            # 确保输出目录存在
            out_dir = os.path.dirname(OUTPUT_FILE)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            # 写入文件（覆盖模式，每次启动只保存最新的一个包）
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(hex_str)
            print(f"[+] 已保存至 {OUTPUT_FILE}")

            # AUTO_REPLY：解析请求并构造合法 DNS 响应
            if AUTO_REPLY:
                try:
                    query = decode(data)
                    qnames = [q.qname for q in query.questions]
                    print(f"    Query: {', '.join(qnames)}")

                    response = build_response(query, SAMPLE_ANSWER)
                    response_bytes = response.to_bytes()
                    sock.sendto(response_bytes, addr)

                    print(f"[<] 已返回 DNS 响应给 {addr[0]}:{addr[1]} "
                          f"({len(response_bytes)} 字节, "
                          f"{response.ancount} 条 Answer)")
                except Exception as e:
                    # decode 失败时 fallback：回显原始数据（至少让客户端不超时）
                    sock.sendto(data, addr)
                    print(f"[!] 解析失败 ({e})，已回显原始数据")

            print("[*] 继续等待下一个请求...\n")

    except KeyboardInterrupt:
        print("\n[*] 用户中断，服务器已关闭")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
