#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 迭代解析器 — 常量和配置。
"""

from __future__ import annotations

# ══════════════════════════════════════════════════════════════════
# 根服务器
# ══════════════════════════════════════════════════════════════════
# IANA 官方 13 组根服务器 IP（2025-04 更新）
# 见 https://www.iana.org/domains/root/servers

ROOT_SERVERS: list[str] = [
    "198.41.0.4",        # a.root-servers.net
    "199.9.14.201",      # b.root-servers.net
    "192.33.4.12",       # c.root-servers.net
    "199.7.91.13",       # d.root-servers.net
    "192.203.230.10",    # e.root-servers.net
    "192.5.5.241",       # f.root-servers.net
    "192.112.36.4",      # g.root-servers.net
    "198.97.190.53",     # h.root-servers.net
    "192.36.148.17",     # i.root-servers.net
    "192.58.128.30",     # j.root-servers.net
    "193.0.14.129",      # k.root-servers.net
    "199.7.83.42",       # l.root-servers.net
    "202.12.27.33",      # m.root-servers.net
]

# ══════════════════════════════════════════════════════════════════
# 安全限制
# ══════════════════════════════════════════════════════════════════

MAX_DEPTH: int = 16
"""Task Stack 最大深度——防止 CNAME 无限链。"""

MAX_STEPS: int = 128
"""全局解析步数上限——防止意外死循环。"""
