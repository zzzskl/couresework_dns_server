#!/usr/bin/env python3
"""
真实网络迭代解析测试 — 从根服务器开始全程迭代解析域名。

用法:
    python tests/test_iterative_real.py [domain] [qtype]

示例:
    python tests/test_iterative_real.py www.baidu.com
    python tests/test_iterative_real.py www.baidu.com 1
    python tests/test_iterative_real.py google.com 28     # AAAA
"""

import asyncio
import logging
import sys
from pathlib import Path

# 将项目根目录加入 sys.path（使可直接运行）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from dns_common import setup_logger, QTYPE_MAP
from dns_transport import AsyncUdpTransport
from dns_iterative.engine import ResolutionEngine


async def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "www.baidu.com"
    qtype_str = sys.argv[2] if len(sys.argv) > 2 else "A"
    qtype = QTYPE_MAP.get(qtype_str.upper(), 1)

    setup_logger(level=logging.INFO, console=True)

    transport = AsyncUdpTransport(timeout=5.0)
    engine = ResolutionEngine(transport)

    print()
    print("=" * 60)
    print(f"  迭代解析: {domain}  (qtype={qtype_str})")
    print("=" * 60)
    print()

    result = await engine.resolve(domain, qtype=qtype)

    print()
    print("=" * 60)
    if result:
        print("  [OK] SUCCESS")
        for ans in result.answers:
            rdata_str = str(ans.rdata) if not isinstance(ans.rdata, bytes) else ans.rdata.hex()
            print(f"     {ans.name:<30s} {ans.type_str:<6s} {rdata_str}  (ttl={ans.ttl})")
        for ns in result.authorities:
            print(f"     [NS] {ns.name:<30s} -> {ns.rdata}")
        print(f"     ({result.ancount} answers, {result.nscount} authorities)")
    else:
        print("  [FAIL] FAILED")
        print(f"     engine.resolve() returned None")
    print("=" * 60)
    print()


if __name__ == "__main__":
    asyncio.run(main())
