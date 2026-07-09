"""
DNS Client 全覆盖集成测试 — 多类型 × 多域名。

运行前提：
    DNS Server (dns_server.py) 已在 127.0.0.1:5354 运行。

用法:
    python tests/test_client_coverage.py

输出:
    - stdout 实时打印每个用例结果
    - 最终汇总统计
    - 同时写入 test_output.txt
"""

from __future__ import annotations

import socket
import sys
import time
from collections import defaultdict
from pathlib import Path

# 确保能找到项目根目录的模块
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dns_types import DnsMessage
from dns_decoder import decode

# ══════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════
TARGET = ("127.0.0.1", 5354)
TIMEOUT = 15  # 迭代解析首次可能较慢

# ══════════════════════════════════════════════════════════════
# 测试矩阵：覆盖关键类型和域名
# ══════════════════════════════════════════════════════════════
# (domain, qtype_str, 描述)
TEST_CASES = [
    # --- A 记录 (IPv4) ---
    ("www.baidu.com",           "A",     "国内大站 A 记录"),
    ("www.google.com",          "A",     "国外大站 A 记录"),
    ("www.github.com",          "A",     "CDN 域名 A 记录"),
    ("www.cloudflare.com",      "A",     "CDN 域名 A 记录"),
    # --- AAAA 记录 (IPv6) ---
    ("www.google.com",          "AAAA",  "国外大站 IPv6"),
    ("www.cloudflare.com",      "AAAA",  "CDN IPv6"),
    # --- NS 记录 ---
    ("baidu.com",               "NS",    "国内域名 NS"),
    ("google.com",              "NS",    "国外域名 NS"),
    ("example.com",             "NS",    "RFC 保留域名 NS"),
    # --- MX 记录 ---
    ("gmail.com",               "MX",    "邮件服务 MX"),
    ("qq.com",                  "MX",    "国内邮件 MX"),
    ("outlook.com",             "MX",    "微软邮件 MX"),
    # --- CNAME 记录 ---
    ("www.github.io",           "CNAME", "CNAME 链测试"),
    # --- TXT 记录 ---
    ("google.com",              "TXT",   "TXT/SPF 记录"),
    ("qq.com",                  "TXT",   "国内域名 TXT"),
    # --- SOA 记录 ---
    ("baidu.com",               "SOA",   "国内域名 SOA"),
    ("example.com",             "SOA",   "RFC 保留域名 SOA"),
    # --- 不存在域名（负测试）---
    ("this-does-not-exist-abc123-testing-only.com", "A", "不存在域名 → NXDOMAIN"),
    # --- 特殊域名 ---
    (".",                       "NS",    "根域 NS"),
]


def format_rcode(rcode: int) -> str:
    """将数值 rcode 转为可读字符串。"""
    MAP = {0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain",
           4: "NotImp", 5: "Refused"}
    return MAP.get(rcode, f"Unknown({rcode})")


def run_single_test(domain: str, qtype_str: str, desc: str) -> dict:
    """
    执行单次 DNS 查询。

    Returns:
        dict with keys: ok, elapsed_ms, rcode, rcode_str, answers,
                        authorities, additionals, size, error, txid_match
    """
    query = DnsMessage.create_query(domain, qtype_str)
    query_data = query.to_bytes()
    query_txid = query.header.id

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    result = {
        "ok": False,
        "elapsed_ms": 0,
        "rcode": -1,
        "rcode_str": "N/A",
        "answers": 0,
        "authorities": 0,
        "additionals": 0,
        "size": 0,
        "error": None,
        "txid_match": False,
    }

    try:
        t0 = time.time()
        sock.sendto(query_data, TARGET)
        resp_data, addr = sock.recvfrom(4096)
        result["elapsed_ms"] = (time.time() - t0) * 1000

        resp = decode(resp_data)
        result["rcode"] = resp.header.rcode
        result["rcode_str"] = format_rcode(resp.header.rcode)
        result["answers"] = len(resp.answers)
        result["authorities"] = len(resp.authorities)
        result["additionals"] = len(resp.additionals)
        result["size"] = len(resp_data)
        result["txid_match"] = (resp.header.id == query_txid)
        result["ok"] = True

        # 收集答案细节
        result["answer_details"] = []
        for a in resp.answers:
            result["answer_details"].append({
                "name": a.name,
                "type_str": a.type_str,
                "rdata": str(a.rdata),
                "ttl": a.ttl,
            })

    except socket.timeout:
        result["error"] = f"TIMEOUT (>{TIMEOUT}s)"
    except Exception as e:
        result["error"] = str(e)
    finally:
        sock.close()

    return result


def print_result(idx: int, domain: str, qtype: str, desc: str, r: dict):
    """格式化打印单条测试结果。"""
    status = "[PASS]" if r["ok"] and r["rcode"] in (0, 3) else "[FAIL]"
    # NXDOMAIN for nonexistent domain is expected -> still PASS
    if "not-exist" in domain and r["rcode"] == 3:
        status = "[PASS] (expected NXDOMAIN)"

    elapsed = f"{r['elapsed_ms']:.0f}ms" if r["ok"] else "-"
    rcode = r["rcode_str"]
    answers = r["answers"]
    auth = r["authorities"]
    txid = "OK" if r["txid_match"] else "MISMATCH"

    print(f"  {idx:2d}. {status} | {elapsed:>7s} | rcode={rcode:12s} | "
          f"ans={answers} auth={auth} | txid={txid} | "
          f"{desc}: {domain} ({qtype})")

    if r.get("answer_details"):
        for ad in r["answer_details"]:
            print(f"       | {ad['name']}  {ad['type_str']:5s}  {ad['rdata']:40s}  TTL={ad['ttl']}")

    if r["error"]:
        print(f"       !  {r['error']}")


def main():
    results = []
    log_lines = []

    def log(s: str = ""):
        print(s)
        log_lines.append(s)

    log("=" * 90)
    log(f"  DNS Client 全覆盖集成测试")
    log(f"  测试日期: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"  目标服务器: {TARGET[0]}:{TARGET[1]}")
    log(f"  超时设定: {TIMEOUT}s")
    log(f"  测试用例数: {len(TEST_CASES)}")
    log("=" * 90)
    log()

    for idx, (domain, qtype_str, desc) in enumerate(TEST_CASES, 1):
        r = run_single_test(domain, qtype_str, desc)
        print_result(idx, domain, qtype_str, desc, r)
        results.append({
            "idx": idx,
            "domain": domain,
            "qtype": qtype_str,
            "desc": desc,
            **r,
        })

    # ── 汇总统计 ────────────────────────────────────────
    log()
    log("=" * 90)
    log("  汇总统计")
    log("=" * 90)

    total = len(results)

    def is_pass(r: dict) -> bool:
        if not r["ok"]:
            return False
        if "not-exist" in r["domain"]:
            return r["rcode"] == 3  # NXDOMAIN expected
        return r["rcode"] in (0,)

    passed = sum(1 for r in results if is_pass(r))
    failed = total - passed

    log(f"  总数: {total}  通过: {passed}  失败: {failed}")
    log()

    # ── 按类型统计 ──────────────────────────────────────
    by_type: dict[str, list] = defaultdict(list)
    for r in results:
        by_type[r["qtype"]].append(r)

    log("  按查询类型统计:")
    for qt in sorted(by_type.keys()):
        cases = by_type[qt]
        p = sum(1 for c in cases if is_pass(c))
        f = len(cases) - p
        log(f"    {qt:6s}: {p}/{len(cases)} 通过  {f} 失败")
    log()

    # ── 失败详情 ────────────────────────────────────────
    failed_cases = [r for r in results if not is_pass(r)]
    if failed_cases:
        log("  失败用例:")
        for r in failed_cases:
            if r["error"]:
                log(f"    ✗ [{r['idx']}] {r['domain']} ({r['qtype']}) — {r['desc']}")
                log(f"       错误: {r['error']}")
            else:
                log(f"    ✗ [{r['idx']}] {r['domain']} ({r['qtype']}) — {r['desc']}")
                log(f"       rcode={r['rcode_str']} answers={r['answers']}")
        log()

    # ── TxID 一致性 ─────────────────────────────────────
    txid_mismatch = [r for r in results if r["ok"] and not r["txid_match"]]
    if txid_mismatch:
        log(f"  ⚠ TxID 不匹配: {len(txid_mismatch)} 个")
        for r in txid_mismatch:
            log(f"    [{r['idx']}] {r['domain']} ({r['qtype']})")
        log()
    else:
        log("  ✓ 所有响应 TxID 与查询一致")
        log()

    # ── 缓存验证（对第一个域名重复查询） ─────────────
    log("  ── 缓存加速验证 ──")
    first = TEST_CASES[0]
    r1 = run_single_test(first[0], first[1], first[2])
    r2 = run_single_test(first[0], first[1], first[2])
    if r1["ok"] and r2["ok"]:
        ratio = r1["elapsed_ms"] / max(r2["elapsed_ms"], 0.01)
        log(f"    首次: {r1['elapsed_ms']:.1f}ms  再次: {r2['elapsed_ms']:.1f}ms  "
            f"加速比: {ratio:.1f}x")
        if ratio >= 2:
            log(f"    ✓ 缓存加速生效")
        else:
            log(f"    ~ 加速不明显（TTL 可能已过期或查询极快）")
    elif r2["error"] and "TIMEOUT" in r2["error"]:
        log(f"    ⚠ 缓存验证超时（服务器可能已关闭）")
    log()

    # ── 性能概览 ────────────────────────────────────────
    ok_times = [r["elapsed_ms"] for r in results if r["ok"] and r["elapsed_ms"] > 0]
    if ok_times:
        log(f"  响应时间统计 (仅成功):")
        log(f"    最小: {min(ok_times):.1f}ms")
        log(f"    最大: {max(ok_times):.1f}ms")
        log(f"    平均: {sum(ok_times)/len(ok_times):.1f}ms")
        log(f"    中位: {sorted(ok_times)[len(ok_times)//2]:.1f}ms")

    log()
    log("=" * 90)

    # ── 写入文件 ────────────────────────────────────────
    output_path = Path(__file__).resolve().parent.parent / "test_output.txt"
    output_path.write_text("\n".join(log_lines), encoding="utf-8")
    print(f"\n[输出已保存到 {output_path}]")

    return results


if __name__ == "__main__":
    main()
