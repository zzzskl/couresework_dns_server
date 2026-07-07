"""
dns_iterative 模块单元测试：

  1. QueryStack：正常路径、NS+胶水自旋、全部目标失败、_has_ns_glue 判定
  2. TaskStack：NEW→PENDING→FINISHED、CNAME 链、PAUSED 恢复、空栈、MAX_DEPTH/MAX_STEPS
  3. ResolutionEngine：集成 MockTransport 端到端
"""

from __future__ import annotations

import asyncio

import pytest

from dns_iterative.models import TaskResult, QueryStatus
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_iterative.engine import ResolutionEngine
from dns_transport import (
    DnsMessage,
    QueryFrame,
    TransportError,
    TransportTimeoutError,
)
from testutils import MockTransport, make_dns_message
from dns_types import DnsResourceRecord


# ══════════════════════════════════════════════════════════════
# QueryStack 测试
# ══════════════════════════════════════════════════════════════


class TestQueryStack:
    """QueryStack 状态机行为。"""

    # ── 基础路径 ──────────────────────────────────────

    def test_push_sets_ready(self, mock_transport):
        """push 后状态应为 READY。"""
        qs = QueryStack(mock_transport)
        frame = QueryFrame("8.8.8.8", "www.example.com", 1)
        qs.push(frame)
        assert qs._status == QueryStatus.READY

    def test_run_normal_path(self, mock_transport, sample_a_response):
        """正常查询：READY→SENT→FINISHED，结果存入 _result_data。"""
        mock_transport.add_response(sample_a_response)
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("8.8.8.8", "www.example.com", 1))
        asyncio.run(qs.run())
        result = qs.consume_result()
        assert result.response is sample_a_response
        assert qs._status == QueryStatus.FINISHED
        assert len(mock_transport.call_history) == 1

    def test_consume_result_after_run(self, mock_transport, sample_a_response):
        """run 后 consume_result 应返回同一响应。"""
        mock_transport.add_response(sample_a_response)
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("8.8.8.8", "www.example.com", 1))
        asyncio.run(qs.run())
        assert qs.consume_result().response is sample_a_response

    # ── NS+胶水自旋 ──────────────────────────────────

    def test_ns_glue_spin(self, mock_transport):
        """NS+胶水响应应触发自旋：内部提取胶水 IP 重查。"""
        # 第一轮：NS + 胶水 A 记录
        ns_glue_resp = make_dns_message(
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
            additionals=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
        )
        # 第二轮：最终 A 记录答案
        final_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "93.184.216.34")],
        )
        mock_transport.add_response(ns_glue_resp)
        mock_transport.add_response(final_resp)

        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("8.8.8.8", "www.example.com", 1))
        asyncio.run(qs.run())
        result = qs.consume_result()

        assert result.response is final_resp
        assert len(mock_transport.call_history) == 2
        # 第一次查询用原始 target_ip
        assert mock_transport.call_history[0].target_ip == "8.8.8.8"
        # 自旋后第二次查询用胶水 IP
        assert mock_transport.call_history[1].target_ip == "1.2.3.4"
        assert mock_transport.call_history[1].domain == "www.example.com"

    def test_ns_glue_edns_false_positive(self, mock_transport):
        """EDNS OPT 伪记录不应误触 NS+胶水自旋。"""
        # 权威段有 NS，但附加段 A 记录不匹配 NS 目标（模拟 EDNS OPT 场景）
        # DnsResourceRecord.create_a 创建 type=1 的记录，这里改用手动构造来模拟
        ns_resp = make_dns_message(
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
            additionals=[
                DnsResourceRecord(name="someother.example.com", type=1, rdata="5.6.7.8"),
            ],
        )
        mock_transport.add_response(ns_resp)

        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("8.8.8.8", "www.example.com", 1))
        asyncio.run(qs.run())
        result = qs.consume_result()

        # 不应自旋：附加段没有匹配 NS 目标的 A 记录
        assert result.response is ns_resp
        assert len(mock_transport.call_history) == 1

    def test_no_ns_no_glue_no_spin(self, mock_transport, sample_a_response):
        """既无 NS 也无胶水 → 不自旋。"""
        mock_transport.add_response(sample_a_response)
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("8.8.8.8", "www.example.com", 1))
        asyncio.run(qs.run())
        result = qs.consume_result()
        assert result.response is sample_a_response
        assert len(mock_transport.call_history) == 1

    # ── 全部目标失败 ─────────────────────────────────

    def test_all_targets_fail(self, mock_transport):
        """所有目标均失败 → consume_result 返回 QueryResult(error=...)。"""
        mock_transport.add_error(TransportTimeoutError("超时 1"))
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("8.8.8.8", "www.example.com", 1), targets=["8.8.8.8", "1.1.1.1"])
        asyncio.run(qs.run())
        result = qs.consume_result()
        assert result is not None and result.error is not None
        assert len(mock_transport.call_history) == 2

    def test_single_target_no_fallback(self, mock_transport):
        """单目标失败（无 targets 列表）→ 无后备，consume_result 返回 QueryResult(error=...)。"""
        mock_transport.add_error(TransportTimeoutError("超时"))
        qs = QueryStack(mock_transport)
        qs.push(QueryFrame("8.8.8.8", "www.example.com", 1))
        asyncio.run(qs.run())
        result = qs.consume_result()
        assert result is not None and result.error is not None
        assert len(mock_transport.call_history) == 1

    # ── _has_ns_glue 边界值 ──────────────────────────

    def test_has_ns_glue_true(self, mock_transport, sample_ns_glue_response):
        """权威段 NS + 附加段匹配 A → 返回 True。"""
        qs = QueryStack(mock_transport)
        assert qs._has_ns_glue(sample_ns_glue_response) is True

    def test_has_ns_glue_no_ns(self, mock_transport, sample_a_response):
        """无权威段 NS → 返回 False。"""
        qs = QueryStack(mock_transport)
        assert qs._has_ns_glue(sample_a_response) is False

    def test_has_ns_glue_no_glue(self, mock_transport, sample_ns_no_glue_response):
        """权威段 NS + 无附加段匹配 → 返回 False。"""
        qs = QueryStack(mock_transport)
        assert qs._has_ns_glue(sample_ns_no_glue_response) is False

    def test_has_ns_glue_empty(self, mock_transport, sample_empty_response):
        """空响应 → 返回 False。"""
        qs = QueryStack(mock_transport)
        assert qs._has_ns_glue(sample_empty_response) is False


# ══════════════════════════════════════════════════════════════
# TaskStack 测试
# ══════════════════════════════════════════════════════════════


class TestTaskStack:
    """TaskStack 状态机行为。"""

    # ── 正常路径 ──────────────────────────────────────

    def test_push_and_run_simple(self, mock_transport, sample_a_response):
        """简单 A 记录查询：NEW→PENDING→FINISHED→pop→返回答案。"""
        mock_transport.add_response(sample_a_response)
        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts.push("www.example.com")
        result = asyncio.run(ts.run(qs))
        assert result is not None
        assert result is sample_a_response

    def test_run_empty_stack(self, mock_transport):
        """空栈 → run 立即返回 None。"""
        qs = QueryStack(mock_transport)
        ts = TaskStack()
        result = asyncio.run(ts.run(qs))
        assert result is None

    def test_push_check_depth(self, mock_transport):
        """压入 MAX_DEPTH+1 个任务应抛 RuntimeError。"""
        from dns_iterative.consts import MAX_DEPTH
        qs = QueryStack(mock_transport)
        ts = TaskStack()
        # 压满 MAX_DEPTH
        for i in range(MAX_DEPTH):
            ts.push(f"level{i}.example.com")
        # 再压一个应抛异常
        with pytest.raises(RuntimeError, match="深度超过上限"):
            ts.push("overflow.example.com")

    # ── CNAME 链 ──────────────────────────────────────

    def test_cname_chain(self, mock_transport):
        """CNAME 链：初始域名→CNAME→目标域名 A 记录→最终结果。"""
        cname_resp = make_dns_message(
            answers=[DnsResourceRecord.create_cname("www.example.com", "target.example.com")],
        )
        a_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("target.example.com", "93.184.216.34")],
        )
        mock_transport.add_response(cname_resp)  # 第一次查询返回 CNAME
        mock_transport.add_response(a_resp)      # 第二次查询（CNAME 目标）返回 A

        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts.push("www.example.com")
        result = asyncio.run(ts.run(qs))

        assert result is not None
        assert result is a_resp
        assert len(mock_transport.call_history) == 2

    def test_cname_chain_multi_hop(self, mock_transport):
        """多跳 CNAME 链：A→CNAME→B→CNAME→C→A。"""
        cname_a = make_dns_message(
            answers=[DnsResourceRecord.create_cname("a.example.com", "b.example.com")],
        )
        cname_b = make_dns_message(
            answers=[DnsResourceRecord.create_cname("b.example.com", "c.example.com")],
        )
        a_c = make_dns_message(
            answers=[DnsResourceRecord.create_a("c.example.com", "1.2.3.4")],
        )
        mock_transport.add_response(cname_a)
        mock_transport.add_response(cname_b)
        mock_transport.add_response(a_c)

        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts.push("a.example.com")
        result = asyncio.run(ts.run(qs))

        assert result is not None
        assert result is a_c
        assert len(mock_transport.call_history) == 3

    def test_cname_child_failure(self, mock_transport):
        """CNAME 子任务失败 → 父任务应正确处理并返回 None。"""
        cname_resp = make_dns_message(
            answers=[DnsResourceRecord.create_cname("www.example.com", "target.example.com")],
        )
        mock_transport.add_response(cname_resp)  # 第一次返回 CNAME
        # 第二次（CNAME 目标）所有目标失败 — 不添加响应

        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts.push("www.example.com")
        result = asyncio.run(ts.run(qs))

        # CNAME 子任务无有效响应 → 应优雅处理，返回 None
        assert result is None

    # ── PAUSED 恢复 ──────────────────────────────────

    def test_paused_recovery(self, mock_transport):
        """缺胶水场景：NS 无胶水 → 子任务解析 NS IP → 恢复查询原域名。"""
        # 第一次查询：NS 无胶水（Paused 触发条件）
        ns_no_glue = make_dns_message(
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        )
        # 第二次查询（子任务）：查 NS 域名的 A 记录
        ns_ip_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
        )
        # 第三次查询（父任务恢复）：用胶水 IP 查原域名
        final_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "93.184.216.34")],
        )
        mock_transport.add_response(ns_no_glue)
        mock_transport.add_response(ns_ip_resp)
        mock_transport.add_response(final_resp)

        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts.push("www.example.com")
        result = asyncio.run(ts.run(qs))

        assert result is not None
        assert result is final_resp
        # 第三次查询的 target_ip 应为 ns1.example.com 的 IP
        assert mock_transport.call_history[2].target_ip == "1.2.3.4"

    def test_paused_child_failure(self, mock_transport):
        """缺胶水场景子任务失败 → 父任务优雅终止。"""
        ns_no_glue = make_dns_message(
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        )
        mock_transport.add_response(ns_no_glue)  # 第一次：NS 无胶水
        # 第二次（NS 域名子任务）：无响应 → 失败

        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts.push("www.example.com")
        result = asyncio.run(ts.run(qs))

        # PAUSED 子任务无有效 result → 应优雅处理，返回 None
        assert result is None

    # ── MAX_STEPS 限制 ───────────────────────────────

    def test_max_steps_limit(self, mock_transport):
        """超多步循环应被 MAX_STEPS 截断，返回 None。"""
        # 不断返回 CNAME 链直到超出步数限制
        from dns_iterative.consts import MAX_STEPS
        cname = make_dns_message(
            answers=[DnsResourceRecord.create_cname("x.com", "y.com")],
        )
        # 填充足够的响应让步数耗尽
        for _ in range(MAX_STEPS + 5):
            mock_transport.add_response(cname)
        # 还需要一个让 y.com 的查询也返回 CNAME...
        # 简化：压入一个会反复触发 CNAME 的场景
        # 实际上 MAX_STEPS 是全局步数，超过就返回 None
        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts.push("x.com")
        result = asyncio.run(ts.run(qs))
        # 步数耗尽后栈非空 → 返回 None
        assert result is None

    # ── 空栈防御 ─────────────────────────────────────

    def test_peek_empty_stack(self, mock_transport):
        """空栈 _peek 应抛 RuntimeError。"""
        ts = TaskStack()
        with pytest.raises(RuntimeError, match="peek 空栈"):
            ts._peek()

    def test_pop_empty_stack(self, mock_transport):
        """空栈 _pop 应抛 RuntimeError。"""
        ts = TaskStack()
        with pytest.raises(RuntimeError, match="pop 空栈"):
            ts._pop()


# ══════════════════════════════════════════════════════════════
# ResolutionEngine 测试
# ══════════════════════════════════════════════════════════════


class TestResolutionEngine:
    """ResolutionEngine 端到端集成测试。"""

    def test_resolve_simple(self, mock_transport, sample_a_response):
        """engine.resolve 应返回 A 记录答案。"""
        mock_transport.add_response(sample_a_response)
        engine = ResolutionEngine(mock_transport)
        result = asyncio.run(engine.resolve("www.example.com"))
        assert result is sample_a_response

    def test_resolve_no_response(self, mock_transport):
        """所有目标失败 → resolve 返回 None。"""
        mock_transport.add_error(TransportTimeoutError("超时"))
        engine = ResolutionEngine(mock_transport)
        result = asyncio.run(engine.resolve("www.example.com"))
        assert result is None

    def test_resolve_cname_chain(self, mock_transport):
        """engine 应能解析 CNAME 链。"""
        cname_resp = make_dns_message(
            answers=[DnsResourceRecord.create_cname("www.example.com", "target.com")],
        )
        a_resp = make_dns_message(
            answers=[DnsResourceRecord.create_a("target.com", "1.2.3.4")],
        )
        mock_transport.add_response(cname_resp)
        mock_transport.add_response(a_resp)
        engine = ResolutionEngine(mock_transport)
        result = asyncio.run(engine.resolve("www.example.com"))
        assert result is a_resp

    def test_resolve_paused_recovery(self, mock_transport):
        """engine 应能处理缺胶水恢复。"""
        ns_no_glue = make_dns_message(
            authorities=[DnsResourceRecord.create_ns("example.com", "ns1.example.com")],
        )
        ns_ip = make_dns_message(
            answers=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
        )
        final = make_dns_message(
            answers=[DnsResourceRecord.create_a("www.example.com", "93.184.216.34")],
        )
        mock_transport.add_response(ns_no_glue)
        mock_transport.add_response(ns_ip)
        mock_transport.add_response(final)
        engine = ResolutionEngine(mock_transport)
        result = asyncio.run(engine.resolve("www.example.com"))
        assert result is final

    def test_resolve_with_qtype(self, mock_transport):
        """engine.resolve 可指定 qtype。"""
        aaaa_resp = make_dns_message(
            answers=[DnsResourceRecord.create_aaaa("www.example.com", "::1")],
        )
        mock_transport.add_response(aaaa_resp)
        engine = ResolutionEngine(mock_transport)
        result = asyncio.run(engine.resolve("www.example.com", qtype=28))
        assert result is aaaa_resp
        # 验证查询帧使用了正确的 qtype
        assert mock_transport.call_history[0].qtype == 28
