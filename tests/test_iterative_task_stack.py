"""
dns_iterative/task_stack.py — 完整集成测试。

覆盖: TaskStack — init / push / run (7条状态转换路径) / 内部方法
      (consume_last_task_result, visited, has_answer, has_cname, has_referral,
       handle_answer, handle_cname, handle_referral)
共 ~15 个测试函数。
"""

from __future__ import annotations

import pytest

from dns_iterative.consts import MAX_DEPTH, MAX_STEPS
from dns_iterative.models import Task, TaskResult, TaskStatus
from dns_iterative.query_stack import QueryStack
from dns_iterative.task_stack import TaskStack
from dns_transport import DnsMessage, QueryFrame, TransportTimeoutError
from dns_types import DnsResourceRecord


# ════════════════════════════════════════════════════════════════
# TaskStack 基本操作
# ════════════════════════════════════════════════════════════════


class TestTaskStackBasic:
    def test_init(self):
        ts = TaskStack()
        assert ts._is_empty()
        assert ts._result_data is None
        assert ts._visited == set()
        assert ts._step_count == 0

    def test_push(self):
        ts = TaskStack()
        ts.push("www.example.com")
        assert ts._is_empty() is False
        task = ts._peek()
        assert task.domain == "www.example.com"
        assert task.status == TaskStatus.NEW
        assert task.qtype == 1
        assert "www.example.com" in ts._visited

    def test_push_with_qtype(self):
        ts = TaskStack()
        ts._qtype = 1
        ts.push("www.example.com", qtype=28)
        assert ts._peek().qtype == 28

    def test_push_default_qtype(self):
        ts = TaskStack()
        ts._qtype = 1
        ts.push("test.com")  # qtype=None → use _qtype=1
        assert ts._peek().qtype == 1

    def test_max_depth_overflow(self):
        ts = TaskStack()
        # 压满 MAX_DEPTH 个
        for i in range(MAX_DEPTH):
            ts.push(f"domain{i}.com")
        with pytest.raises(RuntimeError, match="深度超限"):
            ts.push("overflow.com")


# ════════════════════════════════════════════════════════════════
# TaskStack.run() — 7 条状态转换路径
# ════════════════════════════════════════════════════════════════


class TestTaskStackRun:
    @pytest.fixture
    def setup_ts(self, mock_transport):
        """创建一个已绑定 query_stack 和 initial_targets 的 TaskStack."""
        qs = QueryStack(mock_transport)
        ts = TaskStack()
        ts._query_stack = qs
        ts._qtype = 1
        ts._initial_targets = ["198.41.0.4"]
        return ts

    def test_new_to_answer(self, setup_ts, mock_transport, sample_a_response):
        """NEW → PENDING → 有答案 → FINISHED → pop → 空栈 + result."""
        import asyncio
        ts = setup_ts
        mock_transport.set_response("198.41.0.4", sample_a_response)
        ts.push("www.example.com")
        asyncio.run(ts.run())
        assert ts._is_empty()
        assert ts._result_data is not None
        assert ts._result_data.response is not None
        assert len(ts._result_data.response.answers) == 1

    def test_new_to_nxdomain(self, setup_ts, mock_transport, sample_nxdomain_response):
        """NEW → PENDING → rcode≠0 → FINISHED → 透传 rcode."""
        import asyncio
        ts = setup_ts
        mock_transport.set_response("198.41.0.4", sample_nxdomain_response)
        ts.push("nx.example.com")
        asyncio.run(ts.run())
        assert ts._is_empty()
        assert ts._result_data is not None
        assert ts._result_data.response is not None
        assert ts._result_data.response.header.rcode == 3

    def test_new_to_cname_chain(
        self, setup_ts, mock_transport,
        sample_cname_response, sample_a_response,
    ):
        """
        NEW → PENDING → CNAME → push 子域名 alias → 子任务解析
        → 子任务 FINISHED → CNAME pop → 继承 result.
        """
        import asyncio
        ts = setup_ts
        # 根服务器返回 CNAME
        mock_transport.set_response("198.41.0.4", sample_cname_response)
        # 第二次(子任务)询问 www.example.com → 用同个根 IP (或虚构)
        mock_transport.set_response("93.184.216.34", sample_a_response)

        ts.push("alias.example.com")
        asyncio.run(ts.run())
        assert ts._is_empty()
        assert ts._result_data is not None

    def test_new_to_referral(
        self, setup_ts, mock_transport,
        sample_ns_noglue,
    ):
        """
        NEW → PENDING → NS 无胶水 → PAUSED → push NS 解析
        → 子任务得到 IP → PENDING → 最终 FINISHED.
        """
        import asyncio
        ts = setup_ts
        # 根服务器 198.41.0.4 → NS 无 glue (for example.com)
        mock_transport.set_domain_response("198.41.0.4", "example.com", sample_ns_noglue)
        # 子任务：解析 ns1.example.com → A 响应
        ns_query = DnsMessage.create_query("ns1.example.com", "A")
        ns_response = DnsMessage.create_response(
            ns_query,
            answers=[DnsResourceRecord.create_a("ns1.example.com", "1.2.3.4")],
        )
        mock_transport.set_domain_response("198.41.0.4", "ns1.example.com", ns_response)

        ts.push("example.com")
        asyncio.run(ts.run())
        assert ts._is_empty()

    def test_unknown_response(self, setup_ts, mock_transport):
        """rcode=0 但无答案/CNAME/推荐 → NOERROR 空答案."""
        import asyncio
        # 空响应（NOERROR, 无答案）
        empty_resp = DnsMessage.create_response(
            DnsMessage.create_query("test.com", "A"),
        )
        mock_transport.set_response("198.41.0.4", empty_resp)
        ts = setup_ts
        ts.push("test.com")
        asyncio.run(ts.run())
        assert ts._result_data is not None
        # 新行为：返回空响应（rcode=0），而非错误
        assert ts._result_data.error is None
        assert ts._result_data.response is not None
        assert ts._result_data.response.header.rcode == 0

    def test_query_error(self, setup_ts, mock_transport):
        """NEW → PENDING → transport error → error result."""
        import asyncio
        mock_transport.set_error("198.41.0.4", TransportTimeoutError("timeout"))
        ts = setup_ts
        ts.push("timeout.com")
        asyncio.run(ts.run())
        assert ts._result_data is not None
        assert ts._result_data.error is not None

    def test_max_steps_limit(self, setup_ts, mock_transport, sample_ns_noglue):
        """
        NS referral loop 被 visited 检测正确阻断（不会栈溢出）。
        """
        import asyncio
        mock_transport.set_domain_response("198.41.0.4", "loop.example.com", sample_ns_noglue)
        mock_transport.set_domain_response("198.41.0.4", "ns1.example.com", sample_ns_noglue)

        ts = setup_ts
        ts._initial_targets = ["198.41.0.4"]
        ts.push("loop.example.com")
        asyncio.run(ts.run())
        # _handle_referral 检测到所有 NS 已 visited → 不 push 子任务
        # PAUSED handler 无子任务结果 → NS 解析失败错误
        assert ts._result_data is not None
        assert ts._result_data.error is not None


# ════════════════════════════════════════════════════════════════
# 内部方法
# ════════════════════════════════════════════════════════════════


class TestTaskStackInternal:
    def test_consume_last_task_result(self):
        ts = TaskStack()
        ts._result_data = TaskResult(error="test")
        result = ts._consume_last_task_result()
        assert result.error == "test"
        assert ts._result_data is None  # 清空

    def test_consume_result_none(self):
        ts = TaskStack()
        assert ts._consume_last_task_result() is None

    def test_visited(self):
        ts = TaskStack()
        ts._mark_visited("a.com")
        ts._mark_visited("b.com")
        assert ts._was_visited("a.com") is True
        assert ts._was_visited("c.com") is False

    def test_has_answer_normal(self):
        """qtype≠5 时 CNAME 不算答案."""
        ts = TaskStack()
        ts._qtype = 1
        msg = DnsMessage.create_query("test.com")
        msg.answers.append(DnsResourceRecord.create_cname("x.com", "y.com"))
        assert ts._has_answer(msg) is False  # CNAME 不算

        msg.answers.append(DnsResourceRecord.create_a("y.com", "1.2.3.4"))
        assert ts._has_answer(msg) is True

    def test_has_answer_qtype_cname(self):
        """qtype=5 时 CNAME 算答案."""
        ts = TaskStack()
        ts._qtype = 5
        msg = DnsMessage.create_query("test.com", "CNAME")
        msg.answers.append(DnsResourceRecord.create_cname("x.com", "y.com"))
        assert ts._has_answer(msg) is True

    def test_has_answer_qtype_mismatch(self):
        """qtype=28 时 A 记录不匹配 (AAAA 查询但上游只返回 A)."""
        ts = TaskStack()
        ts._qtype = 28  # AAAA
        msg = DnsMessage.create_query("test.com", "AAAA")
        msg.answers.append(DnsResourceRecord.create_a("test.com", "1.2.3.4"))
        # 只有 A 记录没有 AAAA 记录 → 不算匹配答案
        assert ts._has_answer(msg) is False

    def test_has_answer_qtype_match_aaaa(self):
        """AAAA 查询时 AAAA 记录算答案."""
        ts = TaskStack()
        ts._qtype = 28  # AAAA
        msg = DnsMessage.create_query("test.com", "AAAA")
        msg.answers.append(DnsResourceRecord.create_aaaa("test.com", "::1"))
        assert ts._has_answer(msg) is True

    def test_has_answer_qtype_mx(self):
        """MX 查询时 MX 记录算答案."""
        ts = TaskStack()
        ts._qtype = 15  # MX
        msg = DnsMessage.create_query("test.com", "MX")
        msg.answers.append(
            DnsResourceRecord.create_mx("test.com", 10, "mail.test.com")
        )
        assert ts._has_answer(msg) is True

    def test_has_cname(self):
        ts = TaskStack()
        msg = DnsMessage.create_query("test.com")
        msg.answers.append(DnsResourceRecord.create_cname("a.com", "b.com"))
        assert ts._has_cname(msg) is True

    def test_has_cname_no(self):
        ts = TaskStack()
        msg = DnsMessage.create_query("test.com")
        msg.answers.append(DnsResourceRecord.create_a("a.com", "1.2.3.4"))
        assert ts._has_cname(msg) is False

    def test_has_referral(self):
        ts = TaskStack()
        msg = DnsMessage.create_query("test.com")
        msg.authorities.append(DnsResourceRecord.create_ns("test.com", "ns.test.com"))
        assert ts._has_referral(msg) is True

    def test_has_referral_soa_is_not(self):
        """SOA 不是 referral."""
        ts = TaskStack()
        msg = DnsMessage.create_query("test.com")
        msg.authorities.append(
            DnsResourceRecord(
                name="test.com", rr_type=6, rdata="soa"
            )
        )
        assert ts._has_referral(msg) is False

    def test_handle_answer(self, sample_a_response):
        ts = TaskStack()
        task = Task(domain="www.example.com", status=TaskStatus.PENDING)
        ts._handle_answer(sample_a_response, task)
        assert task.status == TaskStatus.FINISHED
        assert ts._result_data is not None
        assert ts._result_data.answer_ip == "93.184.216.34"

    def test_handle_answer_overwrite_guard(self, sample_a_response):
        """已有 _result_data 时抛 RuntimeError."""
        ts = TaskStack()
        ts._result_data = TaskResult(error="existing")
        task = Task(domain="test.com", status=TaskStatus.PENDING)
        with pytest.raises(RuntimeError, match="准备覆盖未消费的 _result_data"):
            ts._handle_answer(sample_a_response, task)

    def test_handle_answer_ipv6(self):
        """AAAA 记录的 answer_ip 提取."""
        ts = TaskStack()
        query = DnsMessage.create_query("test.com", "AAAA")
        resp = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_aaaa("test.com", "::1")],
        )
        task = Task(domain="test.com", status=TaskStatus.PENDING)
        ts._handle_answer(resp, task)
        assert ts._result_data.answer_ip == "::1"

    def test_handle_cname(self):
        ts = TaskStack()
        query = DnsMessage.create_query("alias.com", "A")
        resp = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_cname("alias.com", "target.com")],
        )
        task = Task(domain="alias.com", status=TaskStatus.PENDING)
        ts._handle_cname(resp, task)
        assert task.status == TaskStatus.CNAME
        # 子域名被压栈
        assert ts._peek().domain == "target.com"

    def test_handle_cname_already_visited(self):
        """已 visit 过的不再 push."""
        ts = TaskStack()
        ts._mark_visited("target.com")
        query = DnsMessage.create_query("alias.com", "A")
        resp = DnsMessage.create_response(
            query,
            answers=[DnsResourceRecord.create_cname("alias.com", "target.com")],
        )
        task = Task(domain="alias.com", status=TaskStatus.PENDING)
        ts._handle_cname(resp, task)
        # visited 已在集合中，不 push 子任务
        assert ts._is_empty() is True

    def test_handle_referral(self, sample_ns_noglue):
        ts = TaskStack()
        task = Task(domain="example.com", status=TaskStatus.PENDING)
        ts._handle_referral(sample_ns_noglue, task)
        assert task.status == TaskStatus.PAUSED
        assert ts._peek().domain == "ns1.example.com"  # 子任务

    def test_handle_noerror_empty(self):
        """NOERROR 空答案：返回 rcode=0 的响应，非错误."""
        ts = TaskStack()
        query = DnsMessage.create_query("test.com", "AAAA")
        resp = DnsMessage.create_response(query, rcode=0)  # 无答案
        task = Task(domain="test.com", status=TaskStatus.PENDING)
        ts._handle_noerror_empty(resp, task)
        assert task.status == TaskStatus.FINISHED
        assert ts._result_data is not None
        assert ts._result_data.error is None  # 非错误
        assert ts._result_data.response is not None
        assert ts._result_data.response.header.rcode == 0
