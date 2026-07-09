"""
dns_iterative/models.py — 完整集成测试。

覆盖: TaskStatus / QueryStatus / 枚举值 / Task / TaskResult / QueryResult
共 ~8 个测试函数。
"""

from __future__ import annotations

import pytest

from dns_iterative.models import (
    QueryResult,
    QueryStatus,
    Task,
    TaskResult,
    TaskStatus,
)
from dns_types import DnsMessage


# ════════════════════════════════════════════════════════════════
# TaskStatus / QueryStatus 枚举
# ════════════════════════════════════════════════════════════════


class TestEnums:
    def test_task_status_values(self):
        """TaskStatus 各成员存在且值唯一."""
        values = list(TaskStatus)
        assert TaskStatus.NEW in values
        assert TaskStatus.PENDING in values
        assert TaskStatus.CNAME in values
        assert TaskStatus.PAUSED in values
        assert TaskStatus.FINISHED in values
        # 验证 auto 生成了不同值
        assert len({s.value for s in values}) == len(values)

    def test_query_status_values(self):
        values = list(QueryStatus)
        assert QueryStatus.READY in values
        assert QueryStatus.SENT in values
        assert QueryStatus.FINISHED in values
        assert len({s.value for s in values}) == len(values)


# ════════════════════════════════════════════════════════════════
# Task
# ════════════════════════════════════════════════════════════════


class TestTask:
    def test_defaults(self):
        task = Task(domain="www.example.com")
        assert task.domain == "www.example.com"
        assert task.status == TaskStatus.NEW
        assert task.qtype == 1

    def test_custom_qtype(self):
        task = Task(domain="www.example.com", qtype=28)
        assert task.qtype == 28

    def test_custom_status(self):
        task = Task(domain="test.com", status=TaskStatus.FINISHED)
        assert task.status == TaskStatus.FINISHED

    def test_mutable_fields(self):
        task = Task(domain="test.com")
        task.status = TaskStatus.PENDING
        assert task.status == TaskStatus.PENDING


# ════════════════════════════════════════════════════════════════
# TaskResult
# ════════════════════════════════════════════════════════════════


class TestTaskResult:
    def test_defaults(self):
        r = TaskResult()
        assert r.response is None
        assert r.answer_ip is None
        assert r.error is None

    def test_all_fields(self):
        msg = DnsMessage.create_query("test.com")
        r = TaskResult(response=msg, answer_ip="1.2.3.4", error=None)
        assert r.response is not None
        assert r.answer_ip == "1.2.3.4"
        assert r.error is None

    def test_error_only(self):
        r = TaskResult(error="timeout")
        assert r.response is None
        assert r.error == "timeout"


# ════════════════════════════════════════════════════════════════
# QueryResult
# ════════════════════════════════════════════════════════════════


class TestQueryResult:
    def test_defaults(self):
        r = QueryResult()
        assert r.response is None
        assert r.error is None

    def test_with_response(self):
        msg = DnsMessage.create_query("test.com")
        r = QueryResult(response=msg)
        assert r.response is not None
        assert r.error is None

    def test_with_error(self):
        r = QueryResult(error="all targets failed")
        assert r.response is None
        assert r.error == "all targets failed"
