"""
logger.py — 完整集成测试。

覆盖: setup_logger (幂等/参数) / set_request_context / clear_request_context /
      _ContextFilter
共 ~5 个测试函数。
"""

from __future__ import annotations

import io
import logging
import os
from unittest.mock import patch

import pytest

from logger import (
    _ContextFilter,
    _initialized,
    _request_ctx,
    clear_request_context,
    set_request_context,
    setup_logger,
)


# ════════════════════════════════════════════════════════════════
# setup_logger
# ════════════════════════════════════════════════════════════════


class TestSetupLogger:
    def teardown_method(self):
        """每个测试后重置全局状态."""
        import logger as logger_mod
        logger_mod._initialized = False
        # 清除 root logger 的 handlers
        root = logging.getLogger()
        root.handlers.clear()

    def test_basic_setup(self):
        """基本配置不抛出异常."""
        setup_logger(level=logging.INFO)
        root = logging.getLogger()
        assert len(root.handlers) >= 1

    def test_idempotent(self):
        """重复调用不增加 handler."""
        setup_logger(level=logging.INFO)
        handler_count = len(logging.getLogger().handlers)
        setup_logger(level=logging.DEBUG)
        assert len(logging.getLogger().handlers) == handler_count

    def test_console_disabled(self):
        """console=False 时不添加非文件 StreamHandler."""
        setup_logger(level=logging.INFO, console=False)
        root = logging.getLogger()
        # RotatingFileHandler 继承 StreamHandler，需要排除文件 handler
        console_handlers = [
            h for h in root.handlers
            if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert len(console_handlers) == 0

    def test_custom_log_file(self, tmp_path):
        """指定日志文件路径."""
        log_file = os.path.join(str(tmp_path), "test.log")
        setup_logger(level=logging.INFO, file=log_file)
        assert os.path.exists(log_file)

    def test_level_debug(self):
        """DEBUG 级别可设置."""
        setup_logger(level=logging.DEBUG)
        assert logging.getLogger().level == logging.DEBUG


# ════════════════════════════════════════════════════════════════
# 请求上下文
# ════════════════════════════════════════════════════════════════


class TestRequestContext:
    def test_set_and_clear(self):
        """set → context 非空 → clear → 空."""
        set_request_context("req123", "www.example.com", 1)
        ctx = _request_ctx.get()
        assert ctx["request_id"] == "req123"
        assert ctx["domain"] == "www.example.com"
        assert ctx["qtype"] == "1"

        clear_request_context()
        ctx2 = _request_ctx.get()
        assert ctx2 == {}

    def test_qtype_as_string(self):
        """qtype 为字符串时保持."""
        set_request_context("req1", "test.com", "A")
        ctx = _request_ctx.get()
        assert ctx["qtype"] == "A"

    def test_default_context_empty(self):
        """未设置时字段为 '-'."""
        clear_request_context()  # 确保无残留
        ctx = _request_ctx.get()
        assert ctx == {}  # 默认空 dict


# ════════════════════════════════════════════════════════════════
# _ContextFilter
# ════════════════════════════════════════════════════════════════


class TestContextFilter:
    def test_injects_fields(self):
        """filter 向 LogRecord 注入 request_id/domain/qtype."""
        clear_request_context()
        set_request_context("abc123", "test.com", "1")

        filt = _ContextFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="test", args=(),
            exc_info=None,
        )
        result = filt.filter(record)
        assert result is True  # filter 返回 True
        assert record.request_id == "abc123"
        assert record.domain == "test.com"
        assert record.qtype == "1"

    def test_default_fields(self):
        """未设置 context 时使用 '-'."""
        clear_request_context()
        filt = _ContextFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="test", args=(),
            exc_info=None,
        )
        filt.filter(record)
        assert record.request_id == "-"
        assert record.domain == "-"
        assert record.qtype == "-"
