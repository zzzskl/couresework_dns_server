#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 协议栈统一日志。

提供:
  - setup_logger()  — 在进程入口处调用一次（幂等）
  - set_request_context() / clear_request_context() — 为每条请求注入追踪 ID
  - 通过 ContextFilter 自动为所有模块的日志附加 [req=xxx] [domain] [qtype]

用法 — 入口:
    from logger import setup_logger
    setup_logger(level=logging.INFO)

用法 — 各模块（标准 logging，无需改动）:
    import logging
    log = logging.getLogger(__name__)
    log.info("...")
"""

from __future__ import annotations

import logging
import sys
import threading
from contextvars import ContextVar
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict

# ══════════════════════════════════════════════════════════════════
# 默认配置
# ══════════════════════════════════════════════════════════════════

_LOG_DIR = Path(__file__).resolve().parent / "logs"
_LOG_FILE = _LOG_DIR / "dns_stack.log"

_FORMAT = (
    "%(asctime)s [%(levelname)-5s] [%(name)-20s] "
    "[req=%(request_id)s] [%(domain)s] [qtype=%(qtype)s] %(message)s"
)
_DATE_FMT = "%Y-%m-%d %H:%M:%S"

_initialized = False
_init_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════
# 请求上下文（通过 contextvars 跨 await 自动传播）
# ══════════════════════════════════════════════════════════════════

_request_ctx: ContextVar[Dict[str, Any]] = ContextVar("request_ctx", default={})


def set_request_context(request_id: str, domain: str, qtype: int | str) -> None:
    """
    为当前协程/线程设置请求上下文。

    此后所有模块的日志消息会自动附加 [req=xxx] [domain=yyy] [qtype=z]。
    在请求处理完毕后应调用 clear_request_context()。
    """
    _request_ctx.set({
        "request_id": request_id,
        "domain": domain,
        "qtype": str(qtype),
    })


def clear_request_context() -> None:
    """清除当前请求上下文。"""
    _request_ctx.set({})


def is_request_context_set() -> bool:
    """检查当前协程/线程是否已有请求上下文。"""
    return bool(_request_ctx.get())


# ══════════════════════════════════════════════════════════════════
# 上下文过滤器（向每条 LogRecord 注入请求字段）
# ══════════════════════════════════════════════════════════════════


class _ContextFilter(logging.Filter):
    """向 LogRecord 注入 request_id / domain / qtype 字段。

    字段值来源于 ContextVar，若未设置则默认显示 "-"。
    无需修改各模块的日志调用代码。
    """

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = _request_ctx.get()
        record.request_id = ctx.get("request_id", "-")
        record.domain = ctx.get("domain", "-")
        record.qtype = ctx.get("qtype", "-")
        return True


# ══════════════════════════════════════════════════════════════════
# 配置函数
# ══════════════════════════════════════════════════════════════════


def setup_logger(
    *,
    level: int = logging.INFO,
    file: str | None = None,
    console: bool = True,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> None:
    """
    配置全局日志（在进程入口处调用一次，重复调用无副作用）。

    Args:
        level:        logging.DEBUG / INFO / WARNING / ERROR
        file:         日志文件路径。默认 None 表示使用 logs/dns_stack.log
        console:      是否同时输出到控制台（默认 True）
        max_bytes:    单日志文件最大字节数（默认 10 MB）
        backup_count: 保留的历史文件数（默认 5）
    """
    global _initialized
    with _init_lock:
        if _initialized:
            return
        _initialized = True

    root = logging.getLogger()
    root.setLevel(level)
    # 清除已有 handler，避免重复添加
    root.handlers.clear()

    fmt = logging.Formatter(_FORMAT, _DATE_FMT)
    ctx_filter = _ContextFilter()

    # ── 文件输出（带轮转） ──────────────────────────────
    log_path = Path(file).resolve() if file else _LOG_FILE
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = RotatingFileHandler(
        str(log_path),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    fh.addFilter(ctx_filter)
    root.addHandler(fh)

    # ── 控制台输出 ──────────────────────────────────────
    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        ch.addFilter(ctx_filter)
        root.addHandler(ch)

