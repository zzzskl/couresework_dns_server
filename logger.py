#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 协议栈统一日志。

用法 — 在进程入口处调用一次:
    from logger import setup_logger
    setup_logger(level=logging.INFO)

各模块使用标准 logging.getLogger(__name__):
    import logging
    log = logging.getLogger(__name__)
    log.info("...")
    log.debug("...")
    log.warning("...")
    log.error("...")
"""

import logging
import sys
from pathlib import Path

# ══════════════════════════════════════════════════════════════════
# 默认配置
# ══════════════════════════════════════════════════════════════════

_LOG_DIR = Path(__file__).resolve().parent / "logs"
_LOG_FILE = _LOG_DIR / "dns_stack.log"

_FORMAT = "%(asctime)s [%(levelname)-5s] [%(name)s] %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"

_initialized = False


# ══════════════════════════════════════════════════════════════════
# 配置函数
# ══════════════════════════════════════════════════════════════════


def setup_logger(
    *,
    level: int = logging.INFO,
    file: str | None = None,
    console: bool = True,
) -> None:
    """
    配置全局日志（在进程入口处调用一次，重复调用无副作用）。

    Args:
        level:   logging.DEBUG / INFO / WARNING / ERROR
        file:    日志文件路径。默认 None 表示使用 logs/dns_stack.log
        console: 是否同时输出到控制台（默认 True）
    """
    global _initialized
    if _initialized:
        return

    root = logging.getLogger()
    root.setLevel(level)
    # 清除已有 handler，避免重复添加
    root.handlers.clear()

    fmt = logging.Formatter(_FORMAT, _DATE_FMT)

    # ── 文件输出 ──────────────────────────────────────
    log_path = Path(file).resolve() if file else _LOG_FILE
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(str(log_path), encoding="utf-8", mode="a")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # ── 控制台输出 ────────────────────────────────────
    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        root.addHandler(ch)

    _initialized = True
