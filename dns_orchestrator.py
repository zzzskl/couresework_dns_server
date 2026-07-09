#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 解析编排器 — 显式三步解析：Cache → Database → Engine。

将 DnsCache（内存）、DnsDatabase（SQLite 持久化）、ResolutionEngine（迭代解析）
三个平级组件按序编排，每步显式调用、可观测、可独立 mock。

解析流程：
    ① 内存缓存 (DnsCache)       — 毫秒级，命中即返回
    ② 数据库   (DnsDatabase)    — 毫秒级，命中后回填内存缓存再返回
    ③ 迭代解析 (ResolutionEngine) — 秒级，成功后回填数据库（内存缓存由 engine 内部更新）

分层归属 — Layer 3 业务编排:
    - 不包含任何协议编解码逻辑
    - 不包含任何网络 I/O
    - 纯编排：决定"先查什么，再查什么，最后查什么"

用法:
    cache = DnsCache()
    database = DnsDatabase()
    transport = AsyncUdpTransport()
    engine = ResolutionEngine(transport, cache=cache)  # 共享 cache
    orchestrator = DnsOrchestrator(cache, database, engine)

    result = await orchestrator.resolve("www.example.com", 1)
"""

from __future__ import annotations

import logging
from typing import Optional

from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_iterative.engine import ResolutionEngine
from dns_types import DnsMessage

log = logging.getLogger(__name__)


class DnsOrchestrator:
    """
    DNS 解析编排器。

    三步解析的每一阶段都是显式调用：
        第①步从内存缓存读取
        第②步从数据库读取（命中后推广到内存缓存）
        第③步走迭代解析（成功后推广到数据库）
    """

    def __init__(
        self,
        cache: DnsCache,
        database: DnsDatabase,
        engine: ResolutionEngine,
    ):
        """
        Args:
            cache:    内存缓存实例（建议与 engine 共享同一实例）
            database: SQLite 数据库实例
            engine:   迭代解析引擎实例
        """
        self._cache = cache
        self._database = database
        self._engine = engine

    # ── 属性访问（便于测试时检查状态） ────────────────────────

    @property
    def cache(self) -> DnsCache:
        return self._cache

    @property
    def database(self) -> DnsDatabase:
        return self._database

    @property
    def engine(self) -> ResolutionEngine:
        return self._engine

    # ── 主入口 ────────────────────────────────────────────────

    async def resolve(
        self,
        domain: str,
        qtype: int = 1,
    ) -> Optional[DnsMessage]:
        """
        对指定域名执行三步解析。

        Args:
            domain: 查询域名（如 ``www.example.com``）
            qtype:  查询类型数值（1=A, 28=AAAA，默认 1）

        Returns:
            成功时返回 DNS 响应报文（DnsMessage），
            失败时返回 None。
        """
        # ── 第①步: 内存缓存 ────────────────────────────────────
        hit = self._cache.get_answer(domain, qtype)
        if hit is not None:
            log.info("Step ① Cache HIT  for %s (qtype=%d)", domain, qtype)
            return hit

        # ── 第②步: 数据库 ──────────────────────────────────────
        db_hit = self._database.get_answer(domain, qtype)
        if db_hit is not None:
            log.info("Step ② Database HIT for %s (qtype=%d)", domain, qtype)
            # 回填内存缓存，后续请求可直接命中
            self._cache.set_answer(domain, qtype, 1, db_hit)
            return db_hit

        # ── 第③步: 迭代解析 ────────────────────────────────────
        # 注: engine 内部同样检查 cache（ResolutionEngine._cache_lookup +
        # _enhance_task_stack.cached_push）。由于共享同一 DnsCache 实例，
        # 此处的 cache miss 意味着 engine 内部也会 miss，即 engine 内部
        # 的缓存检查是冗余的（O(1) 字典查询，可忽略不计）。
        # 保留 engine 内部缓存检查的好处：当 engine 被独立使用（不经由
        # Orchestrator）时，缓存仍能正常工作。
        log.info("Step ③ Resolving  %s (qtype=%d) via iterative engine", domain, qtype)
        result = await self._engine.resolve(domain, qtype)

        if result is not None:
            self._database.set_answer(
                domain, qtype, 1, result,
                is_negative=(result.header.rcode != 0),
            )
            # 内存缓存已由 engine 内部写入（共享同一 cache 实例）
            log.info(
                "Resolved %s -> %d answers, written to DB",
                domain,
                len(result.answers),
            )
        else:
            log.warning("Failed to resolve %s (qtype=%d)", domain, qtype)

        return result
