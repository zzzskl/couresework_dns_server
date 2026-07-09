#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 数据库持久化层 — SQLite 实现。

与 DnsCache 接口对称的持久化存储层，使用 SQLite 存储 DNS 缓存条目。
Record 列表使用 JSON 序列化（复用 DnsResourceRecord.to_dict / from_dict）。

API 与 DnsCache 一致:
    get_answer / set_answer / get_delegation / set_delegation / delete

用法:
    db = DnsDatabase("data/dns_cache.db")
    try:
        msg = db.get_answer("www.example.com", 1)
        db.set_answer("www.example.com", 1, 1, response_msg)
    finally:
        db.close()
    # 注意：DnsDatabase 未实现 __enter__/__exit__ 上下文管理器协议，
    # 调用方需自行管理 close()，推荐使用 try/finally。

分层归属 — Layer 2.5 持久化数据访问:
    与 DnsCache（Layer 2 内存缓存）平级且对称，
    均由 DnsOrchestrator（Layer 3）显式编排调用。
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from dns_common import min_ttl_from_message
from dns_types import DnsMessage, DnsResourceRecord

log = logging.getLogger(__name__)

# 默认数据库路径（相对于项目根目录）
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data",
    "dns_cache.db",
)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dns_cache (
    domain      TEXT NOT NULL,
    qtype       INTEGER NOT NULL,
    qclass      INTEGER NOT NULL DEFAULT 1,
    answers     TEXT NOT NULL DEFAULT '[]',
    authorities TEXT NOT NULL DEFAULT '[]',
    additionals TEXT NOT NULL DEFAULT '[]',
    rcode       INTEGER NOT NULL DEFAULT 0,
    expires_at  REAL NOT NULL,
    is_negative INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (domain, qtype, qclass)
)
"""


class DnsDatabase:
    """
    DNS 数据库持久化层。

    接口与 DnsCache 对称，提供 get_answer / set_answer / get_delegation /
    set_delegation。所有操作同步执行，由调用方（DnsOrchestrator）负责
    在合适时机调用。

    线程安全：SQLite WAL 模式下读读不阻塞，写写串行。
    对演示项目场景完全足够。

    注意：未实现 __enter__/__exit__ 上下文管理器协议，
    调用方需手动调用 close()，推荐使用 try/finally 确保释放。
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Args:
            db_path: SQLite 文件路径，默认 ``data/dns_cache.db``。
                     传入 ``:memory:`` 可创建临时内存数据库（用于测试）。
        """
        self._db_path = db_path or DEFAULT_DB_PATH

        # 确保目录存在（:memory: 不需要创建目录）
        if self._db_path != ":memory:":
            db_dir = os.path.dirname(self._db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_SCHEMA_SQL)
        self._conn.commit()

        log.info("DnsDatabase opened: %s", self._db_path)

    # ══════════════════════════════════════════════════════════════
    # 序列化辅助
    # ══════════════════════════════════════════════════════════════

    @staticmethod
    def _rr_to_json(rrs: List[DnsResourceRecord]) -> str:
        """RR 列表 → JSON 字符串。"""
        return json.dumps([r.to_dict() for r in rrs], ensure_ascii=False)

    @staticmethod
    def _json_to_rr(json_str: str) -> List[DnsResourceRecord]:
        """JSON 字符串 → RR 列表。"""
        try:
            data = json.loads(json_str) if json_str else []
            return [DnsResourceRecord.from_dict(d) for d in data]
        except (json.JSONDecodeError, TypeError, ValueError):
            log.warning("DB JSON deserialize failed, returning empty list")
            return []

    # ══════════════════════════════════════════════════════════════
    # 答案缓存
    # ══════════════════════════════════════════════════════════════

    def get_answer(
        self,
        domain: str,
        qtype: int,
        qclass: int = 1,
    ) -> Optional[DnsMessage]:
        """
        从数据库获取缓存的 DNS 答案。

        如果条目已过期则自动删除并返回 None（懒清理模式）。
        返回的 DnsMessage 不含 questions 节（由调用方补齐）。
        """
        try:
            cursor = self._conn.execute(
                "SELECT * FROM dns_cache WHERE domain=? AND qtype=? AND qclass=?",
                (domain.lower(), qtype, qclass),
            )
            row = cursor.fetchone()
            if row is None:
                return None

            # 懒过期清理
            now = time.time()
            if now >= row["expires_at"]:
                self._conn.execute(
                    "DELETE FROM dns_cache WHERE domain=? AND qtype=? AND qclass=?",
                    (domain.lower(), qtype, qclass),
                )
                self._conn.commit()
                return None

            # 从 JSON 重建 RR 列表
            answers = self._json_to_rr(row["answers"])
            authorities = self._json_to_rr(row["authorities"])
            additionals = self._json_to_rr(row["additionals"])

            msg = DnsMessage(
                answers=answers,
                authorities=authorities,
                additionals=additionals,
            )
            msg.header.qr = 1
            msg.header.rcode = row["rcode"]
            msg.header.ra = 1

            return msg

        except sqlite3.Error as e:
            log.warning("DB query error (get_answer): %s", e)
            return None

    def set_answer(
        self,
        domain: str,
        qtype: int,
        qclass: int,
        msg: DnsMessage,
        ttl: Optional[int] = None,
        is_negative: bool = False,
    ) -> None:
        """
        将 DNS 答案写入数据库。

        Args:
            domain:      查询域名
            qtype:       查询类型
            qclass:      查询类别
            msg:         DNS 响应报文
            ttl:         缓存 TTL（秒），默认取 msg 中最小 TTL
            is_negative: 是否为负缓存
        """
        try:
            if ttl is None:
                ttl = min_ttl_from_message(msg)

            # 注: ttl=0 时 expires_at ≈ time.time()，条目立即过期。
            # 下次 get_answer 访问时触发懒清理（过期判断 → 删除 → 返回 None）。
            # 这是设计使然，允许调用方通过 ttl=0 写入"立即可丢弃"的条目。
            expires_at = time.time() + ttl

            self._conn.execute(
                """INSERT OR REPLACE INTO dns_cache
                   (domain, qtype, qclass, answers, authorities, additionals,
                    rcode, expires_at, is_negative)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    domain.lower(),
                    qtype,
                    qclass,
                    self._rr_to_json(msg.answers),
                    self._rr_to_json(msg.authorities),
                    self._rr_to_json(msg.additionals),
                    msg.header.rcode,
                    expires_at,
                    1 if is_negative else 0,
                ),
            )
            self._conn.commit()

        except sqlite3.Error as e:
            log.warning("DB write error (set_answer): %s", e)

    # ══════════════════════════════════════════════════════════════
    # 委派缓存
    # ══════════════════════════════════════════════════════════════

    def get_delegation(
        self,
        domain: str,
    ) -> Optional[Tuple[List[DnsResourceRecord], List[DnsResourceRecord]]]:
        """
        获取委派缓存（NS 记录 + glue A/AAAA）。

        Returns:
            (ns_records, glue_records) 或 None。
        """
        try:
            row = self._conn.execute(
                "SELECT * FROM dns_cache WHERE domain=? AND qtype=2 AND qclass=1",
                (domain.lower(),),
            ).fetchone()

            if row is None:
                return None

            # 过期检查
            now = time.time()
            if now >= row["expires_at"]:
                self._conn.execute(
                    "DELETE FROM dns_cache WHERE domain=? AND qtype=2 AND qclass=1",
                    (domain.lower(),),
                )
                self._conn.commit()
                return None

            ns_records = self._json_to_rr(row["answers"])
            glue_records = self._json_to_rr(row["additionals"])

            return (ns_records, glue_records)

        except sqlite3.Error as e:
            log.warning("DB query error (get_delegation): %s", e)
            return None

    def set_delegation(
        self,
        domain: str,
        ns_records: List[DnsResourceRecord],
        glue_records: List[DnsResourceRecord],
        ttl: int = 3600,
    ) -> None:
        """
        写入委派缓存。

        Args:
            domain:       域名
            ns_records:   NS 记录列表
            glue_records: 对应的 A/AAAA glue 记录列表
            ttl:          缓存 TTL（默认 3600s = 1h）
        """
        try:
            expires_at = time.time() + ttl
            self._conn.execute(
                """INSERT OR REPLACE INTO dns_cache
                   (domain, qtype, qclass, answers, authorities, additionals,
                    rcode, expires_at, is_negative)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    domain.lower(),
                    2,  # NS qtype
                    1,  # IN class
                    self._rr_to_json(ns_records),
                    '[]',
                    self._rr_to_json(glue_records),
                    0,
                    expires_at,
                    0,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as e:
            log.warning("DB write error (set_delegation): %s", e)

    # ══════════════════════════════════════════════════════════════
    # 通用操作
    # ══════════════════════════════════════════════════════════════

    def delete(
        self,
        domain: str,
        qtype: int,
        qclass: int = 1,
    ) -> bool:
        """删除缓存条目，返回是否存在。"""
        try:
            cursor = self._conn.execute(
                "DELETE FROM dns_cache WHERE domain=? AND qtype=? AND qclass=?",
                (domain.lower(), qtype, qclass),
            )
            self._conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            log.warning("DB delete error: %s", e)
            return False

    def clear(self) -> None:
        """清空全部缓存。"""
        try:
            self._conn.execute("DELETE FROM dns_cache")
            self._conn.commit()
        except sqlite3.Error as e:
            log.warning("DB clear error: %s", e)

    def close(self) -> None:
        """关闭数据库连接。"""
        try:
            self._conn.close()
            log.info("DnsDatabase closed: %s", self._db_path)
        except sqlite3.Error as e:
            log.warning("DB close error: %s", e)

    @property
    def path(self) -> str:
        """数据库文件路径。"""
        return self._db_path
