"""
DNS 编排器测试套件 — 覆盖三步解析的所有路径。

测试场景:
  1. Cache HIT  → 不碰 DB 和 Engine
  2. DB HIT     → 回填 Cache 后返回
  3. Engine OK  → 回填 DB 后返回
  4. Engine FAIL → 返回 None
  5. DB→Cache 推广 — DB 命中后，后续请求从 Cache 直接命中
"""

from __future__ import annotations

import asyncio

import pytest

from dns_cache import DnsCache
from dns_database import DnsDatabase
from dns_iterative.engine import ResolutionEngine
from dns_orchestrator import DnsOrchestrator
from dns_transport import DnsMessage
from dns_types import DnsHeader, DnsResourceRecord


# ── 辅助函数 ──────────────────────────────────────────────────────

def _msg(answers=None, rcode=0) -> DnsMessage:
    """快速构造测试用 DnsMessage。"""
    return DnsMessage(
        header=DnsHeader(rcode=rcode, qr=1),
        questions=[],
        answers=answers or [],
        authorities=[],
        additionals=[],
    )


# ── Mock Engine ───────────────────────────────────────────────────

class MockEngine:
    """可编程的 ResolutionEngine mock — 不继承，鸭子类型即可。"""

    def __init__(self):
        self.call_count = 0
        self._result: DnsMessage | None = None
        self._cache: DnsCache | None = None

    def set_result(self, result: DnsMessage | None):
        self._result = result

    def set_cache(self, cache: DnsCache):
        """模拟 ResolutionEngine 接收 cache 引用的行为。"""
        self._cache = cache

    async def resolve(self, domain: str, qtype: int = 1) -> DnsMessage | None:
        self.call_count += 1
        result = self._result

        # 如果 engine 有 cache 引用，模拟 engine 内部写 cache 的行为
        if self._cache is not None and result is not None:
            self._cache.set_answer(domain, qtype, 1, result)

        return result


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def cache():
    return DnsCache()


@pytest.fixture
def db():
    database = DnsDatabase(":memory:")
    yield database
    database.close()


@pytest.fixture
def mock_engine():
    return MockEngine()


@pytest.fixture
def orchestrator(cache, db, mock_engine):
    return DnsOrchestrator(cache=cache, database=db, engine=mock_engine)


@pytest.fixture
def sample_a_response() -> DnsMessage:
    return _msg(answers=[DnsResourceRecord.create_a("www.example.com", "1.2.3.4")])


# ══════════════════════════════════════════════════════════════════
# 1. Cache HIT
# ══════════════════════════════════════════════════════════════════


def test_cache_hit_returns_immediately(
    orchestrator, cache, db, mock_engine, sample_a_response,
):
    """Cache 命中时直接返回，不查询 DB 和 Engine。"""
    # 预填 cache
    cache.set_answer("www.example.com", 1, 1, sample_a_response)

    result = asyncio.run(orchestrator.resolve("www.example.com", 1))

    assert result is not None
    assert result.answers[0].rdata == "1.2.3.4"
    assert mock_engine.call_count == 0, "Engine 不应被调用"

    # DB 不应有此条目
    assert db.get_answer("www.example.com", 1) is None


def test_cache_hit_does_not_touch_db_engine(
    orchestrator, cache, mock_engine,
):
    """Cache 命中时 DB 和 Engine 都无调用。"""
    cache.set_answer("cache-only.com", 1, 1, _msg(
        answers=[DnsResourceRecord.create_a("cache-only.com", "10.0.0.1")],
    ))
    result = asyncio.run(orchestrator.resolve("cache-only.com", 1))

    assert result is not None
    assert result.answers[0].rdata == "10.0.0.1"
    assert mock_engine.call_count == 0


# ══════════════════════════════════════════════════════════════════
# 2. DB HIT
# ══════════════════════════════════════════════════════════════════


def test_db_hit_returns_and_populates_cache(
    orchestrator, cache, db, mock_engine, sample_a_response,
):
    """DB 命中时返回结果，并将结果回填到 Cache。"""
    # 预填 DB，不清 cache
    db.set_answer("www.example.com", 1, 1, sample_a_response)

    result = asyncio.run(orchestrator.resolve("www.example.com", 1))

    assert result is not None
    assert result.answers[0].rdata == "1.2.3.4"
    assert mock_engine.call_count == 0, "Engine 不应被调用"

    # Cache 应已被回填
    cached = cache.get_answer("www.example.com", 1)
    assert cached is not None
    assert cached.answers[0].rdata == "1.2.3.4"


def test_db_hit_subsequent_cache_hit(
    orchestrator, cache, db, mock_engine, sample_a_response,
):
    """DB 命中后，下一次请求直接从 Cache 命中（不再查 DB）。"""
    db.set_answer("example.com", 1, 1, sample_a_response)

    # 第一次：DB hit → 回填 cache
    r1 = asyncio.run(orchestrator.resolve("example.com", 1))
    assert r1 is not None

    # 从 DB 中删除条目，验证第二次走的是 cache
    db.delete("example.com", 1)

    r2 = asyncio.run(orchestrator.resolve("example.com", 1))
    assert r2 is not None
    assert r2.answers[0].rdata == "1.2.3.4"
    assert mock_engine.call_count == 0


# ══════════════════════════════════════════════════════════════════
# 3. Engine OK
# ══════════════════════════════════════════════════════════════════


def test_engine_resolve_populates_db(
    orchestrator, cache, db, mock_engine, sample_a_response,
):
    """Engine 成功解析后，结果应写入 DB。"""
    mock_engine.set_result(sample_a_response)

    result = asyncio.run(orchestrator.resolve("www.example.com", 1))

    assert result is not None
    assert result.answers[0].rdata == "1.2.3.4"
    assert mock_engine.call_count == 1

    # DB 应有条目
    db_result = db.get_answer("www.example.com", 1)
    assert db_result is not None
    assert db_result.answers[0].rdata == "1.2.3.4"


def test_engine_result_also_in_cache_via_shared_instance(
    orchestrator, cache, db, mock_engine, sample_a_response,
):
    """Engine 有 cache 引用时，结果在内存和 DB 中都存在。"""
    # 模拟 engine 内部写 cache 的行为（类似 ResolutionEngine）
    mock_engine.set_cache(cache)
    mock_engine.set_result(sample_a_response)

    result = asyncio.run(orchestrator.resolve("www.example.com", 1))

    assert result is not None

    # Cache 应有（engine 内部写入）
    cached = cache.get_answer("www.example.com", 1)
    assert cached is not None

    # DB 应有（orchestrator 写入）
    db_result = db.get_answer("www.example.com", 1)
    assert db_result is not None


# ══════════════════════════════════════════════════════════════════
# 4. Engine FAIL
# ══════════════════════════════════════════════════════════════════


def test_all_miss_returns_none(
    orchestrator, cache, db, mock_engine,
):
    """Cache、DB、Engine 全 miss 时返回 None。"""
    mock_engine.set_result(None)

    result = asyncio.run(orchestrator.resolve("unknown.example.com", 1))
    assert result is None
    assert mock_engine.call_count == 1


def test_engine_failure_does_not_write_db(
    orchestrator, db, mock_engine,
):
    """Engine 解析失败时不应写 DB。"""
    mock_engine.set_result(None)

    result = asyncio.run(orchestrator.resolve("fail.example.com", 1))
    assert result is None
    assert db.get_answer("fail.example.com", 1) is None


# ══════════════════════════════════════════════════════════════════
# 5. 边界 & 组合
# ══════════════════════════════════════════════════════════════════


def test_different_qtype_flow_independently(
    orchestrator, cache, db, mock_engine,
):
    """不同 qtype 的解析路径互不干扰。"""
    a_resp = _msg(answers=[DnsResourceRecord.create_a("x.com", "1.1.1.1")])
    aaaa_resp = _msg(answers=[DnsResourceRecord.create_aaaa("x.com", "::1")])

    # A 记录放 DB，AAAA 放 cache
    db.set_answer("x.com", 1, 1, a_resp)
    cache.set_answer("x.com", 28, 1, aaaa_resp)

    r_a = asyncio.run(orchestrator.resolve("x.com", 1))
    assert r_a is not None and r_a.answers[0].rdata == "1.1.1.1"

    r_aaaa = asyncio.run(orchestrator.resolve("x.com", 28))
    assert r_aaaa is not None and r_aaaa.answers[0].rdata == "::1"

    assert mock_engine.call_count == 0  # 都不需要 engine


# ══════════════════════════════════════════════════════════════════
# 6. 防御测试 — 不同 cache 实例隔离
# ══════════════════════════════════════════════════════════════════


def test_orchestrator_engine_different_cache_instances(db):
    """Orchestrator 和 Engine 使用不同 cache 实例时，Engine 内部
    缓存不污染 Orchestrator 的 cache。"""
    cache_orch = DnsCache()    # Orchestrator 的 cache
    cache_eng = DnsCache()     # Engine 内部使用的 cache（不同实例）
    engine = MockEngine()
    engine.set_cache(cache_eng)  # engine 只感知 cache_eng

    orch = DnsOrchestrator(cache=cache_orch, database=db, engine=engine)

    a_resp = _msg(answers=[DnsResourceRecord.create_a("separate.example.com", "5.6.7.8")])
    engine.set_result(a_resp)

    result = asyncio.run(orch.resolve("separate.example.com", 1))

    assert result is not None
    assert result.answers[0].rdata == "5.6.7.8"

    # orchestrator 的 cache 不应有结果（engine 写入了 cache_eng）
    assert cache_orch.get_answer("separate.example.com", 1) is None, \
        "Orchestrator cache 不应被 engine 内部 cache 污染"

    # engine 的 cache 应有结果
    assert cache_eng.get_answer("separate.example.com", 1) is not None

    # DB 应有结果（orchestrator 在 engine 成功后写入 DB）
    assert db.get_answer("separate.example.com", 1) is not None
