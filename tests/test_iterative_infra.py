"""
dns_iterative/engine_infra.py — 完整集成测试。

覆盖: StackBase / StateMachineBase / transition_status
共 ~12 个测试函数。
"""

from __future__ import annotations

from enum import Enum, auto

import pytest

from dns_iterative.engine_infra import StackBase, StateMachineBase, transition_status


# 辅助：用于测试的枚举
class TestStatus(Enum):
    IDLE = auto()
    RUNNING = auto()
    DONE = auto()


# ════════════════════════════════════════════════════════════════
# StackBase
# ════════════════════════════════════════════════════════════════


class TestStackBase:
    def test_push_peek(self):
        s = _ConcreteStack(max_depth=5)
        s._push("item1")
        assert s._peek() == "item1"

    def test_push_pop(self):
        s = _ConcreteStack(max_depth=5)
        s._push("item1")
        s._push("item2")
        assert s._pop() == "item2"
        assert s._pop() == "item1"

    def test_is_empty(self):
        s = _ConcreteStack(max_depth=5)
        assert s._is_empty()
        s._push("x")
        assert not s._is_empty()
        s._pop()
        assert s._is_empty()

    def test_peek_empty(self):
        s = _ConcreteStack(max_depth=5)
        with pytest.raises(RuntimeError, match="peek 空栈"):
            s._peek()

    def test_pop_empty(self):
        s = _ConcreteStack(max_depth=5)
        with pytest.raises(RuntimeError, match="pop 空栈"):
            s._pop()

    def test_max_depth_exceeded(self):
        s = _ConcreteStack(max_depth=2)
        s._push("a")
        s._push("b")
        with pytest.raises(RuntimeError, match="Stack 深度超限"):
            s._push("c")

    def test_no_max_depth(self):
        """max_depth=0 表示不限制."""
        s = _ConcreteStack(max_depth=0)
        for i in range(100):
            s._push(f"item{i}")
        assert s._is_empty() is False

    def test_clear(self):
        s = _ConcreteStack(max_depth=5)
        s._push("a")
        s._push("b")
        s._clear()
        assert s._is_empty()


class _ConcreteStack(StackBase):
    pass


# ════════════════════════════════════════════════════════════════
# StateMachineBase
# ════════════════════════════════════════════════════════════════


class TestStateMachineBase:
    def test_initial_status(self):
        sm = _ConcreteSM()
        assert sm.get_status() is None

    def test_set_status(self):
        sm = _ConcreteSM()
        sm._set_status(TestStatus.IDLE)
        assert sm.get_status() == TestStatus.IDLE

    def test_get_status(self):
        sm = _ConcreteSM()
        sm._set_status(TestStatus.RUNNING)
        assert sm.get_status() == TestStatus.RUNNING

    def test_transition_valid(self):
        sm = _ConcreteSM()
        sm._set_status(TestStatus.IDLE)
        sm._transition(TestStatus.RUNNING, TestStatus.IDLE)
        assert sm.get_status() == TestStatus.RUNNING

    def test_transition_invalid(self):
        sm = _ConcreteSM()
        sm._set_status(TestStatus.IDLE)
        with pytest.raises(RuntimeError, match="非法状态转换"):
            sm._transition(TestStatus.DONE, TestStatus.RUNNING)  # 当前 IDLE 不在 [RUNNING] 中

    def test_transition_without_guard(self):
        """不传 from_states 时不验证."""
        sm = _ConcreteSM()
        sm._set_status(TestStatus.IDLE)
        sm._transition(TestStatus.DONE)  # 无 from 约束
        assert sm.get_status() == TestStatus.DONE

    def test_state_enter_exit_hooks(self):
        sm = _ConcreteSM()
        sm._set_status(TestStatus.IDLE)
        sm._transition(TestStatus.RUNNING, TestStatus.IDLE)
        assert sm._enter_log == [TestStatus.RUNNING]
        assert sm._exit_log == [TestStatus.IDLE]

    def test_transition_data_passed(self):
        sm = _ConcreteSM()
        sm._set_status(TestStatus.IDLE)
        sm._transition(TestStatus.RUNNING, TestStatus.IDLE, extra="data")
        assert sm._last_data == {"extra": "data"}


class _ConcreteSM(StateMachineBase[TestStatus]):
    def __init__(self):
        super().__init__()
        self._enter_log = []
        self._exit_log = []
        self._last_data = {}

    def _on_state_exit(self, state):
        if state is not None:
            self._exit_log.append(state)

    def _on_state_enter(self, state, data):
        self._enter_log.append(state)
        self._last_data = data

    async def run(self):
        pass


# ════════════════════════════════════════════════════════════════
# transition_status
# ════════════════════════════════════════════════════════════════


class TestTransitionStatus:
    def test_valid(self):
        elem = _DummyElem(status=TestStatus.IDLE)
        transition_status(elem, TestStatus.RUNNING, TestStatus.IDLE)
        assert elem.status == TestStatus.RUNNING

    def test_invalid(self):
        elem = _DummyElem(status=TestStatus.IDLE)
        with pytest.raises(RuntimeError, match="非法状态转换"):
            transition_status(elem, TestStatus.DONE, TestStatus.RUNNING)

    def test_no_guard(self):
        elem = _DummyElem(status=TestStatus.IDLE)
        transition_status(elem, TestStatus.DONE)  # 无 from 约束
        assert elem.status == TestStatus.DONE


class _DummyElem:
    def __init__(self, status):
        self.status = status
