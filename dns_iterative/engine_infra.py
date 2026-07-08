"""
engine_infra.py — 栈状态机基础设施纯原语层。

纯原语层，不含任何 DNS 概念，供具体栈继承使用。
所属层: Layer 1
"""

from __future__ import annotations

import abc
from enum import Enum
from typing import Any, Generic, Optional, TypeVar

T = TypeVar("T")
S = TypeVar("S", bound=Enum)


class StackBase(abc.ABC, Generic[T]):
    """
    通用栈原语。

    提供 push / peek / pop / is_empty / clear 操作，内置 max_depth 保护。
    具体栈（QueryStack、TaskStack）继承本类并使用。
    """

    def __init__(self, max_depth: int = 0) -> None:
        """
        Args:
            max_depth: 栈最大深度，0 表示不限制。
        """
        self._stack: list[T] = []
        self._max_depth = max_depth

    def _push(self, item: T) -> None:
        """压栈。深度超限时抛 RuntimeError。"""
        if self._max_depth > 0 and len(self._stack) >= self._max_depth:
            raise RuntimeError(f"Stack 深度超限 ({self._max_depth})")
        self._stack.append(item)

    def _peek(self) -> T:
        """查看栈顶元素。空栈抛 RuntimeError。"""
        if not self._stack:
            raise RuntimeError("peek 空栈")
        return self._stack[-1]

    def _pop(self) -> T:
        """弹出栈顶元素。空栈抛 RuntimeError。"""
        if not self._stack:
            raise RuntimeError("pop 空栈")
        return self._stack.pop()

    def _is_empty(self) -> bool:
        """栈是否为空。"""
        return len(self._stack) == 0

    def _clear(self) -> None:
        """清空栈。"""
        self._stack.clear()


class StateMachineBase(abc.ABC, Generic[S]):
    """
    通用状态机原语。

    提供 _set_status / get_status / _transition 操作，以及状态进入/离开钩子。
    子类必须实现 run()，遵循 while 循环 + 状态检查 + 分支派发的标准模式。

    _transition(to, *from, **data):
        - 验证当前状态在 from 中（from 为空时不验证）
        - data 透传到 _on_state_enter，用于携带状态级必须动作的数据
        - 子类在 _on_state_enter 中实施状态约束
    """

    def __init__(self) -> None:
        self._status: Optional[S] = None

    def _set_status(self, status: S) -> None:
        """初始化或硬设状态（不受守卫保护，用于初始设置）。"""
        self._status = status

    def get_status(self) -> Optional[S]:
        """读取当前状态。"""
        return self._status

    def _transition(self, to_state: S, *from_states: S, **data: Any) -> None:
        """
        受守卫状态转换。

        Args:
            to_state: 目标状态。
            from_states: 允许的源状态（为空时不验证）。
            **data: 动作数据，透传到 _on_state_enter。

        Raises:
            RuntimeError: 当前状态不在 from_states 中。
        """
        if from_states and self._status not in from_states:
            raise RuntimeError(
                f"非法状态转换: {self._status} → {to_state}, "
                f"期望: {'|'.join(str(s) for s in from_states)}"
            )
        old = self._status
        self._on_state_exit(old)
        self._status = to_state
        self._on_state_enter(to_state, data)

    def _on_state_exit(self, state: Optional[S]) -> None:
        """离开某状态时的钩子。子类可重写。"""

    def _on_state_enter(self, state: S, data: dict[str, Any]) -> None:
        """进入某状态时的钩子。子类可在此实施状态级必须动作。"""

    @abc.abstractmethod
    async def run(self) -> None:
        """
        状态机主循环。

        必须实现 while 循环 + 状态检查 + 分支派发的标准模式。
        此方法表达控制权流转语义。
        """


def transition_status(elem: Any, to_state: Enum, *from_states: Enum, **data: Any) -> None:
    """
    元素级状态守卫工具函数。

    用于 TaskStack 等需要管理元素级状态（而非整个栈状态）的场景。
    接收可选的 **data 以保持 API 一致，供后续扩展。

    Args:
        elem: 拥有 .status 属性的对象。
        to_state: 目标状态。
        from_states: 允许的源状态（为空时不验证）。

    Raises:
        RuntimeError: 当前状态不在 from_states 中。
    """
    if from_states and elem.status not in from_states:
        raise RuntimeError(
            f"非法状态转换: {elem.status} → {to_state}, "
            f"期望: {'|'.join(str(s) for s in from_states)}"
        )
    elem.status = to_state



