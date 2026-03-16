"""
wrappers/__init__.py - Wrapper registry and governance execution boundary.

ARCHITECTURAL RULE: Every governed tool action must pass through a registered
wrapper. There is no other lawful execution path.
"""

from __future__ import annotations

from wrappers.base import BaseWrapper, ExecutionContext, WrapperResult
from wrappers.filesystem import FilesystemWrapper
from wrappers.http import HttpWrapper
from wrappers.messaging import MessagingWrapper
from wrappers.shell import ShellWrapper

_REGISTRY: dict[str, type[BaseWrapper]] = {
    "shell": ShellWrapper,
    "http": HttpWrapper,
    "filesystem": FilesystemWrapper,
    "messaging": MessagingWrapper,
}


class UnregisteredToolFamily(Exception):
    """Raised when no governed wrapper is registered for a tool family."""

    def __init__(self, tool_family: str) -> None:
        self.tool_family = tool_family
        self.reason_code = "UNREGISTERED_TOOL_FAMILY"
        super().__init__(
            f"No governed wrapper registered for tool_family='{tool_family}'. "
            "Every governed tool must have a wrapper before it can be executed."
        )


def get_wrapper(tool_family: str, context: ExecutionContext | None = None) -> BaseWrapper:
    """Return an initialized wrapper instance for the given tool_family."""

    cls = _REGISTRY.get(tool_family)
    if cls is None:
        raise UnregisteredToolFamily(tool_family)
    return cls(context=context)


def registered_families() -> list[str]:
    """Return the list of tool families that have registered wrappers."""

    return list(_REGISTRY.keys())


__all__ = [
    "get_wrapper",
    "registered_families",
    "UnregisteredToolFamily",
    "BaseWrapper",
    "ExecutionContext",
    "WrapperResult",
]