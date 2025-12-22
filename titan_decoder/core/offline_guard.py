"""Offline-mode network guard.

This module provides a best-effort process-local kill switch that prevents
outbound network connections by monkeypatching Python's socket APIs.

It is intended for defensive tooling workflows where evidence should never be
sent over the network unless explicitly requested.
"""

from __future__ import annotations

from contextlib import contextmanager
import socket
from typing import Iterator, Callable, Any


class OfflineModeError(RuntimeError):
    """Raised when a network operation is attempted in offline mode."""


_NETWORK_BLOCKED = False


def is_network_blocked() -> bool:
    return _NETWORK_BLOCKED


@contextmanager
def block_network(reason: str = "offline mode") -> Iterator[None]:
    """Block outbound network connections for the current Python process."""

    global _NETWORK_BLOCKED

    old_socket_connect: Callable[..., Any] = socket.socket.connect
    old_create_connection: Callable[..., Any] = socket.create_connection
    old_getaddrinfo: Callable[..., Any] = socket.getaddrinfo

    def _blocked(*args, **kwargs):
        raise OfflineModeError(f"Network disabled ({reason})")

    def _blocked_getaddrinfo(*args, **kwargs):
        raise OfflineModeError(f"DNS/network disabled ({reason})")

    _NETWORK_BLOCKED = True
    socket.socket.connect = _blocked  # type: ignore[assignment]
    socket.create_connection = _blocked  # type: ignore[assignment]
    socket.getaddrinfo = _blocked_getaddrinfo  # type: ignore[assignment]

    try:
        yield
    finally:
        socket.socket.connect = old_socket_connect  # type: ignore[assignment]
        socket.create_connection = old_create_connection  # type: ignore[assignment]
        socket.getaddrinfo = old_getaddrinfo  # type: ignore[assignment]
        _NETWORK_BLOCKED = False
