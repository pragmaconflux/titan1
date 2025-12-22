import socket
import pytest


def test_block_network_blocks_socket_calls():
    from titan_decoder.core.offline_guard import block_network, OfflineModeError, is_network_blocked

    assert is_network_blocked() is False

    with block_network():
        assert is_network_blocked() is True
        with pytest.raises(OfflineModeError):
            socket.getaddrinfo("example.com", 80)
        with pytest.raises(OfflineModeError):
            socket.create_connection(("example.com", 80), timeout=0.1)

    assert is_network_blocked() is False
