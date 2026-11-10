# Bismillah ir-Rahman ir-Rahim
"""
CVE-2023-40217 pattern: TLS handshake bypass on closed sockets.

Pre-handshake data + immediate close = application reads unencrypted
data as if it were TLS-protected. The ssl module didn't verify
handshake completion before allowing reads.

furqan-lint rule mapping: RC-001/RC-003 (resource not properly closed),
MR-005 (empty except around socket operations)
"""
import ssl
import socket

def accept_connection_vulnerable(server_socket):
    """Pattern similar to the vulnerable ssl module behavior."""
    conn, addr = server_socket.accept()
    ssl_sock = ssl.wrap_socket(conn, server_side=True)
    try:
        data = ssl_sock.recv(1024)
    except ssl.SSLError:
        pass  # BUG: swallowed SSL error, connection state unknown
    return data  # May be unencrypted pre-handshake data
    # ssl_sock never explicitly closed

def accept_connection_safe(server_socket):
    """Fixed: proper error handling and cleanup."""
    conn, addr = server_socket.accept()
    ssl_sock = ssl.wrap_socket(conn, server_side=True)
    try:
        data = ssl_sock.recv(1024)
        return data
    except ssl.SSLError as e:
        raise  # Re-raise: don't silently continue
    finally:
        ssl_sock.close()
# Bismillah ir-Rahman ir-Rahim
