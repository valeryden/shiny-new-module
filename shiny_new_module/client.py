import socket
import ssl
from urllib.parse import urlparse

import h11

__all__ = ["SimpleHTTPClient", "simple_get"]


class SimpleHTTPClient:
    """Very small blocking HTTP/1.1 client built on h11."""

    def __init__(self, timeout: float = 5.0):
        self._timeout = timeout

    def _open_connection(self, host: str, port: int, https: bool):
        raw_sock = socket.create_connection((host, port), timeout=self._timeout)
        if https:
            ctx = ssl.create_default_context()
            return ctx.wrap_socket(raw_sock, server_hostname=host)
        return raw_sock

    def get(self, url: str) -> tuple[h11.Response, bytes]:
        parsed = urlparse(url)
        host = parsed.hostname
        if host is None:
            raise ValueError(f"Invalid URL: {url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query

        sock = self._open_connection(host, port, parsed.scheme == "https")
        conn = h11.Connection(our_role=h11.CLIENT)

        # Send request
        request = h11.Request(method="GET",
                              target=target,
                              headers=[("Host", host),
                                       ("User-Agent", "toyhttp/0.1")])
        sock.sendall(conn.send(request))
        sock.sendall(conn.send(h11.EndOfMessage()))

        # Receive response
        body_chunks: list[bytes] = []
        response: h11.Response | None = None
        while True:
            data = sock.recv(4096)
            if data == b"":
                break  # server closed
            conn.receive_data(data)
            while True:
                event = conn.next_event()
                if event is h11.NEED_DATA:
                    break
                if isinstance(event, h11.Response):
                    response = event
                elif isinstance(event, h11.Data):
                    body_chunks.append(event.data)
                elif isinstance(event, h11.EndOfMessage):
                    sock.close()
                    return response, b"".join(body_chunks)


def simple_get(url: str, timeout: float = 5.0) -> tuple[int, bytes]:
    """Convenience helper that returns (status_code, body)."""
    client = SimpleHTTPClient(timeout=timeout)
    response, body = client.get(url)
    return response.status_code, body
