#!/usr/bin/env python3
"""
Network sink of the detonation sandbox: the only reachable host.

It answers every DNS query with its own address and accepts TCP on common ports,
so that malware believes it reached the outside and goes on with its next step.
Every exchange is printed as one JSON line on stdout. Nothing is forwarded.
"""
import base64
import json
import socket
import socketserver
import struct
import sys
import threading

TCP_PORTS = (80, 443, 4444, 8080, 8443)
MAX_BYTES = 256 * 1024
HTTP_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
LOCK = threading.Lock()


def emit(**record) -> None:
    with LOCK:
        print(json.dumps(record), flush=True)


def dns_name(packet: bytes) -> tuple[str, int]:
    """Decode the first question name; return it with the offset following it."""
    labels, offset = [], 12
    while packet[offset]:
        length = packet[offset]
        labels.append(packet[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += length + 1
    return ".".join(labels), offset + 5  # null byte + QTYPE + QCLASS


def serve_dns(own_ip: str) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", 53))
    address = socket.inet_aton(own_ip)
    while True:
        packet, peer = server.recvfrom(4096)
        try:
            name, end = dns_name(packet)
        except IndexError:
            continue
        emit(kind="dns", name=name, peer=peer[0])
        qtype = struct.unpack(">H", packet[end - 4:end - 2])[0]
        answers = 1 if qtype == 1 else 0  # A records only; AAAA gets an empty answer
        reply = packet[:2] + b"\x81\x80" + packet[4:6] + struct.pack(">HHH", answers, 0, 0) + packet[12:end]
        if answers:
            reply += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + address
        server.sendto(reply, peer)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(2)
        data = b""
        try:
            while len(data) < MAX_BYTES:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                data += chunk
                # A complete HTTP request ends the exchange without waiting for the timeout.
                head, separator, body = data.partition(b"\r\n\r\n")
                if separator and len(body) >= _content_length(head):
                    break
        except OSError:
            pass
        emit(kind="tcp", port=self.server.server_address[1], peer=self.client_address[0],
             data=base64.b64encode(data).decode())
        try:
            self.request.sendall(HTTP_OK)
        except OSError:
            pass


def _content_length(head: bytes) -> int:
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1])
            except ValueError:
                return 0
    return 0


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    own_ip = sys.argv[1]
    threading.Thread(target=serve_dns, args=(own_ip,), daemon=True).start()
    servers = [Server(("0.0.0.0", port), Handler) for port in TCP_PORTS]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    emit(kind="ready")
    threading.Event().wait()


if __name__ == "__main__":
    main()
