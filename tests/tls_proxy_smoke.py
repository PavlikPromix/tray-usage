"""Local HTTPS integration test; Python stdlib and OpenSSL are test tools only.

Creates a temporary self-signed fixture certificate. No trust store or real Codex
credentials are used. The normal TLS probe must reject this certificate; a probe
in the TEST executable then accepts its CA to exercise the full HTTPS exchange.
"""
import argparse
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path


def exact(peer, count):
    result = b""
    while len(result) < count:
        data = peer.recv(count - len(result))
        if not data:
            raise EOFError("Unexpected end of proxy stream")
        result += data
    return result


def headers(peer):
    result = b""
    while not result.endswith(b"\r\n\r\n"):
        result += exact(peer, 1)
        assert len(result) < 8192
    return result


def run_probe(binary, context, kind, trust, auth):
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)
        port = listener.getsockname()[1]

        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(5)
                    if kind == "http":
                        request = headers(peer)
                        assert request.startswith(b"CONNECT chatgpt.com:443 HTTP/1.")
                        assert b"dummy-test-token" not in request
                        if auth:
                            assert b"Proxy-Authorization: Basic dXNlcjpwYXNz" in request
                        else:
                            assert b"Proxy-Authorization:" not in request
                        peer.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    else:
                        assert exact(peer, 3) == bytes([5, 1, 2 if auth else 0])
                        peer.sendall(bytes([5, 2 if auth else 0]))
                        if auth:
                            assert exact(peer, 11) == b"\x01\x04user\x04pass"
                            peer.sendall(b"\x01\x00")
                        assert exact(peer, 18) == b"\x05\x01\x00\x03\x0bchatgpt.com\x01\xbb"
                        peer.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")
                    try:
                        tls = context.wrap_socket(peer, server_side=True)
                    except ssl.SSLError:
                        if trust:
                            raise
                        return
                    with tls:
                        if not trust:
                            # Some TLS 1.3 clients finish the handshake, then reject the certificate.
                            try:
                                assert not tls.recv(1), "Untrusted server received application data"
                            except ssl.SSLError:
                                pass
                            return
                        request = headers(tls)
                        assert request.startswith(b"GET /backend-api/wham/usage HTTP/1.1\r\n")
                        assert b"Authorization: Bearer dummy-test-token\r\n" in request
                        assert b"Proxy-Authorization:" not in request
                        body = json.dumps({"rate_limit": {
                            "primary_window": {"used_percent": 41, "limit_window_seconds": 18000},
                            "secondary_window": {"used_percent": 17, "limit_window_seconds": 604800},
                        }}).encode()
                        # Chunked HTTP and fragmented TLS writes exercise WinHTTP's normal parser.
                        tls.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                        for offset in range(0, len(body), 7):
                            chunk = body[offset:offset + 7]
                            tls.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                        tls.sendall(b"0\r\n\r\n")
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = subprocess.run([str(binary), "--tls", kind, str(port), "trust" if trust else "reject", "auth" if auth else "none"],
                                capture_output=True, text=True, timeout=15)
        worker.join(10)
        assert not worker.is_alive(), "Proxy fixture did not finish"
        if errors:
            raise errors[0]
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parent.parent / "out" / "proxy_tests.exe")
    parser.add_argument("--openssl", default=shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="trayusage-tls-") as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                        "-subj", "/CN=chatgpt.com", "-addext", "subjectAltName=DNS:chatgpt.com", "-days", "1"],
                       check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        for kind in ("http", "socks5"):
            run_probe(args.binary, context, kind, trust=False, auth=False)
            for auth in (False, True):
                run_probe(args.binary, context, kind, trust=True, auth=auth)
    print("TLS proxy smoke passed: HTTP/SOCKS5, auth, chunked responses, certificate rejection, credential isolation")


if __name__ == "__main__":
    main()
