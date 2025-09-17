#!/usr/bin/env python3
import os
import sys
import socket
import threading
import select
import urllib.parse
import traceback
from typing import Tuple

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8888
LISTEN_BACKLOG = 100
BUFFER_SIZE = 8192
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", f"--proxy-server={PROXY_HOST}:{PROXY_PORT}")

def debug(msg: str):
    print("[proxy]", msg)


def recv_until_double_crlf(conn: socket.socket, timeout: float = 5.0) -> bytes:
    """
    Read from conn until we see '\r\n\r\n' or timeout.
    Returns the bytes read (headers only).
    """
    conn.settimeout(timeout)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    except Exception:
        pass
    finally:
        conn.settimeout(None)
    return data


def parse_request_line_and_headers(header_bytes: bytes) -> Tuple[str, list]:
    """
    Return request-line string and list of header lines (bytes).
    """
    try:
        s = header_bytes.decode("iso-8859-1", errors="ignore")
        parts = s.split("\r\n")
        return parts[0], parts[1:]
    except Exception:
        return "", []


def forward_data(src: socket.socket, dst: socket.socket):
    """
    Copy until EOF from src to dst.
    """
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass


def tunnel_sockets(a: socket.socket, b: socket.socket):
    """
    Bidirectional tunnel using select — runs until sockets close.
    """
    sockets = [a, b]
    try:
        while True:
            r, _, _ = select.select(sockets, [], [], 10)
            if not r:
                continue
            for s in r:
                other = b if s is a else a
                try:
                    data = s.recv(BUFFER_SIZE)
                except Exception:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except Exception:
                    return
    finally:
        try:
            a.close()
        except Exception:
            pass
        try:
            b.close()
        except Exception:
            pass


def handle_connect(client_conn: socket.socket, target_hostport: str):
    """
    Handle CONNECT host:port
    """
    target_host, _, target_port = target_hostport.partition(":")
    target_port = int(target_port) if target_port else 443
    debug(f"CONNECT to {target_host}:{target_port}")
    try:
        remote = socket.create_connection((target_host, target_port), timeout=10)
    except Exception as e:
        debug(f"Failed to connect to {target_host}:{target_port} -> {e}")
        try:
            client_conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
        client_conn.close()
        return

    try:
        client_conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    except Exception:
        remote.close()
        client_conn.close()
        return

    tunnel_sockets(client_conn, remote)


def extract_host_port_from_headers(headers_list: list, first_request_line: str) -> Tuple[str, int]:
    """
    Determine host and port for a non-CONNECT request.
    headers_list: list of header lines (strings)
    first_request_line: eg 'GET http://example.com/path HTTP/1.1' or 'GET /path HTTP/1.1'
    """
    host = None
    port = 80
    for h in headers_list:
        if not h:
            continue
        if h.lower().startswith("host:"):
            host_val = h.split(":", 1)[1].strip()
            if ":" in host_val:
                hpart, ppart = host_val.split(":", 1)
                host = hpart
                try:
                    port = int(ppart)
                except:
                    port = 80
            else:
                host = host_val
            break
          
    if not host:
        parts = first_request_line.split()
        if len(parts) >= 2:
            uri = parts[1]
            parsed = urllib.parse.urlsplit(uri)
            if parsed.hostname:
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not host:
        host = ""
    return host, port


def rewrite_request_first_line_to_origin(request_line: str) -> str:
    """
    If the request-line uses absolute-URI (proxy-form), convert to origin-form for upstream.
    e.g. "GET http://example.com/path HTTP/1.1" -> "GET /path HTTP/1.1"
    """
    parts = request_line.split()
    if len(parts) < 3:
        return request_line
    method, uri, version = parts[0], parts[1], parts[2]
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return f"{method} {path} {version}"
    return request_line


def handle_http_request(client_conn: socket.socket, initial_header_bytes: bytes):
    """
    Handle non-CONNECT HTTP requests: open connection to remote host (port 80),
    forward the (rewritten) request and then relay response.
    """
    try:
        request_line, headers = parse_request_line_and_headers(initial_header_bytes)
        host, port = extract_host_port_from_headers(headers, request_line)
        if not host:
            debug("Could not determine host for HTTP request; closing")
            client_conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            client_conn.close()
            return
        debug(f"Forwarding HTTP to {host}:{port} (first-line: {request_line})")

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            debug(f"Failed to connect to remote {host}:{port} -> {e}")
            client_conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client_conn.close()
            return

        new_first_line = rewrite_request_first_line_to_origin(request_line)
        try:
            s = initial_header_bytes.decode("iso-8859-1", errors="ignore")
            rest = "\r\n".join(s.split("\r\n")[1:])
            if not rest.endswith("\r\n\r\n"):
                rest = rest + "\r\n\r\n"
            new_header_block = (new_first_line + "\r\n" + rest).encode("iso-8859-1")
        except Exception:
            new_header_block = initial_header_bytes

        remote.sendall(new_header_block)

        while True:
            data = remote.recv(BUFFER_SIZE)
            if not data:
                break
            client_conn.sendall(data)
    except Exception:
        debug("Exception in handle_http_request:\n" + traceback.format_exc())
    finally:
        try:
            client_conn.close()
        except Exception:
            pass
        try:
            remote.close()
        except Exception:
            pass


def handle_client(client_conn: socket.socket, client_addr):
    """
    Entry point for each client connection.
    Read initial headers/request-line to decide CONNECT vs normal HTTP.
    """
    try:
        header_bytes = recv_until_double_crlf(client_conn)
        if not header_bytes:
            client_conn.close()
            return
        request_line, headers = parse_request_line_and_headers(header_bytes)
        if not request_line:
            client_conn.close()
            return
        if request_line.upper().startswith("CONNECT "):
            parts = request_line.split()
            if len(parts) >= 2:
                hostport = parts[1]
                handle_connect(client_conn, hostport)
            else:
                client_conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                client_conn.close()
        else:
            handle_http_request(client_conn, header_bytes)
    except Exception:
        debug("Exception in handle_client:\n" + traceback.format_exc())
        try:
            client_conn.close()
        except Exception:
            pass


def start_proxy(listener_host=PROXY_HOST, listener_port=PROXY_PORT):
    debug(f"Starting proxy on {listener_host}:{listener_port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((listener_host, listener_port))
    s.listen(LISTEN_BACKLOG)
    try:
        while True:
            try:
                client_conn, client_addr = s.accept()
            except KeyboardInterrupt:
                break
            t = threading.Thread(target=handle_client, args=(client_conn, client_addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        debug("Proxy shutting down")
    finally:
        s.close()
      
def run_gui_and_browser():
    from PyQt5 import QtWidgets
    from PyQt5.QtCore import QUrl
    from PyQt5.QtWidgets import QInputDialog, QMessageBox
    from PyQt5.QtWebEngineWidgets import QWebEngineView

    app = QtWidgets.QApplication(sys.argv)

    url_text, ok = QInputDialog.getText(None, "Open URL", "Enter URL (include http(s)://):", text="https://www.example.com")
    if not ok or not url_text.strip():
        QMessageBox.information(None, "Cancelled", "No URL entered. Exiting.")
        return

    url_text = url_text.strip()
    if "://" not in url_text:
        url_text = "http://" + url_text

    window = QtWidgets.QMainWindow()
    window.setWindowTitle(f"Proxy Browser - {url_text}")
    window.resize(1200, 800)

    view = QWebEngineView()
    view.setUrl(QUrl(url_text))

    window.setCentralWidget(view)
    window.show()

    QMessageBox.information(None, "Proxy Active", f"Local proxy running on {PROXY_HOST}:{PROXY_PORT}\n"
                                                 "The embedded browser is configured to use that proxy.")

    app.exec_()

if __name__ == "__main__":
    server_thread = threading.Thread(target=start_proxy, args=(PROXY_HOST, PROXY_PORT), daemon=True)
    server_thread.start()

    try:
        run_gui_and_browser()
    except Exception as e:
        print("Error launching GUI:", e)
        traceback.print_exc()
        print("Proxy is still running in background (press Ctrl+C to exit).")
    finally:
        try:
            os._exit(0)
        except Exception:
            pass
