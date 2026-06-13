#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "docker" / "controller" / "controller.py"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(url: str, method: str = "GET", body: object | None = None, auth: str | None = None, token: str | None = None) -> tuple[int, bytes]:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(auth.encode("utf-8")).decode("ascii")
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_ready(base_url: str) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            status, _ = request(base_url + "/healthz")
            if status == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("controller did not become ready")


def main() -> None:
    port = free_port()
    with tempfile.TemporaryDirectory() as tmpdir:
        env = os.environ.copy()
        env.update(
            {
                "HOST": "127.0.0.1",
                "PORT": str(port),
                "DATABASE_PATH": str(Path(tmpdir) / "controller.sqlite3"),
                "PUBLIC_BASE_URL": f"http://127.0.0.1:{port}",
                "WEB_USER": "admin",
                "WEB_PASS": "web-pass",
                "PROXY_USER": "proxy",
                "PROXY_PASS": "proxy-pass",
                "AGENT_TOKEN": "agent-token",
                "PROXY_ADVERTISE_HOST": "tcp.proxy.koyeb.app",
                "PROXY_ADVERTISE_PORT": "32123",
            }
        )
        proc = subprocess.Popen([sys.executable, "-u", str(CONTROLLER)], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            base_url = f"http://127.0.0.1:{port}"
            wait_ready(base_url)

            status, _ = request(base_url + "/api/config")
            assert status == 401, status

            status, body = request(base_url + "/api/config", auth="admin:web-pass")
            assert status == 200, body
            assert json.loads(body.decode("utf-8"))["0"] == "JP"

            status, _ = request(base_url + "/api/config", method="POST", body={"0": "us", "port": 9000}, auth="admin:web-pass")
            assert status == 200, status

            report = {
                "ip": "203.0.113.10",
                "details": [{"tunnel": "tun_main", "active": True, "country": "US", "port": 9000, "node_ip": "198.51.100.2"}],
                "logs": "agent online",
            }
            status, _ = request(base_url + "/api/report", method="POST", body=report, token="agent-token")
            assert status == 200, status

            status, body = request(base_url + "/api/proxies", auth="admin:web-pass")
            assert status == 200, body
            assert b"socks5://proxy:proxy-pass@tcp.proxy.koyeb.app:32123#US_ActiveNode_198.51.100.2" in body

            status, body = request(base_url + "/scripts/proxy_server.py", token="agent-token")
            assert status == 200, status
            assert b"def start_proxy_server" in body
            proxy_script = Path(tmpdir) / "proxy_server.py"
            proxy_script.write_bytes(body)
            subprocess.run([sys.executable, "-m", "py_compile", str(proxy_script)], check=True)

            status, body = request(base_url + "/scripts/lite_manager.py", token="agent-token")
            assert status == 200, status
            assert f'C2_URL = "{base_url}"'.encode("utf-8") in body
            assert b"agent.log" in body
            manager_script = Path(tmpdir) / "lite_manager.py"
            manager_script.write_bytes(body)
            subprocess.run([sys.executable, "-m", "py_compile", str(manager_script)], check=True)

            status, body = request(base_url + "/agent?token=agent-token")
            assert status == 200, status
            assert b"python3 -u lite_manager.py" in body
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
