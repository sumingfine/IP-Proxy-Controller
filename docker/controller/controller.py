#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import hmac
import html
import json
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "src" / "index.js"
DEFAULT_PORT = 7920
STALE_SERVER_SECONDS = 120
MAX_BODY_BYTES = 1024 * 1024
MAX_LOG_BYTES = 12000


@dataclass(frozen=True)
class AppConfig:
    host: str
    port: int
    database_path: Path
    public_base_url: str
    web_user: str
    web_pass: str
    proxy_user: str
    proxy_pass: str
    agent_token: str
    proxy_advertise_host: str
    proxy_advertise_port: int | None

    @classmethod
    def from_env(cls) -> "AppConfig":
        database_path = Path(os.getenv("DATABASE_PATH", "/data/proxy_controller.sqlite3"))
        advertise_port = os.getenv("PROXY_ADVERTISE_PORT", "").strip()
        return cls(
            host=os.getenv("HOST", "0.0.0.0"),
            port=parse_port(os.getenv("PORT"), 8080),
            database_path=database_path,
            public_base_url=os.getenv("PUBLIC_BASE_URL", "").rstrip("/"),
            web_user=os.getenv("WEB_USER", "admin"),
            web_pass=os.getenv("WEB_PASS", ""),
            proxy_user=os.getenv("PROXY_USER", "proxy"),
            proxy_pass=os.getenv("PROXY_PASS", ""),
            agent_token=os.getenv("AGENT_TOKEN", ""),
            proxy_advertise_host=os.getenv("PROXY_ADVERTISE_HOST", "").strip(),
            proxy_advertise_port=parse_port(advertise_port, 0) if advertise_port else None,
        )

    @property
    def missing_vars(self) -> list[str]:
        values = {
            "WEB_USER": self.web_user,
            "WEB_PASS": self.web_pass,
            "PROXY_USER": self.proxy_user,
            "PROXY_PASS": self.proxy_pass,
            "AGENT_TOKEN": self.agent_token,
        }
        return [key for key, value in values.items() if not value]


class SQLiteStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.lock = threading.Lock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        with self.lock, self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS servers (
                  ip TEXT PRIMARY KEY,
                  details TEXT,
                  last_seen INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS server_logs (
                  ip TEXT PRIMARY KEY,
                  logs TEXT,
                  updated_at INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS global_config (
                  key TEXT PRIMARY KEY,
                  value TEXT
                )
                """
            )

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.lock, self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self.lock, self.connect() as conn:
            conn.execute(sql, params)


def parse_port(value: Any, default: int = DEFAULT_PORT) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 0 < port <= 65535 else default


def parse_non_negative_int(value: Any, default: int = 0) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, number)


def safe_equal(left: str, right: str) -> bool:
    return bool(left) and bool(right) and hmac.compare_digest(left, right)


def safe_net_text(value: Any, max_length: int = 80) -> str:
    return re.sub(r"[^a-zA-Z0-9:._-]", "", str(value or ""))[:max_length]


def sanitize_country(value: Any) -> str:
    country = re.sub(r"[^A-Z]", "", str(value or "").upper())[:4]
    return country or "NA"


def sanitize_details(details: Any) -> list[dict[str, Any]]:
    if not isinstance(details, list):
        return []
    sanitized = []
    for item in details[:4]:
        if not isinstance(item, dict):
            continue
        connected_time = parse_non_negative_int(item.get("connected_time"), 0)
        sanitized.append(
            {
                "tunnel": safe_net_text(item.get("tunnel"), 32),
                "active": bool(item.get("active")),
                "country": sanitize_country(item.get("country")),
                "port": parse_port(item.get("port"), DEFAULT_PORT),
                "connected_time": min(connected_time, 31536000),
                "node_ip": safe_net_text(item.get("node_ip"), 80),
            }
        )
    return sanitized


def js_template_unescape(raw: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != "\\" or index + 1 >= len(raw):
            output.append(char)
            index += 1
            continue

        nxt = raw[index + 1]
        if nxt in ("\\", "`", "$"):
            output.append(nxt)
        elif nxt == "n":
            output.append("\n")
        elif nxt == "r":
            output.append("\r")
        elif nxt == "t":
            output.append("\t")
        else:
            output.append("\\" + nxt)
        index += 2
    return "".join(output)


def extract_worker_template(const_name: str) -> str:
    source = WORKER_SOURCE.read_text(encoding="utf-8")
    marker = f"const {const_name} = `"
    start = source.find(marker)
    if start < 0:
        raise RuntimeError(f"Cannot find {const_name} in {WORKER_SOURCE}")
    index = start + len(marker)
    escaped = False
    while index < len(source):
        char = source[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "`":
            return js_template_unescape(source[start + len(marker) : index])
        index += 1
    raise RuntimeError(f"Unterminated template for {const_name}")


def patch_manager_code(code: str, base_url: str) -> str:
    code = code.replace('C2_URL = "${domain}"', f"C2_URL = {json.dumps(base_url)}")
    pattern = (
        r"def get_recent_logs\(\):\n"
        r"    try:\n"
        r"        res = subprocess\.run\(\[\"journalctl\".*?"
        r"    except: return \"Waiting for logs\.\.\.\"\n"
    )
    replacement = """def get_recent_logs():
    log_file = WORKSPACE / "agent.log"
    try:
        if log_file.exists():
            return log_file.read_text(encoding="utf-8", errors="replace")[-12000:]
    except Exception:
        pass
    return "Waiting for logs..."
"""
    return re.sub(pattern, replacement, code, flags=re.DOTALL)


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


class ControllerHandler(BaseHTTPRequestHandler):
    server_version = "ProxyControllerDocker/1.0"
    config: AppConfig
    store: SQLiteStore

    def do_OPTIONS(self) -> None:
        self.send_body("", headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type"})

    def do_GET(self) -> None:
        if self.config.missing_vars:
            self.configuration_error()
            return

        path = urllib.parse.urlparse(self.path).path
        if path == "/healthz":
            self.send_json({"ok": True})
            return
        if path == "/agent":
            if not self.authenticate_agent(allow_query_token=True):
                self.unauthorized("Proxy Agent Bootstrap")
                return
            self.send_body(self.agent_script(), content_type="text/plain;charset=UTF-8")
            return
        if path == "/scripts/proxy_server.py":
            if not self.authenticate_agent():
                self.unauthorized("Proxy Agent Script")
                return
            self.send_body(extract_worker_template("PROXY_CODE"), content_type="text/plain;charset=UTF-8")
            return
        if path == "/scripts/lite_manager.py":
            if not self.authenticate_agent():
                self.unauthorized("Proxy Agent Script")
                return
            self.send_body(patch_manager_code(extract_worker_template("MANAGER_CODE"), self.origin()), content_type="text/plain;charset=UTF-8")
            return
        if path.startswith("/api/testisp-lookup/"):
            if not self.require_web():
                return
            self.handle_testisp_lookup(path)
            return
        if path == "/api/countries":
            self.handle_countries()
            return
        if path == "/api/config":
            if not (self.authenticate_web() or self.authenticate_agent()):
                self.unauthorized()
                return
            self.handle_get_config()
            return
        if path == "/api/proxies":
            if not self.require_web():
                return
            self.handle_proxies()
            return
        if path == "/api/nodes":
            if not self.require_web():
                return
            self.handle_nodes()
            return
        if path == "/":
            if not self.require_web():
                return
            self.send_body(self.dashboard_html(), content_type="text/html;charset=UTF-8")
            return
        self.send_body("Not Found", status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.config.missing_vars:
            self.configuration_error()
            return

        path = urllib.parse.urlparse(self.path).path
        if path == "/api/config":
            if not self.require_web():
                return
            self.handle_post_config()
            return
        if path == "/api/report":
            if not self.authenticate_agent():
                self.unauthorized("Proxy Agent API")
                return
            self.handle_report()
            return
        self.send_body("Not Found", status=HTTPStatus.NOT_FOUND)

    def log_message(self, fmt: str, *args: Any) -> None:
        print("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), fmt % args), flush=True)

    def send_body(
        self,
        body: str | bytes,
        status: int | HTTPStatus = HTTPStatus.OK,
        content_type: str = "text/plain;charset=UTF-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, payload: Any, status: int | HTTPStatus = HTTPStatus.OK, headers: dict[str, str] | None = None) -> None:
        self.send_body(json.dumps(payload, ensure_ascii=False), status=status, content_type="application/json;charset=UTF-8", headers=headers)

    def configuration_error(self) -> None:
        missing = ", ".join(self.config.missing_vars)
        self.send_body(f"Controller is not configured. Missing variables: {missing}", status=HTTPStatus.SERVICE_UNAVAILABLE)

    def unauthorized(self, realm: str = "Proxy System Security Control") -> None:
        self.send_body(
            "Unauthorized Access.",
            status=HTTPStatus.UNAUTHORIZED,
            headers={"WWW-Authenticate": f'Basic realm="{realm}"'},
        )

    def require_web(self) -> bool:
        if self.authenticate_web():
            return True
        self.unauthorized()
        return False

    def authenticate_web(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, encoded = header.partition(" ")
        if scheme != "Basic" or not encoded:
            return False
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return False
        username, separator, password = decoded.partition(":")
        return bool(separator) and safe_equal(username, self.config.web_user) and safe_equal(password, self.config.web_pass)

    def authenticate_agent(self, allow_query_token: bool = False) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme == "Bearer" and safe_equal(token, self.config.agent_token):
            return True
        if not allow_query_token:
            return False
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return safe_equal((query.get("token") or [""])[0], self.config.agent_token)

    def read_json(self) -> Any:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Invalid request body size")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8") or "{}")

    def origin(self) -> str:
        if self.config.public_base_url:
            return self.config.public_base_url
        proto = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"127.0.0.1:{self.config.port}"
        return f"{proto}://{host}".rstrip("/")

    def handle_get_config(self) -> None:
        rows = self.store.query_all("SELECT value FROM global_config WHERE key = ?", ("slot_map",))
        if rows:
            self.send_body(rows[0]["value"], content_type="application/json;charset=UTF-8")
            return
        self.send_json({"0": "JP", "port": DEFAULT_PORT})

    def handle_post_config(self) -> None:
        try:
            data = self.read_json()
            payload = {
                "0": sanitize_country(data.get("0", "JP")),
                "port": parse_port(data.get("port"), DEFAULT_PORT),
            }
            if data.get("switch_trigger"):
                try:
                    payload["switch_trigger"] = max(0, int(data.get("switch_trigger")))
                except (TypeError, ValueError):
                    payload["switch_trigger"] = int(time.time() * 1000)
            self.store.execute(
                """
                INSERT INTO global_config (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                ("slot_map", json.dumps(payload, ensure_ascii=False)),
            )
            self.send_body("OK")
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def handle_report(self) -> None:
        try:
            data = self.read_json()
            report_ip = safe_net_text(data.get("ip"), 80)
            if not report_ip:
                self.send_body("Invalid report", status=HTTPStatus.BAD_REQUEST)
                return
            details = sanitize_details(data.get("details", []))
            self.store.execute(
                """
                INSERT INTO servers (ip, details, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET details = excluded.details, last_seen = excluded.last_seen
                """,
                (report_ip, json.dumps(details, ensure_ascii=False), int(time.time() * 1000)),
            )
            if data.get("logs"):
                self.store.execute(
                    """
                    INSERT INTO server_logs (ip, logs, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET logs = excluded.logs, updated_at = excluded.updated_at
                    """,
                    (report_ip, str(data.get("logs"))[-MAX_LOG_BYTES:], int(time.time() * 1000)),
                )
            self.send_body("OK")
        except Exception:
            self.send_body("Error", status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def clean_stale_servers(self) -> None:
        cutoff = int((time.time() - STALE_SERVER_SECONDS) * 1000)
        self.store.execute("DELETE FROM servers WHERE last_seen < ?", (cutoff,))

    def handle_proxies(self) -> None:
        self.clean_stale_servers()
        rows = self.store.query_all("SELECT ip, details FROM servers")
        proxy_user = urllib.parse.quote(self.config.proxy_user, safe="")
        proxy_pass = urllib.parse.quote(self.config.proxy_pass, safe="")
        result: list[str] = []
        for row in rows:
            try:
                details = json.loads(row.get("details") or "[]")
            except json.JSONDecodeError:
                details = []
            active = next((item for item in details if item.get("active")), details[0] if details else None)
            if active:
                proxy_host = self.config.proxy_advertise_host or safe_net_text(row.get("ip"))
                proxy_port = self.config.proxy_advertise_port or parse_port(active.get("port"), DEFAULT_PORT)
                result.append(
                    "socks5://"
                    f"{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
                    f"#{sanitize_country(active.get('country'))}_ActiveNode_{safe_net_text(active.get('node_ip') or 'IP')}"
                )
        self.send_body("\n".join(result), content_type="text/plain;charset=UTF-8")

    def handle_nodes(self) -> None:
        self.clean_stale_servers()
        rows = self.store.query_all(
            """
            SELECT s.*, l.logs
            FROM servers s
            LEFT JOIN server_logs l ON s.ip = l.ip
            ORDER BY s.last_seen DESC
            """
        )
        self.send_json(rows)

    def handle_countries(self) -> None:
        countries = {"US", "JP", "KR", "SG", "HK", "TW", "GB", "DE", "FR", "NL", "CA", "AU", "IN", "VN", "BR"}
        try:
            request = urllib.request.Request("https://www.vpngate.net/api/iphone/", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(request, timeout=10) as response:
                text = response.read().decode("utf-8", errors="replace")
            lines = [line for line in text.splitlines() if line and not line.startswith("*")]
            if lines and lines[0].startswith("#"):
                lines[0] = lines[0][1:]
            for row in csv.DictReader(lines):
                country = str(row.get("CountryShort", "")).upper()
                if re.fullmatch(r"[A-Z]{2}", country):
                    countries.add(country)
        except Exception:
            pass
        self.send_json(sorted(countries), headers={"Access-Control-Allow-Origin": "*"})

    def handle_testisp_lookup(self, path: str) -> None:
        target_ip = safe_net_text(urllib.parse.unquote(path.replace("/api/testisp-lookup/", "")), 80)
        if not target_ip:
            self.send_json({"error": "Invalid IP"}, status=HTTPStatus.BAD_REQUEST)
            return
        request = urllib.request.Request(
            f"https://testisp.info/api/check?ip={urllib.parse.quote(target_ip)}",
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json, text/plain, */*",
                "Referer": "https://testisp.info/",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read()
                content_type = response.headers.get("content-type", "application/json")
                self.send_body(body, content_type=content_type, headers={"Access-Control-Allow-Origin": "*"})
        except urllib.error.HTTPError as exc:
            self.send_body(exc.read(), status=exc.code, content_type=exc.headers.get("content-type", "application/json"))
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def agent_script(self) -> str:
        origin = self.origin()
        return f"""#!/usr/bin/env bash
set -euo pipefail

WORKER_ORIGIN={shell_quote(origin)}
AGENT_TOKEN={shell_quote(self.config.agent_token)}
PROXY_USER_VALUE={shell_quote(self.config.proxy_user)}
PROXY_PASS_VALUE={shell_quote(self.config.proxy_pass)}
WORKSPACE=/opt/proxy_lite

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] 请使用 root 用户运行，或改用 docker-compose.agent.yml。"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1 || ! command -v openvpn >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -q
    apt-get install -y openvpn python3 curl iproute2 iptables iputils-ping psmisc ca-certificates
  else
    echo "[!] 未找到 python3/openvpn，且当前系统没有 apt-get。"
    exit 1
  fi
fi

install -d -m 700 "$WORKSPACE/configs"
cd "$WORKSPACE"

cat > "$WORKSPACE/proxy-lite.env" << EOF
C2_TOKEN=$AGENT_TOKEN
PROXY_USER=$PROXY_USER_VALUE
PROXY_PASS=$PROXY_PASS_VALUE
EOF
chmod 600 "$WORKSPACE/proxy-lite.env"
printf "%s" "$AGENT_TOKEN" > "$WORKSPACE/agent_token"
chmod 600 "$WORKSPACE/agent_token"

curl -fsSL -H "Authorization: Bearer $AGENT_TOKEN" -o lite_manager.py "$WORKER_ORIGIN/scripts/lite_manager.py"
curl -fsSL -H "Authorization: Bearer $AGENT_TOKEN" -o proxy_server.py "$WORKER_ORIGIN/scripts/proxy_server.py"
python3 -m py_compile lite_manager.py proxy_server.py

echo "[+] Agent 已准备完成，正在前台启动。Docker 部署建议使用 docker-compose.agent.yml。"
python3 -u lite_manager.py 2>&1 | tee -a "$WORKSPACE/agent.log"
"""

    def dashboard_html(self) -> str:
        origin = self.origin()
        install_url = f"{origin}/agent?token={urllib.parse.quote(self.config.agent_token)}"
        template = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Proxy Controller Docker</title>
  <style>
    :root { color-scheme: dark; --bg:#0f172a; --panel:#111827; --line:#263244; --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; --ok:#34d399; --warn:#f59e0b; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family: Arial, "Microsoft YaHei", sans-serif; }
    header, main { max-width:1180px; margin:0 auto; padding:20px; }
    header { display:flex; justify-content:space-between; gap:16px; align-items:flex-end; border-bottom:1px solid var(--line); }
    h1 { margin:0; font-size:24px; }
    h2 { margin:0 0 12px; font-size:16px; }
    .muted { color:var(--muted); font-size:13px; }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-top:18px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    label { display:block; color:var(--muted); font-size:12px; margin:10px 0 6px; }
    input { width:100%; padding:10px 12px; border-radius:6px; border:1px solid var(--line); background:#0b1220; color:var(--text); font-size:14px; }
    button { border:0; border-radius:6px; padding:10px 12px; color:#03111f; background:var(--accent); font-weight:700; cursor:pointer; margin-right:8px; }
    button.warn { background:var(--warn); }
    code, pre { font-family: Consolas, "Liberation Mono", monospace; }
    pre { overflow:auto; white-space:pre-wrap; word-break:break-word; background:#070d18; border:1px solid var(--line); border-radius:6px; padding:12px; color:#c7d2fe; }
    table { width:100%; border-collapse:collapse; }
    th, td { border-bottom:1px solid var(--line); padding:10px 8px; text-align:left; vertical-align:top; }
    th { color:var(--muted); font-size:12px; }
    .status { color:var(--ok); font-weight:700; }
    @media (max-width: 820px) { header { align-items:flex-start; flex-direction:column; } .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Proxy Controller Docker</h1>
      <div class="muted">自托管控制端：__ORIGIN__</div>
    </div>
    <div class="muted">Web 用户：__WEB_USER__ · 代理用户：__PROXY_USER__</div>
  </header>
  <main>
    <section class="grid">
      <div class="panel">
        <h2>策略配置</h2>
        <label>目标国家代码</label>
        <input id="country" value="JP" maxlength="4">
        <label>代理端口</label>
        <input id="port" type="number" min="1" max="65535" value="7920">
        <p>
          <button onclick="saveConfig()">下发策略</button>
          <button class="warn" onclick="switchIp()">强制更换 IP</button>
        </p>
        <div class="muted" id="save-state">等待同步</div>
      </div>
      <div class="panel">
        <h2>Agent 接入</h2>
        <div class="muted">Docker Agent 推荐使用 compose；下方脚本用于裸机调试或兼容安装。</div>
        <pre>bash &lt;(curl -fsSL "__INSTALL_URL__")</pre>
        <div class="muted">代理列表接口：<code>/api/proxies</code></div>
      </div>
    </section>
    <section class="panel" style="margin-top:16px">
      <h2>在线节点</h2>
      <table>
        <thead><tr><th>母机 IP</th><th>通道</th><th>心跳</th><th>状态</th></tr></thead>
        <tbody id="nodes"><tr><td colspan="4" class="muted">正在加载...</td></tr></tbody>
      </table>
    </section>
    <section class="panel" style="margin-top:16px">
      <h2>实时日志</h2>
      <pre id="logs">等待 Agent 上报...</pre>
    </section>
  </main>
<script>
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;'}[ch]));
}
async function loadConfig() {
  const res = await fetch('/api/config');
  const data = await res.json();
  document.getElementById('country').value = data["0"] || 'JP';
  document.getElementById('port').value = data.port || 7920;
}
async function saveConfig() {
  const body = {
    "0": document.getElementById('country').value.toUpperCase().trim() || 'JP',
    port: Number(document.getElementById('port').value) || 7920
  };
  await fetch('/api/config', {method:'POST', body: JSON.stringify(body)});
  document.getElementById('save-state').textContent = '已同步，Agent 会在下一次心跳应用';
}
async function switchIp() {
  const body = {
    "0": document.getElementById('country').value.toUpperCase().trim() || 'JP',
    port: Number(document.getElementById('port').value) || 7920,
    switch_trigger: Date.now()
  };
  await fetch('/api/config', {method:'POST', body: JSON.stringify(body)});
  document.getElementById('save-state').textContent = '重拨指令已下发';
}
async function loadNodes() {
  try {
    const res = await fetch('/api/nodes');
    const nodes = await res.json();
    const tbody = document.getElementById('nodes');
    if (!nodes.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">暂无在线节点</td></tr>';
      return;
    }
    tbody.innerHTML = nodes.map(node => {
      let details = [];
      try { details = JSON.parse(node.details || '[]'); } catch(e) {}
      const channels = details.map(item => `${esc(item.tunnel)} ${item.active ? '<span class="status">ACTIVE</span>' : 'STANDBY'} ${esc(item.country)} ${esc(item.node_ip)}:${esc(item.port)}`).join('<br>') || '等待拨号';
      const ago = Math.max(0, Math.floor((Date.now() - Number(node.last_seen || 0)) / 1000));
      return `<tr><td><code>${esc(node.ip)}</code></td><td>${channels}</td><td>${ago}s 前</td><td>${ago < 30 ? '<span class="status">在线</span>' : '延迟'}</td></tr>`;
    }).join('');
    document.getElementById('logs').textContent = nodes[0].logs || '等待 Agent 上报...';
  } catch (err) {
    document.getElementById('nodes').innerHTML = '<tr><td colspan="4">加载失败</td></tr>';
  }
}
loadConfig();
loadNodes();
setInterval(loadNodes, 5000);
</script>
</body>
</html>"""
        return (
            template.replace("__ORIGIN__", html.escape(origin))
            .replace("__WEB_USER__", html.escape(self.config.web_user))
            .replace("__PROXY_USER__", html.escape(self.config.proxy_user))
            .replace("__INSTALL_URL__", html.escape(install_url))
        )


def build_server(config: AppConfig) -> ThreadingHTTPServer:
    store = SQLiteStore(config.database_path)
    ControllerHandler.config = config
    ControllerHandler.store = store
    return ThreadingHTTPServer((config.host, config.port), ControllerHandler)


def main() -> None:
    config = AppConfig.from_env()
    server = build_server(config)
    print(f"Proxy Controller Docker listening on {config.host}:{config.port}", flush=True)
    if config.missing_vars:
        print(f"Missing required variables: {', '.join(config.missing_vars)}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
