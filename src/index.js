// ======  Proxy Controller (Active-Standby Multi-Tunnel) ======

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- 提取并处理云端安全隔离变量 ---
    const WEB_USER = env.WEB_USER || "";
    const WEB_PASS = env.WEB_PASS || "";
    const PROXY_USER = env.PROXY_USER || "";
    const PROXY_PASS = env.PROXY_PASS || "";
    const AGENT_TOKEN = env.AGENT_TOKEN || "";

    const requiredVars = { WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS, AGENT_TOKEN };
    const missingVars = Object.entries(requiredVars)
      .filter(([, value]) => !value)
      .map(([key]) => key);

    const safeEqual = (a, b) => {
      a = String(a || "");
      b = String(b || "");
      if (a.length !== b.length || !a || !b) return false;
      let result = 0;
      for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
      return result === 0;
    };

    const authenticateWeb = (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const separator = decoded.indexOf(":");
        if (separator < 0) return false;
        const username = decoded.slice(0, separator);
        const password = decoded.slice(separator + 1);
        return safeEqual(username, WEB_USER) && safeEqual(password, WEB_PASS);
      } catch (e) {
        return false;
      }
    };

    const authenticateAgent = (request, allowQueryToken = false) => {
      const authHeader = request.headers.get("Authorization") || "";
      const [scheme, token] = authHeader.split(" ");
      if (scheme === "Bearer" && safeEqual(token, AGENT_TOKEN)) return true;
      return allowQueryToken && safeEqual(url.searchParams.get("token"), AGENT_TOKEN);
    };

    const configurationErrorResponse = () => {
      return new Response(`Worker is not configured. Missing variables: ${missingVars.join(", ")}`, {
        status: 503,
        headers: { "Content-Type": "text/plain;charset=UTF-8" }
      });
    };

    const unauthorizedResponse = (realm = "Proxy System Security Control") => {
      return new Response("Unauthorized Access.", {
        status: 401,
        headers: {
          "WWW-Authenticate": `Basic realm="${realm}"`,
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    const shellQuote = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;
    const htmlEscape = (value) => String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

    const safeNetText = (value, max = 80) => String(value ?? "")
      .replace(/[^a-zA-Z0-9:._-]/g, "")
      .slice(0, max);

    const sanitizeCountry = (value) => {
      const country = String(value ?? "").toUpperCase().replace(/[^A-Z]/g, "").slice(0, 4);
      return country || "NA";
    };

    const sanitizePort = (value) => {
      const port = Number.parseInt(value, 10);
      return Number.isInteger(port) && port > 0 && port <= 65535 ? port : 7920;
    };

    const sanitizeDetails = (details) => {
      if (!Array.isArray(details)) return [];
      return details.slice(0, 4).map((item) => ({
        tunnel: safeNetText(item?.tunnel, 32),
        active: Boolean(item?.active),
        country: sanitizeCountry(item?.country),
        port: sanitizePort(item?.port),
        connected_time: Math.max(0, Math.min(Number.parseInt(item?.connected_time, 10) || 0, 31536000)),
        node_ip: safeNetText(item?.node_ip, 80)
      }));
    };

    if (missingVars.length > 0) return configurationErrorResponse();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS servers (
        ip TEXT PRIMARY KEY,
        details TEXT,
        last_seen INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS server_logs (
        ip TEXT PRIMARY KEY,
        logs TEXT,
        updated_at INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();

    if (url.pathname === "/scripts/proxy_server.py") {
      if (!authenticateAgent(request)) return unauthorizedResponse("Proxy Agent Script");
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import os, select, socket, threading, urllib.parse, time, base64
from pathlib import Path
from typing import Any

ENV_FILE = Path("/opt/proxy_lite/proxy-lite.env")

def load_env_file(path: Path) -> dict[str, str]:
    values = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return values

ENV_VALUES = load_env_file(ENV_FILE)
PROXY_USER = (os.getenv("PROXY_USER") or ENV_VALUES.get("PROXY_USER") or "").encode()
PROXY_PASS = (os.getenv("PROXY_PASS") or ENV_VALUES.get("PROXY_PASS") or "").encode()

if not PROXY_USER or not PROXY_PASS:
    raise SystemExit("PROXY_USER/PROXY_PASS is not configured.")

# 全局软开关：由 lite_manager 动态更新，实现秒切
ACTIVE_BIND = "tun_main"

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    global ACTIVE_BIND
    bind_interface = ACTIVE_BIND
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored: return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)

        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF")
            return
        client.sendall(b"\\x05\\x02")

        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)

        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\\x01\\x01")
            return
        client.sendall(b"\\x01\\x00")

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")

        upstream = create_connection((host, port), timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")

        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break

        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first)
        else: http_client(client, first)
    except:
        try: client.close()
        except: pass

def start_proxy_server(host: str, port: int) -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address), daemon=True).start()
        except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/scripts/lite_manager.py") {
      if (!authenticateAgent(request)) return unauthorizedResponse("Proxy Agent Script");
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, json
from pathlib import Path
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = "${domain}"

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"
ENV_FILE = WORKSPACE / "proxy-lite.env"
TOKEN_FILE = WORKSPACE / "agent_token"

def load_env_file(path: Path) -> dict:
    values = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return values

ENV_VALUES = load_env_file(ENV_FILE)

def load_agent_token() -> str:
    token = os.getenv("C2_TOKEN") or os.getenv("AGENT_TOKEN") or ENV_VALUES.get("C2_TOKEN", "")
    if token:
        return token.strip()
    try:
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""

C2_TOKEN = load_agent_token()
if not C2_TOKEN:
    raise SystemExit("C2_TOKEN/AGENT_TOKEN is not configured.")

PROXY_PORT = 7920
target_country = "JP"
last_switch_trigger = 0

state_lock = threading.Lock()
dead_ips = set()
last_blacklist_clear = time.time()
public_ip = ""

global_node_reservoir = {}
reservoir_lock = threading.Lock()

class Tunnel:
    def __init__(self, name: str, table_id: int):
        self.name = name
        self.table_id = table_id
        self.process = None
        self.node = None
        self.entry_ip = ""
        self.egress_ip = ""
        self.country = ""
        self.ready = False
        self.connected_at = 0
        self.is_connecting = False

tun_main = Tunnel("tun_main", 101)
tun_backup = Tunnel("tun_backup", 102)

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Authorization": f"Bearer {C2_TOKEN}"
    }

def get_recent_logs():
    try:
        res = subprocess.run(["journalctl", "-u", "proxy-lite.service", "-n", "30", "--no-pager", "--output=cat"], capture_output=True, text=True, errors="replace")
        return res.stdout
    except: return "Waiting for logs..."

def update_config_loop():
    global target_country, last_switch_trigger, PROXY_PORT, tun_main, tun_backup
    while True:
        try:
            req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
            with urllib.request.urlopen(req, timeout=10) as res:
                data = json.loads(res.read().decode("utf-8"))
                desired_country = str(data.get("0", "JP")).upper()
                switch_trigger = int(data.get("switch_trigger", 0))
                new_port = int(data.get("port", 7920))

                if new_port != PROXY_PORT:
                    print(f"[*] 收到端口变更指令 ({PROXY_PORT} -> {new_port})，重启守护进程...", flush=True)
                    os._exit(0)

                with state_lock:
                    force_switch = (switch_trigger > last_switch_trigger)
                    if target_country != desired_country or force_switch:
                        target_country = desired_country
                        if force_switch: print(f"[*] 收到强制更换指令，正在清退通道并拉黑当前 IP...", flush=True)
                        else: print(f"[*] 策略热切换: 目标重定向到 {desired_country}...", flush=True)

                        if tun_main.entry_ip: dead_ips.add(tun_main.entry_ip)
                        if tun_main.process:
                            try: tun_main.process.terminate(); tun_main.process.wait(2)
                            except: tun_main.process.kill()
                        tun_main.ready = False; tun_main.process = None; tun_main.entry_ip = ""; tun_main.egress_ip = ""

                        if tun_backup.process:
                            try: tun_backup.process.terminate(); tun_backup.process.wait(2)
                            except: tun_backup.process.kill()
                        tun_backup.ready = False; tun_backup.process = None; tun_backup.entry_ip = ""; tun_backup.egress_ip = ""

                        last_switch_trigger = switch_trigger
        except Exception as e: pass
        time.sleep(15)

def c2_heartbeat_loop():
    global public_ip, PROXY_PORT, tun_main, tun_backup
    while True:
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        active_countries = set()
        current_target_country = target_country
        with state_lock:
            current_target_country = target_country
            for tun in [tun_main, tun_backup]:
                if tun.ready and tun.process and tun.process.poll() is None:
                    uptime = time.time() - tun.connected_at
                    if tun.country:
                        active_countries.add(tun.country)
                    details.append({
                        "tunnel": tun.name,
                        "active": proxy_server.ACTIVE_BIND == tun.name,
                        "country": tun.country,
                        "port": PROXY_PORT,
                        "connected_time": int(uptime),
                        "node_ip": tun.egress_ip if tun.egress_ip else tun.entry_ip
                    })

        country_map = {}
        with reservoir_lock:
            for node in global_node_reservoir.values():
                country = str(node.get("country", "")).upper()
                if not country or node.get("ip") in dead_ips:
                    continue
                item = country_map.setdefault(country, {"country": country, "candidates": 0, "best_ping": 9999, "active": False})
                item["candidates"] += 1
                try:
                    item["best_ping"] = min(item["best_ping"], int(node.get("ping", 9999)))
                except:
                    pass
        for country in active_countries:
            item = country_map.setdefault(country, {"country": country, "candidates": 0, "best_ping": 9999, "active": False})
            item["active"] = True
        country_stats = sorted(country_map.values(), key=lambda x: (-x["candidates"], x["country"]))
        for item in country_stats:
            if item["best_ping"] == 9999:
                item["best_ping"] = None

        payload = json.dumps({
            "ip": public_ip,
            "details": details,
            "logs": get_recent_logs(),
            "country_stats": country_stats,
            "target_country": current_target_country,
            "proxy_port": PROXY_PORT
        }).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
        except Exception as e: pass
        time.sleep(8)

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n", encoding="utf-8")
        AUTH_FILE.chmod(0o600)
    if not Path("/dev/net/tun").exists():
        print("[!] /dev/net/tun 不存在，OpenVPN 无法创建隧道。请确认容器已开启 privileged/TUN 权限。", flush=True)
    # 强制系统解除反向路径过滤，防止策略路由双拨时数据包被内核丢弃
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"], capture_output=True)

def harvest_snapshot_nodes() -> list:
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip,
                "ping": int(raw_ping) if raw_ping.isdigit() else 9999,
                "country": row.get("CountryShort", "").upper(),
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        return nodes
    except Exception as e: return []

def vpngate_fetch_loop():
    global global_node_reservoir, dead_ips
    while True:
        snapshot = harvest_snapshot_nodes()
        if snapshot:
            with reservoir_lock:
                for n in snapshot:
                    if n["ip"] not in dead_ips:
                        global_node_reservoir[n["ip"]] = n
            print(f"[*] ⚡ 节点库更新，当前囤积有效节点 -> {len(global_node_reservoir)} 个", flush=True)
        time.sleep(300)

def setup_routing(tun_name: str, table_id: int):
    subprocess.run(["ip", "rule", "del", "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id + 1000)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", tun_name, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", tun_name, "lookup", str(table_id), "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "iif", tun_name, "lookup", str(table_id), "pref", str(table_id + 1000)], capture_output=True)

def cleanup_tunnel(tun_name: str, table_id: int):
    subprocess.run(["pkill", "-f", f"openvpn.*--dev {tun_name}"], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id + 1000)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "link", "set", tun_name, "down"], capture_output=True)
    subprocess.run(["ip", "link", "delete", tun_name], capture_output=True)

def connect_node(tun: Tunnel, node: dict):
    global dead_ips
    try:
        cfg_path = CONFIG_DIR / f"{tun.name}.ovpn"
        log_file = WORKSPACE / f"{tun.name}_err.log"
        cfg_path.write_text(node["config"], encoding="utf-8")
        cleanup_tunnel(tun.name, tun.table_id)

        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]

        # 强制添加 --nobind 解除端口冲突，--route-nopull 剥夺路由修改权
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", tun.name, "--dev-type", "tun",
               "--nobind", "--route-nopull",
               "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6",
               "--auth-user-pass", str(AUTH_FILE), "--auth-nocache",
               "--connect-timeout", "5", "--connect-retry-max", "1", "--verb", "3"] + cipher_args

        with open(log_file, "w") as f: process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        with state_lock:
            tun.process = process
            tun.node = node
            tun.entry_ip = node["ip"]
            tun.egress_ip = ""
            tun.country = node["country"]
            tun.ready = False

        success = False
        for _ in range(15):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass

        if success and process.poll() is None:
            setup_routing(tun.name, tun.table_id)
            time.sleep(1)

            # --- 穿透获取通道真实出口 IP ---
            true_ip = ""
            try:
                true_ip_res = subprocess.run(["curl", "-s", "-m", "10", "--interface", tun.name, "https://api.ipify.org"], capture_output=True, text=True)
                candidate_ip = true_ip_res.stdout.strip()
                if candidate_ip and candidate_ip.count('.') == 3:
                    true_ip = candidate_ip
            except: pass

            egress_ip = true_ip if true_ip else node['ip']

            if true_ip and true_ip != node['ip']:
                print(f"[*] {tun.name} 探测到真实出口 IP 与入口不一致: 入口 {node['ip']} -> 出口 {true_ip}", flush=True)

            is_residential = True
            try:
                # 兼容 testisp.info/api/check 的新解析逻辑
                req_url = f"https://testisp.info/api/check?ip={egress_ip}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, method="GET")
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    data = json.loads(check_res.read().decode("utf-8"))
                    isp_flag = str(data.get("isp", {}).get("flag", "")).lower()

                    if isp_flag == "hosting":
                        is_residential = False
            except Exception as e: pass

            if not is_residential:
                print(f"[-] {tun.name} 节点出口 ({egress_ip}) 检测为机房 IP，残忍抛弃！", flush=True)
                dead_ips.add(node["ip"])
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            print(f"[*] {tun.name} 进行流媒体质检 (YouTube)...", flush=True)
            res = subprocess.run(["curl", "-I", "-s", "-A", "Mozilla/5.0", "-m", "5", "--interface", tun.name, "https://www.youtube.com"], capture_output=True)
            if res.returncode != 0:
                print(f"[-] {tun.name} 节点出口无法连通 YouTube，拉黑更换: {node['ip']}", flush=True)
                dead_ips.add(node["ip"])
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            with state_lock:
                tun.process = process
                tun.node = node
                tun.entry_ip = node["ip"]
                tun.egress_ip = egress_ip
                tun.country = node["country"]
                tun.connected_at = time.time()
                tun.ready = True
            role = "主网卡" if proxy_server.ACTIVE_BIND == tun.name else "备用网卡"
            print(f"[+] {tun.name} ({role}) 完全就绪: 入口 {node['ip']} -> 出口 {egress_ip}", flush=True)
        else:
            try:
                tail = "\\n".join(log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-8:])
                if tail:
                    print(f"[-] {tun.name} OpenVPN 未完成初始化，最近错误:\\n{tail}", flush=True)
                else:
                    print(f"[-] {tun.name} OpenVPN 未完成初始化，进程已退出或没有产生日志: {node['ip']}", flush=True)
            except Exception as e:
                print(f"[-] {tun.name} OpenVPN 未完成初始化，且读取错误日志失败: {e}", flush=True)
            try: process.terminate(); process.wait(2)
            except: process.kill()
            cleanup_tunnel(tun.name, tun.table_id)
            dead_ips.add(node["ip"])
            with state_lock:
                if tun.process == process:
                    tun.process = None
                    tun.node = None
                    tun.entry_ip = ""
                    tun.egress_ip = ""
                    tun.country = ""
                    tun.ready = False
    finally:
        with state_lock: tun.is_connecting = False

def health_check_loop():
    global tun_main, dead_ips
    fail_count = 0
    while True:
        # 如果处于异常容错状态，缩短检测间隔进行快速复核
        time.sleep(15 if fail_count == 0 else 5)

        target_tun = ""
        target_entry_ip = ""
        proc_ref = None

        with state_lock:
            if tun_main.ready and tun_main.process and tun_main.process.poll() is None:
                if time.time() - tun_main.connected_at > 20:
                    target_tun = tun_main.name
                    target_entry_ip = tun_main.entry_ip
                    proc_ref = tun_main.process

        if not target_tun:
            fail_count = 0
            continue

        # 1. 应用层：多维 HTTP 探针 (包含域名与直连IP，规避单点限流和DNS污染)
        endpoints = [
            "http://www.gstatic.com/generate_204",
            "http://cp.cloudflare.com/generate_204",
            "http://1.1.1.1",
            "http://8.8.8.8"
        ]

        is_alive = False
        for ep in endpoints:
            res = subprocess.run(["curl", "-I", "-s", "-m", "5", "--interface", target_tun, ep], capture_output=True)
            if res.returncode == 0:
                is_alive = True
                break

        # 2. 网络层：如果应用层全挂，尝试底层 ICMP (Ping) 作为终极底线
        if not is_alive:
            ping_res = subprocess.run(["ping", "-c", "2", "-W", "3", "-I", target_tun, "8.8.8.8"], capture_output=True)
            if ping_res.returncode == 0:
                is_alive = True

        # 3. 容错评估与处决
        if not is_alive:
            fail_count += 1
            if fail_count >= 3:
                print(f"[!] {target_tun} 连续 {fail_count} 次多维探针(HTTP/ICMP)均无响应，确认为真死断流，执行踢线: {target_entry_ip}", flush=True)
                dead_ips.add(target_entry_ip)
                try: proc_ref.terminate(); proc_ref.wait(timeout=2)
                except: proc_ref.kill()
                with state_lock:
                    if tun_main.process == proc_ref: tun_main.ready = False
                fail_count = 0
            else:
                print(f"[*] {target_tun} 探针无响应，启动快频深度复核容错机制 ({fail_count}/3)...", flush=True)
        else:
            fail_count = 0

def get_best_candidate():
    global global_node_reservoir, dead_ips, target_country, tun_main, tun_backup
    with reservoir_lock:
        all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x["ping"])
        candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in dead_ips]

        active_ips = []
        if tun_main.entry_ip: active_ips.append(tun_main.entry_ip)
        if tun_backup.entry_ip: active_ips.append(tun_backup.entry_ip)
        candidates = [n for n in candidates if n["ip"] not in active_ips]

        if not candidates:
            has_blacklisted = any(n["country"] == target_country for n in all_pool_nodes)
            if has_blacklisted:
                dead_ips.clear()
                print(f"[!] ⚡ 紧急熔断：[{target_country}] 节点枯竭，解锁历史黑名单救场！", flush=True)
                candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in active_ips]

        if candidates: return candidates.pop(0)
    return None

def maintain_pool():
    global dead_ips, last_blacklist_clear, tun_main, tun_backup
    while True:
        if time.time() - last_blacklist_clear > 600:
            dead_ips.clear()
            last_blacklist_clear = time.time()

        with reservoir_lock:
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips: global_node_reservoir.pop(ip, None)

        with state_lock:
            main_dead = (not tun_main.is_connecting and (tun_main.process is None or tun_main.process.poll() is not None or not tun_main.ready))
            if main_dead:
                if tun_backup.ready and tun_backup.process and tun_backup.process.poll() is None:
                    print(f"[*] ⚡ 主通道暴毙，软开关秒切！无缝接管业务至备用通道: 出口 {tun_backup.egress_ip or tun_backup.entry_ip}", flush=True)
                    # 状态互换 (身份对调)
                    tun_main, tun_backup = tun_backup, tun_main
                    proxy_server.ACTIVE_BIND = tun_main.name

                    # 异步清理死掉的旧主卡 (现在的 tun_backup)
                    if tun_backup.process:
                        try: tun_backup.process.terminate(); tun_backup.process.wait(2)
                        except: tun_backup.process.kill()
                    tun_backup.process = None; tun_backup.node = None; tun_backup.entry_ip = ""; tun_backup.egress_ip = ""
                    tun_backup.ready = False; tun_backup.is_connecting = False
                else:
                    if tun_main.process:
                        try: tun_main.process.terminate(); tun_main.process.wait(2)
                        except: tun_main.process.kill()
                    tun_main.process = None; tun_main.ready = False; tun_main.is_connecting = False
                    tun_main.entry_ip = ""; tun_main.egress_ip = ""

        with state_lock:
            needs_main = not tun_main.ready and not tun_main.is_connecting
            needs_backup = not tun_backup.ready and not tun_backup.is_connecting

        if needs_main:
            node = get_best_candidate()
            if node:
                with state_lock: tun_main.is_connecting = True
                threading.Thread(target=connect_node, args=(tun_main, node,), daemon=True).start()
                time.sleep(1)
        elif needs_backup:
            node = get_best_candidate()
            if node:
                with state_lock: tun_backup.is_connecting = True
                threading.Thread(target=connect_node, args=(tun_backup, node,), daemon=True).start()

        time.sleep(2)

def main():
    global PROXY_PORT, tun_main
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", "openvpn.*tun_main|tun_backup"], capture_output=True)
    cleanup_tunnel(tun_main.name, tun_main.table_id)
    cleanup_tunnel(tun_backup.name, tun_backup.table_id)

    proxy_server.ACTIVE_BIND = tun_main.name

    try:
        req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.loads(res.read().decode("utf-8"))
            PROXY_PORT = int(data.get("port", 7920))
    except: pass

    print("========================================", flush=True)
    print(f"  Proxy Controller (主备双活引擎) 启动！端口: {PROXY_PORT}", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=vpngate_fetch_loop, daemon=True).start()
    threading.Thread(target=update_config_loop, daemon=True).start()
    threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", PROXY_PORT), daemon=True).start()
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/agent") {
      if (!authenticateAgent(request, true)) return unauthorizedResponse("Proxy Agent Bootstrap");
      const agentScript = `#!/usr/bin/env bash
set -euo pipefail

WORKER_ORIGIN=${shellQuote(domain)}
AGENT_TOKEN=${shellQuote(AGENT_TOKEN)}
PROXY_USER_VALUE=${shellQuote(PROXY_USER)}
PROXY_PASS_VALUE=${shellQuote(PROXY_PASS)}

echo "=========================================================="
echo "     Proxy Controller (Active-Standby Multi-Tunnel)    "
echo "=========================================================="

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] 请使用 root 用户运行安装命令。"
  exit 1
fi

# 彻底修复内核反向路径过滤导致备用通道回包被丢弃的问题
echo "net.ipv4.conf.all.rp_filter=2" > /etc/sysctl.d/99-proxy-lite.conf
echo "net.ipv4.conf.default.rp_filter=2" >> /etc/sysctl.d/99-proxy-lite.conf
sysctl --system >/dev/null 2>&1

apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron psmisc

install -d -m 700 /opt/proxy_lite/configs
cd /opt/proxy_lite

cat > /opt/proxy_lite/proxy-lite.env << EOF
C2_TOKEN=$AGENT_TOKEN
PROXY_USER=$PROXY_USER_VALUE
PROXY_PASS=$PROXY_PASS_VALUE
EOF
chmod 600 /opt/proxy_lite/proxy-lite.env
printf "%s" "$AGENT_TOKEN" > /opt/proxy_lite/agent_token
chmod 600 /opt/proxy_lite/agent_token

echo "[1/3] 从安全中心拉取双活极速引擎..."
curl -fsSL -H "Authorization: Bearer $AGENT_TOKEN" -o lite_manager.py "$WORKER_ORIGIN/scripts/lite_manager.py"
curl -fsSL -H "Authorization: Bearer $AGENT_TOKEN" -o proxy_server.py "$WORKER_ORIGIN/scripts/proxy_server.py"
python3 -m py_compile lite_manager.py proxy_server.py

echo "[2/3] 配置系统守护服务..."
cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Proxy Core Engine (Active-Standby)
After=network.target

[Service]
Type=simple
Environment="PYTHONIOENCODING=utf-8"
Environment="LANG=C.UTF-8"
EnvironmentFile=/opt/proxy_lite/proxy-lite.env
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
systemctl restart proxy-lite.service

echo "[+] 引擎更新成功！主备双活通道、异步刷IP逻辑已全量加载。"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname.startsWith("/api/testisp-lookup/")) {
        if (!authenticateWeb(request)) return unauthorizedResponse();
        const targetIp = safeNetText(decodeURIComponent(url.pathname.replace("/api/testisp-lookup/", "")), 80);
        if (!targetIp) {
            return new Response(JSON.stringify({ error: "Invalid IP" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        try {
            const reqUrl = `https://testisp.info/api/check?ip=${encodeURIComponent(targetIp)}`;
            const resp = await fetch(reqUrl, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Referer": "https://testisp.info/"
                }
            });
            const data = await resp.text();
            return new Response(data, {
                status: resp.status,
                headers: {
                    "Content-Type": resp.headers.get("content-type") || "application/json",
                    "Access-Control-Allow-Origin": "*"
                }
            });
        } catch (err) {
            return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
        }
    }

    if (url.pathname === "/api/countries") {
        try {
            const response = await fetch("https://www.vpngate.net/api/iphone/");
            const text = await response.text();
            const lines = text.split('\n');
            const dynamicCountries = new Set();
            for (let i = 2; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if (parts.length > 6) {
                    const country = parts[6];
                    if (country && country.length === 2 && country !== "xx" && country !== "--") {
                        dynamicCountries.add(country.toUpperCase());
                    }
                }
            }
            const predefinedCountries = ["US", "JP", "KR", "SG", "HK", "TW", "GB", "DE", "FR", "NL", "CA", "AU", "IN", "VN", "BR", "AE", "MY", "TH", "PH", "ID", "TR", "ZA", "IT", "ES", "RU", "CH", "SE", "PL", "NO", "DK", "FI", "IE", "AT", "NZ", "BE", "PT", "CZ", "GR", "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "UA", "RS", "BA", "CY", "MT", "IS", "LU"];
            const allCountries = new Set([...predefinedCountries, ...Array.from(dynamicCountries)]);
            return new Response(JSON.stringify(Array.from(allCountries).sort()), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        } catch(err) {
            return new Response(JSON.stringify(["US", "JP", "KR", "SG", "HK", "TW"]), { headers: { "Content-Type": "application/json" } });
        }
    }

    if (url.pathname === "/" || url.pathname === "/api/nodes" || url.pathname === "/api/proxies") {
      if (!authenticateWeb(request)) return unauthorizedResponse();
    }

    if (url.pathname === "/api/config" && request.method === "GET") {
      if (!authenticateWeb(request) && !authenticateAgent(request)) return unauthorizedResponse();
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
      if (!authenticateWeb(request)) return unauthorizedResponse();
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      if (!authenticateAgent(request)) return unauthorizedResponse("Proxy Agent API");
    }

    if (url.pathname === "/api/config" && request.method === "GET") {
        const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'slot_map'`).all();
        if (results && results.length > 0) return new Response(results[0].value, { headers: { "Content-Type": "application/json" } });
        return new Response(JSON.stringify({ "0": "JP", "port": 7920 }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        const data = await request.json();
        const sanitizedMap = {
            "0": sanitizeCountry(data["0"] || "JP"),
            "port": sanitizePort(data.port)
        };
        if (data.switch_trigger) sanitizedMap.switch_trigger = Math.max(0, Number.parseInt(data.switch_trigger, 10) || Date.now());
        await env.DB.prepare(`INSERT INTO global_config (key, value) VALUES ('slot_map', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(JSON.stringify(sanitizedMap)).run();
        return new Response("OK");
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        const reportIp = safeNetText(data.ip, 80);
        if (!reportIp) return new Response("Invalid report", { status: 400 });
        const details = sanitizeDetails(data.details || []);
        await env.DB.prepare(`INSERT INTO servers (ip, details, last_seen) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET details = excluded.details, last_seen = excluded.last_seen`).bind(reportIp, JSON.stringify(details), Date.now()).run();
        if (data.logs) {
          const safeLogs = String(data.logs).slice(-12000);
          await env.DB.prepare(`INSERT INTO server_logs (ip, logs, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET logs = excluded.logs, updated_at = excluded.updated_at`).bind(reportIp, safeLogs, Date.now()).run();
        }
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error", { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      const proxyUserPart = encodeURIComponent(PROXY_USER);
      const proxyPassPart = encodeURIComponent(PROXY_PASS);
      if (results) {
        for (let server of results) {
          let details = [];
          try { details = JSON.parse(server.details || '[]'); } catch (e) { details = []; }
          const activeNode = details.find(d => d.active) || details[0];
          if (activeNode) {
            proxyList.push(`socks5://${proxyUserPart}:${proxyPassPart}@${safeNetText(server.ip)}:${sanitizePort(activeNode.port)}#${sanitizeCountry(activeNode.country)}_ActiveNode_${safeNetText(activeNode.node_ip || 'IP')}`);
          }
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`
        SELECT s.*, l.logs
        FROM servers s
        LEFT JOIN server_logs l ON s.ip = l.ip
        ORDER BY s.last_seen DESC
      `).all();
      return new Response(JSON.stringify(results || []), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      return new Response(DASHBOARD_HTML(domain, WEB_USER, PROXY_USER, AGENT_TOKEN), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = (domain, webUser, proxyUser, agentToken) => {
const agentInstallUrl = `${domain}/agent?token=${encodeURIComponent(agentToken)}`;
return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Controller - 双活引擎总控</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.5); }
        ::-webkit-scrollbar-thumb { background: rgba(51, 65, 85, 0.8); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(71, 85, 105, 1); }
        input[type=number]::-webkit-inner-spin-button,
        input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
    </style>
</head>
<body class="min-h-screen bg-[#090E17] text-slate-300 relative overflow-x-hidden selection:bg-indigo-500/30">
    <div class="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/20 blur-[120px] rounded-full pointer-events-none z-0"></div>
    <div class="fixed bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none z-0"></div>

    <div class="max-w-7xl mx-auto p-6 relative z-10">
        <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-10 gap-6">
            <div>
                <h1 class="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 tracking-tight drop-shadow-sm">Proxy Controller</h1>
                <p class="text-slate-400 mt-2 text-sm flex items-center gap-2">
                    <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                    直链提取 API: <a href="/api/proxies" target="_blank" class="text-indigo-400 hover:text-indigo-300 border-b border-indigo-400/30 hover:border-indigo-300 transition-colors">${domain}/api/proxies</a>
                </p>
            </div>

            <div class="flex flex-col gap-3 w-full md:w-auto">
                <div class="bg-slate-900/80 backdrop-blur-md border border-slate-700/50 rounded-xl overflow-hidden shadow-lg">
                    <div class="bg-slate-800/50 px-4 py-2 border-b border-slate-700/50 flex items-center gap-2">
                        <div class="flex gap-1.5">
                            <div class="w-3 h-3 rounded-full bg-rose-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-amber-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                        </div>
                        <span class="text-xs text-slate-400 font-mono ml-2">VPS 纳管命令 (Root)</span>
                    </div>
                    <div class="p-3 bg-[#0D1117] text-sm font-mono text-emerald-400 select-all overflow-x-auto whitespace-nowrap">
                        bash <(curl -fsSL ${agentInstallUrl})
                    </div>
                </div>

                <div class="flex gap-4 text-xs font-mono">
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">面板凭证</span>
                        <span class="text-indigo-300 font-bold ml-4">${webUser} <span class="text-slate-600">/</span> 已隐藏</span>
                    </div>
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">代理凭证</span>
                        <span class="text-amber-300 font-bold ml-4">${proxyUser} <span class="text-slate-600">/</span> 已隐藏</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
            <div class="lg:col-span-1 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20">
                <div class="flex items-center gap-2 mb-4">
                    <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <h2 class="text-lg font-bold text-slate-200">全量国家代码库</h2>
                </div>
                <p class="text-xs text-slate-500 mb-4 leading-relaxed">系统已合并预设代码及实时的网络探测代码，提供最全面的目标锁定选择。</p>
                <div id="countries-list" class="flex flex-wrap gap-2 max-h-[160px] overflow-y-auto pr-1">
                    <span class="text-slate-600 text-sm animate-pulse">正在同步数据库...</span>
                </div>
            </div>

            <div class="lg:col-span-3 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20 flex flex-col justify-center relative overflow-hidden">
                <div class="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
                    <svg class="w-32 h-32" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                </div>

                <div class="mb-6 relative z-10">
                    <h2 class="text-2xl font-bold text-slate-100 tracking-wide mb-1 flex items-center gap-2">主备双活调度引擎 <span class="bg-indigo-500/20 text-indigo-400 text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border border-indigo-500/30">Active-Standby</span></h2>
                    <p class="text-sm text-slate-400">单路端口锁定，内置主备双路隧道 (tun_main / tun_backup)，通道死活将由软开关瞬间接管。</p>
                </div>

                <div class="flex flex-wrap items-center bg-slate-950/50 border border-slate-800/80 rounded-xl p-5 relative z-10 gap-y-4">
                    <div class="flex items-center gap-3 mr-3 border-r border-slate-700/50 pr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">目标地区:</span>
                        <input type="text" id="slot-cfg-0" value="JP" maxlength="2" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-16 text-white font-bold text-lg uppercase text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="US" />
                    </div>

                    <div class="flex items-center gap-3 mr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">服务端口:</span>
                        <input type="number" id="slot-port" value="7920" min="1024" max="65535" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-24 text-white font-bold text-lg text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="7920" />
                    </div>

                    <button onclick="saveConfig()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-bold shadow-lg shadow-blue-900/20 hover:shadow-indigo-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden ml-auto">
                        <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                        <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg>
                            下发策略
                        </span>
                    </button>

                    <div class="h-8 w-px bg-slate-800 mx-2 hidden sm:block"></div>

                    <button onclick="switchIP()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 text-white text-sm font-bold shadow-lg shadow-purple-900/20 hover:shadow-pink-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden">
                         <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                         <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                            强制更换 IP
                         </span>
                    </button>
                </div>
            </div>
        </div>

        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse"></div>
                    活跃节点矩阵
                </h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider">
                            <th class="py-4 px-6 font-medium w-1/5">母机宿主 IP</th>
                            <th class="py-4 px-6 font-medium">主备双路出口状态 (Active / Standby)</th>
                            <th class="py-4 px-6 font-medium w-32">心跳延迟</th>
                            <th class="py-4 px-6 font-medium text-right w-24">负载率</th>
                        </tr>
                    </thead>
                    <tbody id="nodes-table" class="divide-y divide-slate-800/50 text-sm">
                        <tr><td colspan="4" class="py-12 text-center text-slate-500">正在与 D1 数据库建立量子纠缠...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div id="ip-score-section" style="display: none;" class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    原生深度质检报告 (testisp.info)
                </h3>
                <a id="ip-score-link" href="#" class="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors">
                    原版页面 <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                </a>
            </div>

            <div id="native-score-container" class="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 bg-[#090E17]">
                <div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500">
                    <svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    <span>穿透请求中，正在构建原生质检报告...</span>
                </div>
            </div>
        </div>

        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 pb-8">
            <div class="px-4 py-3 border-b border-slate-800 bg-slate-900/80 flex justify-between items-center">
                <span class="text-xs text-slate-400 font-mono flex items-center gap-2">
                    <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M4 17h16a2 2 0 002-2V5a2 2 0 00-2-2H4a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                    VPS 实时运行日志 (Auto-Sync)
                </span>
                <span class="flex gap-1.5">
                    <div class="w-3 h-3 rounded-full bg-rose-500/80 shadow-[0_0_5px_rgba(244,63,94,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-amber-500/80 shadow-[0_0_5px_rgba(245,158,11,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-emerald-500/80 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div>
                </span>
            </div>
            <div class="p-4 h-64 overflow-y-auto bg-[#0D1117] font-mono text-[13px] leading-relaxed text-slate-300" id="terminal-output">
                <div class="text-slate-500 animate-pulse">等待 VPS 心跳回传日志数据...</div>
            </div>
        </div>
    </div>

    <script>
        let currentScoreIp = "";

        function escapeHtml(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                container.innerHTML = list.map(c => \`<span class="bg-slate-800/80 hover:bg-indigo-500/20 text-slate-300 hover:text-indigo-300 transition-colors border border-slate-700/50 px-2.5 py-1 rounded-md text-xs font-mono font-bold shadow-sm cursor-default">\${escapeHtml(c)}</span>\`).join('');
            } catch(e) {}
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/config');
                const map = await res.json();
                document.getElementById('slot-cfg-0').value = map["0"] || 'JP';
                document.getElementById('slot-port').value = map["port"] || 7920;
            } catch(e) {}
        }

        async function saveConfig() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            const port = parseInt(document.getElementById(\`slot-port\`).value) || 7920;
            await fetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val, "port": port })
            });
            alert('🚀 策略及端口已云端同步！Agent 将在下一心跳周期应用。');
        }

        async function switchIP() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            const port = parseInt(document.getElementById(\`slot-port\`).value) || 7920;
            await fetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val, "port": port, "switch_trigger": Date.now() })
            });
            alert('🔄 重拨指令已下发！VPS 将清退当前通道池重新并发建连...');
        }

        async function loadNativeIpScore(ip) {
            const container = document.getElementById('native-score-container');
            container.innerHTML = '<div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500"><svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg><span>穿透请求中，正在构建原生质检报告...</span></div>';

            try {
                const res = await fetch('/api/testisp-lookup/' + encodeURIComponent(ip));
                const rawText = await res.text();

                let d;
                try {
                    d = JSON.parse(rawText);
                } catch (e) {
                    const safeText = escapeHtml(rawText.substring(0, 500));
                    throw new Error(\`目标接口返回了非 JSON 格式数据(可能 API 路径错误或被云端盾拦截)。<br>HTTP 状态码: \${res.status}<br><div class="mt-3 text-left bg-slate-900 p-3 rounded text-xs text-rose-300 font-mono break-all overflow-y-auto max-h-32 border border-rose-500/30">\${safeText}</div>\`);
                }

                if (!d || !d.geo || !d.isp) {
                    container.innerHTML = \`<div class="col-span-full text-center py-8 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">无法获取报告: 接口返回数据结构异常 \${escapeHtml(d?.error || '')}</div>\`;
                    return;
                }

                const isHosting = d.isp.flag === 'hosting';
                const threat = Boolean(d.risk?.threat_listed);
                const isNative = d.geo.is_native;

                const tags = isHosting
                    ? '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-bold">机房IP</span>'
                    : '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 text-xs font-bold">家庭宽带</span>';

                const locStr = escapeHtml([d.geo.country, d.geo.city].filter(Boolean).join(" "));
                const orgStr = escapeHtml(d.isp.org || '-');
                const safeIp = escapeHtml(ip);
                const countryCode = escapeHtml(d.geo.country_code || 'N/A');
                const nativeType = escapeHtml(d.geo.native_type || '广播 IP');
                const ispType = escapeHtml(d.isp.type || '-');
                const asn = escapeHtml(d.isp.asn || '-');
                const timezone = escapeHtml(d.geo.timezone || '-');
                const driftKm = escapeHtml(d.geo.drift_km || 0);
                const rdns = escapeHtml(d.isp.rdns || '-');
                const warning = escapeHtml(d.isp.warning || '未检测到明显异常');
                const dataSource = escapeHtml(d.data_source || 'Unknown');

                container.innerHTML = \`
                    <div class="col-span-full bg-slate-800/60 border border-slate-700/80 p-5 rounded-2xl flex flex-wrap gap-4 justify-between items-center mb-2 shadow-lg">
                        <div class="flex items-center gap-4">
                            <span class="text-3xl font-extrabold font-mono text-white tracking-tight drop-shadow-sm">\${safeIp}</span>
                            <span class="text-slate-400 text-sm hidden sm:flex items-center border-l border-slate-700 pl-4 h-6">
                                <span class="uppercase tracking-widest text-indigo-400 mr-2 text-xs font-bold">\${countryCode}</span>
                                \${locStr} · \${orgStr}
                            </span>
                        </div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">基础物理画像</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">IP 原生性</span> <span class="font-medium text-sm">\${isNative ? '<span class="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold">原生 IP (Native)</span>' : \`<span class="px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-bold">\${nativeType}</span>\`}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">业务标记</span> <div class="flex gap-1">\${tags}</div></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">运营类型</span> <span class="font-medium \${isHosting ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${ispType}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">归属机构</span> <span class="font-medium text-slate-300 text-sm truncate max-w-[150px]" title="\${orgStr}">\${orgStr}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">ISP 网络底层</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">ASN</span> <span class="font-medium text-indigo-300 text-sm font-mono">\${asn}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">解析时区</span> <span class="font-medium text-slate-300 text-sm font-mono">\${timezone}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">偏移量 (Drift)</span> <span class="font-medium \${d.geo.has_drift ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${driftKm} km</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">反向 DNS (rDNS)</span> <span class="font-medium text-slate-400 text-xs font-mono truncate max-w-[150px]" title="\${rdns}">\${rdns}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">风险深度检测</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">Spamhaus 情报</span> <span class="\${threat ? 'px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-bold' : 'px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold'}">\${threat ? '🚨 已在黑名单' : '✅ 纯净无异常'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">代理/机房特征</span> <span class="font-medium text-xs font-bold \${d.isp.warning ? 'text-amber-400' : 'text-emerald-400'} truncate max-w-[150px]" title="\${warning}">\${warning}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">数据源</span> <span class="font-medium text-slate-400 text-xs">\${dataSource}</span></div>
                    </div>
                \`;
            } catch (e) {
                container.innerHTML = \`<div class="col-span-full text-left p-6 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">\${escapeHtml(e.message)}</div>\`;
            }
        }

        async function fetchNodes() {
            try {
                const res = await fetch('/api/nodes');
                const servers = await res.json();
                const tbody = document.getElementById('nodes-table');
                const terminal = document.getElementById('terminal-output');

                if (!servers || servers.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-12 text-center text-slate-500 flex-col items-center justify-center"><svg class="w-12 h-12 mx-auto text-slate-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>未检测到在线母机，请在 VPS 运行纳管命令接入</td></tr>';
                    return;
                }

                tbody.innerHTML = servers.map(server => {
                    let details = [];
                    try { details = JSON.parse(server.details || '[]'); } catch(e) { details = []; }
                    const timeAgo = Math.floor((Date.now() - server.last_seen) / 1000);
                    const serverIp = escapeHtml(server.ip);

                    let proxyBadges = '';
                    if (details.length === 0) {
                        proxyBadges = \`
                        <div class="inline-flex items-center bg-slate-900 border border-amber-500/30 rounded-xl px-3 py-1.5 shadow-inner text-amber-400/90 text-sm">
                            <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-amber-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                            双路通道震荡熔断，正在全异步抢救拨号中...
                        </div>\`;
                    } else {
                        proxyBadges = '<div class="flex flex-col gap-2">' + details.map(d => {
                            const isActive = d.active;
                            const statusColorClass = isActive ? 'bg-emerald-500' : 'bg-sky-500';
                            const statusText = isActive ? 'ACTIVE (业务出口)' : 'STANDBY (热备就绪)';
                            const borderColorClass = isActive ? 'border-emerald-500/30' : 'border-sky-500/30';
                            const bgColorClass = isActive ? 'bg-emerald-500/10' : 'bg-sky-500/10';
                            const textColorClass = isActive ? 'text-emerald-400' : 'text-sky-400';
                            const tunnel = escapeHtml(d.tunnel || '');
                            const country = escapeHtml(d.country || '');
                            const nodeIp = escapeHtml(d.node_ip || '---.---.---.---');
                            const port = escapeHtml(d.port || '');

                            return \`
                            <div class="inline-flex items-center bg-slate-950 border border-slate-800/80 rounded-xl px-2.5 py-1.5 shadow-inner">
                                <span class="bg-slate-800 text-slate-300 font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-slate-700 font-bold">\${tunnel}</span>
                                <span class="bg-indigo-500/20 text-indigo-400 font-bold font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-indigo-500/20">\${country}</span>
                                <span class="font-mono text-slate-300 text-sm tracking-wide mr-3" title="出口物理 IP">\${nodeIp}:\${port}</span>
                                <span class="flex items-center gap-1.5 \${textColorClass} \${bgColorClass} px-2 py-0.5 rounded-md border \${borderColorClass} text-xs font-medium">
                                    <span class="w-1.5 h-1.5 rounded-full \${statusColorClass} shadow-[0_0_5px_currentColor]"></span> \${statusText}
                                </span>
                            </div>\`;
                        }).join('') + '</div>';
                    }

                    return \`
                        <tr class="hover:bg-slate-800/30 transition-colors group">
                            <td class="py-5 px-6 font-mono text-indigo-300 align-middle">
                                <div class="flex items-center gap-2">
                                    <svg class="w-4 h-4 text-slate-600 group-hover:text-indigo-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                                    \${serverIp}
                                </div>
                            </td>
                            <td class="py-5 px-6 align-middle">\${proxyBadges}</td>
                            <td class="py-5 px-6 align-middle">
                                <span class="flex items-center gap-1.5 \${timeAgo < 20 ? 'text-emerald-400' : 'text-rose-400'} font-mono text-xs">
                                    <span class="w-1.5 h-1.5 rounded-full \${timeAgo < 20 ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                                    \${timeAgo}s 前
                                </span>
                            </td>
                            <td class="py-5 px-6 align-middle text-right">
                                <span class="\${details.length === 2 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : (details.length === 1 ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30')} py-1 px-3 rounded-md text-xs font-mono font-bold">
                                    \${details.length} / 2
                                </span>
                            </td>
                        </tr>
                    \`;
                }).join('');

                if (servers.length > 0 && servers[0].details) {
                    let details = [];
                    try { details = JSON.parse(servers[0].details); } catch(e) { details = []; }
                    // 深度质检报告：永远提取正在承载业务的 ACTIVE 网卡 IP 进行评分
                    const activeNode = details.find(d => d.active) || details[0];
                    if (activeNode && activeNode.node_ip) {
                        const newIp = String(activeNode.node_ip);
                        if (newIp !== currentScoreIp) {
                            currentScoreIp = newIp;
                            document.getElementById('ip-score-section').style.display = 'block';

                            // 针对 testisp.info 前端默认仅查本机的防呆机制：自动复制 IP 到剪贴板，跳转后由用户粘贴
                            const scoreLink = document.getElementById('ip-score-link');
                            scoreLink.href = \`https://testisp.info/?ip=\${encodeURIComponent(newIp)}\`;
                            scoreLink.onclick = (e) => {
                                e.preventDefault();
                                navigator.clipboard.writeText(newIp).then(() => {
                                    alert('🟢 已自动复制隧道节点 IP: ' + newIp + '\\n\\n由于 testisp.info 官网默认仅检测本机，请在随后打开的网页【输入框】中【粘贴】并回车查询！');
                                    window.open(\`https://testisp.info/?ip=\${encodeURIComponent(newIp)}\`, '_blank');
                                }).catch(() => {
                                    window.open(\`https://testisp.info/?ip=\${encodeURIComponent(newIp)}\`, '_blank');
                                });
                            };

                            loadNativeIpScore(newIp);
                        }
                    }
                }

                if (servers[0] && servers[0].logs) {
                    const isAtBottom = terminal.scrollHeight - terminal.scrollTop <= terminal.clientHeight + 30;

                    let logHTML = servers[0].logs
                        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
                        .replace(/\\[\\*\\]/g, '<span class="text-indigo-400 font-bold">[*]</span>')
                        .replace(/\\[\\+\\]/g, '<span class="text-emerald-400 font-bold">[+]</span>')
                        .replace(/\\[\\-\\]/g, '<span class="text-rose-400 font-bold">[-]</span>')
                        .replace(/\\[\\!\\]/g, '<span class="text-amber-400 font-bold">[!]</span>');

                    terminal.innerHTML = '<pre class="whitespace-pre-wrap break-all">' + logHTML + '</pre>';

                    if (isAtBottom) {
                        terminal.scrollTop = terminal.scrollHeight;
                    }
                }

            } catch (err) {}
        }

        fetchCountries();
        loadConfig();
        fetchNodes();
        setInterval(fetchNodes, 5000);
    </script>
</body>
</html>
`;
};
