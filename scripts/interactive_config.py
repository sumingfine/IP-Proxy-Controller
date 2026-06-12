#!/usr/bin/env python3
"""Interactive secure configuration helper for Proxy Controller."""

from __future__ import annotations

import re
import secrets
import string
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRANGLER = ROOT / "wrangler.toml"
DEPLOY_DIR = ROOT / ".deploy"
SAFE_ALPHABET = string.ascii_letters + string.digits + "-_"


def random_secret(length: int = 40) -> str:
    return "".join(secrets.choice(SAFE_ALPHABET) for _ in range(length))


def toml_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def read_existing_value(key: str, default: str) -> str:
    if not WRANGLER.exists():
        return default
    match = re.search(rf'^\s*{re.escape(key)}\s*=\s*"([^"]*)"', WRANGLER.read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1) if match else default


def ask(label: str, default: str = "", required: bool = True) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{label}{suffix}: ").strip()
        if not value:
            value = default
        if value or not required:
            return value
        print("  This value is required.")


def ask_secret(label: str, default_length: int = 40) -> str:
    value = input(f"{label} [press Enter to generate]: ").strip()
    if value:
        return value
    generated = random_secret(default_length)
    print(f"  generated: {generated}")
    return generated


def write_wrangler(worker_name: str, database_name: str, database_id: str, web_user: str, proxy_user: str) -> None:
    WRANGLER.write_text(
        f'''name = "{toml_string(worker_name)}"
main = "src/index.js"
compatibility_date = "2026-06-03"
workers_dev = true

# Non-sensitive values may stay here. Passwords and AGENT_TOKEN must be stored
# with Wrangler secrets; run .deploy/apply_secrets.ps1 or .deploy/apply_secrets.sh.
[vars]
WEB_USER = "{toml_string(web_user)}"
PROXY_USER = "{toml_string(proxy_user)}"

[[d1_databases]]
binding = "DB"
database_name = "{toml_string(database_name)}"
database_id = "{toml_string(database_id)}"
''',
        encoding="utf-8",
    )


def write_secret_helpers(web_pass: str, proxy_pass: str, agent_token: str) -> None:
    DEPLOY_DIR.mkdir(exist_ok=True)
    (DEPLOY_DIR / "secrets.env").write_text(
        f"WEB_PASS={web_pass}\nPROXY_PASS={proxy_pass}\nAGENT_TOKEN={agent_token}\n",
        encoding="utf-8",
    )
    (DEPLOY_DIR / "apply_secrets.ps1").write_text(
        """$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
$secrets = @{}
Get-Content (Join-Path $PSScriptRoot 'secrets.env') | ForEach-Object {
  if ($_ -match '^\\s*([^#][^=]+)=(.*)$') {
    $secrets[$matches[1].Trim()] = $matches[2]
  }
}
foreach ($key in @('WEB_PASS', 'PROXY_PASS', 'AGENT_TOKEN')) {
  if (-not $secrets.ContainsKey($key) -or [string]::IsNullOrWhiteSpace($secrets[$key])) {
    throw "Missing $key in .deploy/secrets.env"
  }
  Write-Host "Uploading secret $key"
  $secrets[$key] | npx wrangler secret put $key
}
""",
        encoding="utf-8",
    )
    (DEPLOY_DIR / "apply_secrets.sh").write_text(
        """#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
set -a
. ./.deploy/secrets.env
set +a
for key in WEB_PASS PROXY_PASS AGENT_TOKEN; do
  value="${!key:-}"
  if [ -z "$value" ]; then
    echo "Missing $key in .deploy/secrets.env" >&2
    exit 1
  fi
  echo "Uploading secret $key"
  printf '%s' "$value" | npx wrangler secret put "$key"
done
""",
        encoding="utf-8",
    )


def main() -> None:
    print("Proxy Controller secure interactive configuration")
    print("Sensitive values are written only under .deploy/, which is gitignored.")
    print()

    worker_name = ask("Cloudflare Worker name", read_existing_value("name", "proxy-controller"))
    database_name = ask("D1 database name", read_existing_value("database_name", "proxy_db"))
    database_id = ask("D1 database id", read_existing_value("database_id", ""), required=False)
    if not database_id:
        print("  You can fill database_id later after running: npx wrangler d1 create <database_name>")

    web_user = ask("Web panel username", read_existing_value("WEB_USER", "admin"))
    web_pass = ask_secret("Web panel password", 40)
    proxy_user = ask("Proxy username", read_existing_value("PROXY_USER", "proxy"))
    proxy_pass = ask_secret("Proxy password", 40)
    agent_token = ask_secret("Agent registration/runtime token", 48)

    write_wrangler(worker_name, database_name, database_id, web_user, proxy_user)
    write_secret_helpers(web_pass, proxy_pass, agent_token)

    print()
    print("Done.")
    print(f"- Updated: {WRANGLER}")
    print(f"- Created: {DEPLOY_DIR / 'secrets.env'}")
    print()
    print("Next steps:")
    print("1. Create or bind the D1 database if database_id is still blank.")
    print("2. Upload secrets:")
    print("   PowerShell: .\\.deploy\\apply_secrets.ps1")
    print("   Bash:       bash ./.deploy/apply_secrets.sh")
    print("3. Deploy: npx wrangler deploy")


if __name__ == "__main__":
    main()
