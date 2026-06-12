# 部署与使用说明

本文档适用于已加固版本：控制端运行在 Cloudflare Workers + D1，VPS 端运行 Python Agent，并通过 `AGENT_TOKEN` 与控制端通信。

## 一、部署前准备

你需要准备：

- 一个 GitHub 仓库，用来保存本项目代码。
- 一个 Cloudflare 账号。
- 一台干净的 Linux VPS，推荐 Ubuntu 20.04/22.04、Debian 11/12。
- 本机安装 Node.js、Python 3、Git。
- 本机可运行 `npx wrangler`。

安全建议：

- 不要把 `.deploy/`、`.dev.vars`、任何密码或 token 提交到 GitHub。
- VPS 代理端口不要长期对全网开放，建议只允许你的固定 IP 访问。
- `WEB_PASS`、`PROXY_PASS`、`AGENT_TOKEN` 要使用长随机字符串。

## 二、克隆你的仓库

```bash
git clone git@github.com:你的用户名/IP-Proxy-Controller.git
cd IP-Proxy-Controller
```

如果你是在 Windows PowerShell 中操作，同样可以执行：

```powershell
git clone git@github.com:你的用户名/IP-Proxy-Controller.git
cd IP-Proxy-Controller
```

## 三、安装并登录 Wrangler

```bash
npm install -g wrangler
npx wrangler login
```

登录时浏览器会打开 Cloudflare 授权页面，授权完成后回到终端。

## 四、创建 Cloudflare D1 数据库

```bash
npx wrangler d1 create proxy_db
```

命令会输出类似内容：

```toml
[[d1_databases]]
binding = "DB"
database_name = "proxy_db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

把 `database_id` 复制下来，下一步交互式配置会用到。

## 五、运行交互式配置

在项目根目录执行：

```bash
python scripts/interactive_config.py
```

脚本会依次询问：

| 项目 | 说明 | 建议 |
| --- | --- | --- |
| Cloudflare Worker name | Worker 项目名 | 例如 `ip-proxy-controller` |
| D1 database name | D1 数据库名 | 一般填 `proxy_db` |
| D1 database id | D1 数据库 ID | 填第四步输出的 `database_id` |
| Web panel username | 面板用户名 | 可用 `admin` 或自定义 |
| Web panel password | 面板密码 | 直接回车自动生成 |
| Proxy username | 代理用户名 | 可用 `proxy` 或自定义 |
| Proxy password | 代理密码 | 直接回车自动生成 |
| Agent registration/runtime token | VPS Agent token | 直接回车自动生成 |

脚本会生成或修改这些文件：

- `wrangler.toml`：保存 Worker 名称、D1 绑定、非敏感用户名。
- `.deploy/secrets.env`：保存本地 secrets，不要提交。
- `.deploy/apply_secrets.ps1`：Windows PowerShell 上传 secrets 脚本。
- `.deploy/apply_secrets.sh`：Linux/macOS 上传 secrets 脚本。

## 六、上传 Secrets

Windows PowerShell：

```powershell
.\.deploy\apply_secrets.ps1
```

Linux/macOS：

```bash
bash ./.deploy/apply_secrets.sh
```

这些 secrets 会被上传到 Cloudflare Workers：

- `WEB_PASS`：Web 面板 Basic Auth 密码。
- `PROXY_PASS`：Socks5/HTTP 代理密码。
- `AGENT_TOKEN`：VPS Agent 下载脚本、拉取脚本、心跳上报所需 token。

## 七、部署 Worker

```bash
npx wrangler deploy
```

部署成功后，终端会输出 Worker 地址，例如：

```text
https://ip-proxy-controller.你的账号.workers.dev
```

打开这个地址，浏览器会弹出 Basic Auth 登录框：

- 用户名：你在交互式配置里填写的 `WEB_USER`
- 密码：`.deploy/secrets.env` 里的 `WEB_PASS`

## 八、纳管 VPS

登录 Web 面板后，右上角会显示 VPS 纳管命令，格式类似：

```bash
bash <(curl -fsSL https://你的-worker.workers.dev/agent?token=你的AGENT_TOKEN)
```

在 VPS 上用 root 执行该命令：

```bash
ssh root@你的VPS_IP
bash <(curl -fsSL "https://你的-worker.workers.dev/agent?token=你的AGENT_TOKEN")
```

安装脚本会自动完成：

1. 调整 Linux `rp_filter`，避免双隧道路由回包被丢弃。
2. 安装 `openvpn`、`python3`、`curl`、`iproute2` 等依赖。
3. 写入 `/opt/proxy_lite/proxy-lite.env`，保存本机运行所需 token 和代理凭据。
4. 使用 `AGENT_TOKEN` 拉取 `lite_manager.py` 和 `proxy_server.py`。
5. 创建并启动 `proxy-lite.service`。

查看 Agent 状态：

```bash
systemctl status proxy-lite.service
journalctl -u proxy-lite.service -f
```

## 九、VPS 防火墙建议

默认代理端口是 `7920`，可以在 Web 面板修改。

强烈建议只允许你的客户端 IP 访问代理端口。以 UFW 为例：

```bash
ufw allow OpenSSH
ufw allow from 你的客户端公网IP to any port 7920 proto tcp
ufw enable
ufw status
```

如果你不用 UFW，也可以在云服务商安全组里只放行你的客户端 IP。

## 十、Web 面板使用

登录 Worker 面板后，主要区域包括：

- 国家策略：填写目标国家代码，例如 `JP`、`US`、`GB`。
- 服务端口：默认 `7920`，修改后 Agent 会在下一轮同步时重启应用。
- 下发策略：保存国家和端口配置。
- 强制更换 IP：让 VPS 清退当前通道并重新拨号。
- 节点状态：显示 VPS 母机、Active/Standby 通道、出口 IP、存活时间。
- 原生深度质检：调用 TestISP 接口展示当前出口 IP 的 ISP 与风险信息。
- 实时日志：展示 VPS `proxy-lite.service` 最近日志。

## 十一、客户端连接代理

面板的 `/api/proxies` 会输出当前 Active 代理地址。访问该接口需要 Web 面板 Basic Auth：

```bash
curl -u "WEB_USER:WEB_PASS" "https://你的-worker.workers.dev/api/proxies"
```

返回示例：

```text
socks5://proxy:你的代理密码@你的VPS_IP:7920#JP_ActiveNode_x.x.x.x
```

常见客户端格式：

```text
SOCKS5 主机：你的VPS_IP
SOCKS5 端口：7920
用户名：PROXY_USER
密码：PROXY_PASS
```

HTTP 代理也支持：

```text
http://PROXY_USER:PROXY_PASS@你的VPS_IP:7920
```

## 十二、更新代码后重新发布

本地修改代码后：

```bash
git status
git add .
git commit -m "Update proxy controller"
git push
npx wrangler deploy
```

如果 Agent 端代码有变化，部署 Worker 后建议在 VPS 上重新运行面板里的纳管命令，或执行：

```bash
systemctl restart proxy-lite.service
```

## 十三、轮换密码和 Token

如果你怀疑密码泄露，建议立即轮换：

1. 重新运行：

```bash
python scripts/interactive_config.py
```

2. 上传 secrets：

```powershell
.\.deploy\apply_secrets.ps1
```

3. 重新部署：

```bash
npx wrangler deploy
```

4. 到 VPS 重新执行面板里的纳管命令，让新的 `AGENT_TOKEN` 和代理密码写入 `/opt/proxy_lite/proxy-lite.env`。

## 十四、卸载 VPS Agent

在 VPS 上执行：

```bash
systemctl stop proxy-lite.service 2>/dev/null
systemctl disable proxy-lite.service 2>/dev/null
rm -f /lib/systemd/system/proxy-lite.service
systemctl daemon-reload

pkill -f "lite_manager.py" 2>/dev/null
pkill -f "proxy_server.py" 2>/dev/null
pkill -f "openvpn.*tun_main|tun_backup" 2>/dev/null

ip rule del lookup 101 pref 101 2>/dev/null
ip rule del lookup 101 pref 1101 2>/dev/null
ip route flush table 101 2>/dev/null
ip rule del lookup 102 pref 102 2>/dev/null
ip rule del lookup 102 pref 1102 2>/dev/null
ip route flush table 102 2>/dev/null

rm -rf /opt/proxy_lite
```

## 十五、常见问题

### Worker 打开后显示未配置

说明缺少环境变量或 secrets。检查：

```bash
npx wrangler secret list
```

需要有：

- `WEB_PASS`
- `PROXY_PASS`
- `AGENT_TOKEN`

并确认 `wrangler.toml` 里有：

- `WEB_USER`
- `PROXY_USER`
- `DB` D1 绑定

### 登录面板后没有 VPS 节点

检查 VPS 服务：

```bash
systemctl status proxy-lite.service
journalctl -u proxy-lite.service -n 100 --no-pager
```

常见原因：

- VPS 无法访问 Cloudflare Worker。
- `AGENT_TOKEN` 已轮换，但 VPS 还没重新纳管。
- OpenVPN 没有成功建立隧道。
- 目标国家节点暂时不足。

### 代理端口连接不上

检查：

```bash
ss -lntp | grep 7920
systemctl status proxy-lite.service
```

如果服务正常，继续检查 VPS 防火墙、安全组是否放行你的客户端 IP。

### `/api/proxies` 返回 401

该接口需要 Basic Auth：

```bash
curl -u "WEB_USER:WEB_PASS" "https://你的-worker.workers.dev/api/proxies"
```

### 重新部署后旧 VPS 不能上报

如果你重新生成了 `AGENT_TOKEN`，旧 VPS 本地 token 已失效。重新执行面板里的纳管命令即可。
