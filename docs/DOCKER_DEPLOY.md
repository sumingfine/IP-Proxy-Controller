# 完全 Docker 化部署说明

本文档用于自托管 Docker 部署，不依赖 Cloudflare Workers 与 D1。原来的 Wrangler 部署方式仍然保留。

如果你要在 Koyeb 上用一个 Docker 同时跑控制端和 Agent，请直接看本文最后的“九、Koyeb 单容器部署”。

## 一、架构

- `controller`：Python 标准库 HTTP 服务，提供 Web 面板、API、Agent 脚本下发，使用 SQLite 保存状态。
- `agent`：Python + OpenVPN 容器，在每台 VPS 本机运行，创建 `tun_main` / `tun_backup` 并对外提供 Socks5/HTTP 代理。

> 注意：Agent 需要操作 TUN、策略路由和网络接口，必须运行在承载代理出口的 VPS 上。

## 二、准备配置

复制环境变量模板：

```bash
cp .env.example .env
```

修改 `.env`：

```env
WEB_USER=admin
WEB_PASS=请改成长随机密码
PROXY_USER=proxy
PROXY_PASS=请改成长随机密码
AGENT_TOKEN=请改成长随机Token
PUBLIC_BASE_URL=http://你的控制端域名或IP:8080
PORT=8080
AGENT_CONTROLLER_URL=http://你的控制端域名或IP:8080
```

`.env` 已加入 `.gitignore`，不要提交。

## 三、启动控制端

```bash
docker compose up -d --build controller
```

访问：

```text
http://你的控制端域名或IP:8080
```

浏览器会要求 Basic Auth：

- 用户名：`WEB_USER`
- 密码：`WEB_PASS`

## 四、启动 Agent

Agent 必须在目标 VPS 上运行，并且该 VPS 需要支持 `/dev/net/tun`。

如果控制端和 Agent 在同一台机器：

```bash
docker compose --profile agent up -d --build agent
```

如果 Agent 在另一台 VPS：

1. 把本仓库和 `.env` 放到该 VPS。
2. 确认 `.env` 里的 `AGENT_CONTROLLER_URL` 指向控制端公网地址。
3. 执行：

```bash
docker compose --profile agent up -d --build agent
```

查看日志：

```bash
docker compose logs -f agent
```

## 五、端口和防火墙

默认代理端口是 `7920`，可以在 Web 面板修改。请只允许你的客户端公网 IP 访问该端口。

如果使用云服务商安全组，建议仅放行：

- 控制端端口：`PORT`，只给你自己的管理 IP。
- 代理端口：面板配置的端口，只给你的客户端 IP。

## 六、常见问题

### Agent 无法创建 TUN

检查宿主机是否存在：

```bash
ls -l /dev/net/tun
```

如果不存在，需要先在宿主机启用 TUN。部分 VPS 还需要联系服务商开启。

### Agent 报权限不足

`compose.yaml` 已配置：

- `network_mode: host`
- `cap_add: NET_ADMIN`
- `cap_add: NET_RAW`
- `/dev/net/tun` 设备挂载

如果你的 Docker 环境仍然限制网络能力，可临时在 `agent` 服务下增加：

```yaml
privileged: true
```

这会提高容器权限，建议只在可信 VPS 上使用。

### 控制端没有节点

检查：

```bash
docker compose logs -f controller
docker compose logs -f agent
```

常见原因：

- `AGENT_CONTROLLER_URL` 无法从 Agent VPS 访问。
- `AGENT_TOKEN` 不一致。
- VPS 无法访问 VPNGate、TestISP 或 YouTube。
- OpenVPN 节点临时不可用。

## 七、代理调用

面板登录后可访问：

```text
/api/proxies
```

返回格式：

```text
socks5://PROXY_USER:PROXY_PASS@VPS公网IP:7920#JP_ActiveNode_x.x.x.x
```

HTTP 代理同端口同账号密码。

## 八、外部代理地址覆盖

如果 Docker 平台把容器内部端口映射成了另一个外部域名或端口，需要配置：

```env
PROXY_ADVERTISE_HOST=平台分配的TCP代理域名
PROXY_ADVERTISE_PORT=平台分配的TCP代理端口
```

配置后，`/api/proxies` 会输出：

```text
socks5://PROXY_USER:PROXY_PASS@PROXY_ADVERTISE_HOST:PROXY_ADVERTISE_PORT#...
```

这对 Koyeb TCP Proxy 必需，因为 Koyeb 会把容器内的 `7920` 暴露成独立的 TCP Proxy 地址。

## 九、Koyeb 单容器部署

本仓库根目录的 `Dockerfile` 是 Koyeb all-in-one 镜像，会在一个容器内同时启动：

- 控制端：HTTP `8080`
- Agent 代理服务：TCP `7920`

### 1. 创建 Koyeb Service

在 Koyeb 里选择 GitHub 仓库部署，构建方式选 Dockerfile：

```text
Dockerfile path: Dockerfile
```

### 2. 暴露端口

添加两个端口：

```text
HTTP 8080
TCP 7920
```

HTTP 健康检查：

```text
Path: /healthz
Port: 8080
Expected status: 200
```

TCP `7920` 要开启 Koyeb TCP Proxy。Koyeb 会分配一个类似下面的外部地址：

```text
xxxx.proxy.koyeb.app:随机端口
```

### 3. 开启权限

Agent 需要 OpenVPN/TUN 和策略路由能力，请在 Koyeb Service 设置里开启：

```text
Privileged: enabled
```

如果 Koyeb 当前区域或套餐不允许 privileged/TUN，这种单容器部署会失败，只能改成“控制端在 Koyeb，Agent 在 VPS”。

### 4. 环境变量

第一次部署可以先填：

```env
HOST=0.0.0.0
PORT=8080
DATABASE_PATH=/data/proxy_controller.sqlite3

WEB_USER=admin
WEB_PASS=请改成长随机密码
PROXY_USER=proxy
PROXY_PASS=请改成长随机密码
AGENT_TOKEN=请改成长随机Token

PUBLIC_BASE_URL=https://你的-koyeb-http域名.koyeb.app
```

部署完成后，到 Koyeb 的 TCP Proxy 页面复制 `7920` 对应的外部 host 和 port，再补充：

```env
PROXY_ADVERTISE_HOST=xxxx.proxy.koyeb.app
PROXY_ADVERTISE_PORT=随机端口
```

然后重新部署一次。否则 `/api/proxies` 会输出容器内地址，客户端连不上。

### 5. 持久化

挂载 Koyeb Volume：

```text
Mount path: /data
```

否则 SQLite 数据会随着实例重建丢失。

### 6. 扩缩容

保持：

```text
Min instances: 1
Max instances: 1
Scale to zero: disabled
```

原因：当前单容器模式使用本地 SQLite 和单个 Agent，不能横向多实例。

### 7. 使用代理

部署稳定后访问：

```text
https://你的-koyeb-http域名.koyeb.app/api/proxies
```

返回的地址应该是：

```text
socks5://proxy:密码@xxxx.proxy.koyeb.app:随机端口#JP_ActiveNode_x.x.x.x
```

客户端使用这个地址连接，不要手动填容器内部 `7920`。
