# Server Panel

一个自托管的 Linux 服务器资源监控与 SSH 登录审计面板，附带：

- CPU / 内存 / 网络持续占用告警
- SSH 成功登录、失败爆破检测与邮件通知
- 手动 / 自动 IP 封锁（nftables，仅作用于 22 端口）
- SSH 国家/地区白名单
- 内核层网络流量过滤（IP / CIDR / 国家，支持直接丢包、404、失败页）
- 失败页独立 vhost，可在线编辑
- Cloudflare 真实 IP 还原与 `CF-IPCountry` 兜底

面板本身是一个 Node.js 进程，只监听 `127.0.0.1`，由 nginx 反向代理并终止 TLS。
它不依赖数据库，运行数据全部是 `/var/lib/monitor` 下的 JSON 文件。

> 本仓库中的域名、IP、邮箱均为文档示例（`example.com`、`203.0.113.0/24`、
> `198.51.100.0/24` 等）。部署前请替换成你自己的值。

---

## 目录

- [功能概览](#功能概览)
- [架构与隔离](#架构与隔离)
- [环境要求](#环境要求)
- [本地运行](#本地运行)
- [生产部署](#生产部署)
- [配置项](#配置项)
- [权限要求](#权限要求)
- [安全模型](#安全模型)
- [数据与持久化](#数据与持久化)
- [运维与排查](#运维与排查)
- [测试](#测试)
- [已知限制](#已知限制)
- [许可证](#许可证)

---

## 功能概览

### 资源监控

每 60 秒直接读取 `/proc/stat`、`/proc/meminfo`、`/proc/net/dev`，不调用外部命令。
支持“连续 N 次超阈值”和“窗口内累计 N 次”两种规则，可要求任一满足或同时满足。
触发后按指标冷却，避免持续高负载刷屏。

### SSH 登录监控

通过 `journalctl -u ssh` 增量读取日志（cursor 持久化，不重复、不丢事件）：

- 首次出现的公网 IP 成功登录 → 邮件告警
- 同一 IP 在窗口内失败次数达到阈值 → 邮件告警
- 记录每一次失败尝试，保留每个 IP 的永久历史
- 私有地址、回环地址只记录不告警

### IP 封锁与地区白名单

- 手动封锁：只能封锁“有失败记录、没有成功登录、没有活跃会话、不是受保护地址、
  不是服务器自身、不是内网/保留地址”的 IP
- 自动封锁：可选，默认关闭，阈值默认 100 次 / 24 小时
- 所有拒绝原因由纯函数 `evaluateBlockRequest()` 统一判断，并有单元测试
- 只丢弃目标 TCP 22 的流量，不影响网站、邮件等其它端口
- 国家白名单使用 ipdeny.com 的公开 zone 文件，带多层“反锁死”保护

### 流量过滤

在 nftables `input` hook 上按 IP / CIDR / 国家匹配，动作支持拦截或放行，
并可选三种 HTTP/HTTPS 响应方式：直接丢包、404、302 到失败页。
规则整表原子替换，失败时保留旧表。

---

## 架构与隔离

```
浏览器 ──HTTPS──> nginx ──HTTP 127.0.0.1:8087──> server.js
                    │                              │
                    ├─ 静态失败页 vhost             ├─ /proc（只读）
                    └─ TLS 证书                     ├─ journald（ssh unit）
                                                    ├─ nftables（CAP_NET_ADMIN）
                                                    └─ mail-panel Unix socket（可选）
```

默认部署会创建：

| 资源 | 默认值 |
| --- | --- |
| 系统用户 / 组 | `monsvc:monsvc` |
| 程序目录 | `/opt/monitor`（root:root，0755） |
| 数据目录 | `/var/lib/monitor`（monsvc:monsvc，0750） |
| 环境文件 | `/etc/monitor/monitor.env`（root:root，0600） |
| systemd unit | `monitor.service` |
| 监听地址 | `127.0.0.1:8087` |
| 面板域名 | `panel.example.com` |
| 失败页域名 | `blocked.example.com` |
| 失败页目录 | `/var/www/blocked.example.com` |
| nginx 配置 | `/etc/nginx/sites-enabled/{panel,blocked}.example.com.conf` |

服务与主站、邮件面板、日志服务相互独立：独立用户、目录、端口、unit、vhost 和证书。
面板进程不以 root 运行，也不需要 shell。

---

## 环境要求

### 必需

- Linux（使用 systemd、journald、nftables）
- Node.js **>= 18**（只用标准库，无 npm 依赖）
- nginx（反向代理、TLS、失败页）
- nftables（`nft` 命令）
- Python 3（仅部署脚本和 nginx root helper 使用）
- `journalctl` 可读取 `ssh.service` 或 `ssh` unit
- 安装阶段需要 root 或可 `sudo` 的账号

### 可选

- certbot（自动申请 Let's Encrypt 证书）
- 兼容的本地邮件面板 API（Unix socket；不配置则不发邮件，其它功能正常）
- Cloudflare 代理（用于真实 IP 还原；不是必需）

### 部署脚本额外依赖

`deploy/deploy.sh` 通过 SSH 密码登录目标机，因此本机需要：

- `bash`
- `ssh` / `scp`
- `sshpass`
- `openssl`

如果不想使用密码登录，可以手动执行脚本中的步骤，或把 `rsh` / `put` 改成基于
SSH key 的实现。

---

## 本地运行

本地运行只需要 Node.js。建议用临时数据目录，避免写入 `/var/lib/monitor`：

```bash
MONITOR_PASSWORD='local-test-password' \
MONITOR_SECRET="$(openssl rand -hex 32)" \
DATA_DIR=/tmp/server-panel-data \
HOST=127.0.0.1 PORT=8087 \
node server.js
```

然后访问 <http://127.0.0.1:8087/>。

说明：

- 没有 nginx 时，面板只在本机 HTTP 上可用；正式环境必须走 HTTPS
- 非 root 用户无法读取 journal、无法操作 nftables，SSH 监控和封锁会报错或降级
- 未配置邮件 socket 时，告警发送失败，但采样、记录和页面仍可工作
- 数据目录必须可写，默认 `0750`

运行测试不需要服务器、不需要网络：

```bash
npm test
# 或
node test/monitor.test.js
```

---

## 生产部署

### 1. 准备 DNS 与证书

至少准备两个域名（也可以只用一个，失败页功能会不可用）：

- `panel.example.com` → 服务器 IP
- `blocked.example.com` → 服务器 IP

80 端口必须能被 ACME 访问。使用 CDN/Cloudflare 时，首次签发证书可临时关闭代理，
或改用 DNS-01。

### 2. 准备服务器

目标机需要：

```bash
node -v          # >= 18
nginx -v
nft --version
python3 --version
journalctl --version
command -v certbot
```

并确保 SSH 日志由 journald 管理。Debian/Ubuntu 通常是 `ssh.service`；如果 unit 名
不同，需要调整程序中的 journal 读取参数。

### 3. 运行部署脚本

在仓库根目录：

```bash
HOST=203.0.113.10 \
SSH_USER=root \
MONITOR_HOST=panel.example.com \
FAILED_HOST=blocked.example.com \
MAIN_HOST=example.com \
PASS='<root 密码>' \
bash deploy/deploy.sh
```

脚本会：

1. 检查 Node / nginx / certbot / journalctl / 端口占用
2. 创建 `monsvc` 用户和目录
3. 生成并安装 `/etc/monitor/monitor.env`（0600）
4. 上传程序并以 root:root 0755/0644 安装
5. 安装并启动 `monitor.service`
6. 安装 nginx root helper 和唯一一条 sudoers 规则
7. 检查面板域名解析
8. 安装 nginx vhost，申请证书
9. 安装失败页 vhost
10. 冒烟测试、`certbot renew --dry-run`、封锁 API 端到端验证

脚本是幂等的，可以重复执行。强制重新生成面板密码：

```bash
FORCE_ENV=1 PASS='...' bash deploy/deploy.sh
```

部署脚本会在本地生成 `deploy/monitor.env.local`（0600），其中包含面板密码和
HMAC secret。该文件已被 `.gitignore` 排除，**不要提交**。

### 4. 部署后检查

```bash
systemctl status monitor
journalctl -u monitor -n 50 --no-pager
curl -fsS http://127.0.0.1:8087/health

# 确认运行用户、能力与 sandbox
systemctl show monitor -p User -p Group -p AmbientCapabilities -p NoNewPrivileges

# 确认服务能读 journal
sudo -u monsvc journalctl -u ssh -n 1 --no-pager -o cat

# 确认 nftables 可用（未创建表时应返回非零，但不是权限错误）
sudo -u monsvc nft list tables
```

---

## 配置项

`monitor.service` 通过 `Environment=` 和 `EnvironmentFile=/etc/monitor/monitor.env`
传入配置。

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | HTTP 监听地址，不要改成 `0.0.0.0` |
| `PORT` | `8087` | HTTP 监听端口 |
| `DATA_DIR` | `/var/lib/monitor` | 运行数据目录 |
| `PUBLIC_URL` | `https://panel.example.com/` | 邮件里的面板链接 |
| `ALERT_TO` | `admin@example.com` | 告警收件人 |
| `SERVER_NAME` | 系统 hostname | 邮件中的服务器名 |
| `PROTECTED_IPS` | `203.0.113.11`（示例，建议替换） | 永不封锁的 IP，逗号分隔 |
| `SAMPLE_INTERVAL_MS` | `60000` | 资源采样间隔 |
| `SSH_POLL_MS` | `20000` | journal / 自动封锁巡检间隔 |
| `MAIL_API_SOCKET` | `/run/mail-panel/api.sock` | 本地邮件 API socket |
| `MONITOR_PASSWORD` | 无 | 面板登录密码，必填 |
| `MONITOR_SECRET` | 无 | cookie 签名 secret，必填 |
| `MAIL_API_KEY_ID` | 空 | 邮件 API key id（可选） |
| `MAIL_API_SECRET` | 空 | 邮件 API secret（可选） |
| `NGINX_TF_HELPER` | `/usr/local/libexec/monitor-nginx-tf` | root helper 路径 |
| `PROC_STAT` / `PROC_MEMINFO` / `PROC_NET_DEV` | 标准 `/proc` 路径 | 仅测试或特殊环境覆盖 |

`/etc/monitor/monitor.env` 示例见 [`deploy/monitor.env.example`](deploy/monitor.env.example)。

> `PROTECTED_IPS` 建议填写管理员固定出口 IP。即使不填，成功登录过的 IP 和当前
> 活跃会话也会被保护；但固定 IP 是额外的双保险。

---

## 权限要求

这是本项目最重要的部署前提。完整细节、验证命令和故障排查见
[`docs/PERMISSIONS.md`](docs/PERMISSIONS.md)。

### 总原则

- 服务进程以专用非特权用户 `monsvc` 运行
- 只授予完成工作所必需的最小权限
- 唯一允许的提权路径是一条固定 root helper 的 sudoers 白名单
- 安装时用 root，运行时不使用 root

### 用户与组

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin monsvc
usermod -a -G systemd-journal monsvc   # 读取 journalctl -u ssh
usermod -a -G www-data monsvc          # 访问邮件面板 Unix socket（可选）
```

| 用户/组 | 用途 |
| --- | --- |
| `monsvc` | 运行 Node 进程 |
| `systemd-journal` | 允许读取 systemd journal；否则看不到 SSH 日志 |
| `www-data` | 允许连接 `/run/mail-panel/api.sock`；不配置邮件时可不加 |

### Linux capabilities

`monitor.service` 使用：

```ini
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_PTRACE
```

- `CAP_NET_ADMIN` 是环境能力（ambient），让 `nft` 管理 `monitor_block`、
  `ssh_geoip`、`traffic_filter` 三张表
- `CAP_NET_BIND_SERVICE` 在 bounding set 内，供辅助的 `nginx -t` 检查 80/443
- 其余 bounding set 能力不是 ambient，`monsvc` 本身不能直接使用
- 不授予 `CAP_SYS_ADMIN`、`CAP_SYS_MODULE`

### systemd 沙箱

关键配置：

```ini
User=monsvc
Group=monsvc
SupplementaryGroups=systemd-journal www-data
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=yes
ProtectHome=true
ProtectControlGroups=true
StateDirectory=monitor
StateDirectoryMode=0750
ReadWritePaths=/var/lib/monitor
```

为什么 `NoNewPrivileges=false`：流量过滤需要 `monsvc` 通过 sudo 执行唯一的 root
helper。sudo 在检测到 `PR_SET_NO_NEW_PRIVS` 时会拒绝提权，即使有 NOPASSWD 规则。
因此以下选项**不能启用**（它们会隐式设置 no-new-privileges）：

- `ProtectKernelTunables`
- `ProtectKernelModules`
- `RestrictAddressFamilies`
- `LockPersonality`

`ProtectSystem=yes` 而不是 `strict`，是为了让 root helper 能写 `/etc/nginx`；
`monsvc` 自身仍然没有 `/etc/nginx` 的写权限。

### sudoers

只允许一条命令：

```sudoers
monsvc ALL=(root) NOPASSWD: /usr/local/libexec/monitor-nginx-tf
```

文件 `/etc/sudoers.d/monitor-nginx-tf` 必须：

```bash
chown root:root /etc/sudoers.d/monitor-nginx-tf
chmod 0440 /etc/sudoers.d/monitor-nginx-tf
visudo -cf /etc/sudoers.d/monitor-nginx-tf
```

禁止使用 `NOPASSWD: ALL`、`monsvc ALL=(ALL) ...` 或让 helper 接受任意路径参数。

### root helper 的边界

`/usr/local/libexec/monitor-nginx-tf`：

- 只接受固定输入：`/var/lib/monitor/nginx/` 下的 `mode`、map 文件、`index.html`
- map 每行必须是 `<cidr> 1;`，用 Python `ipaddress` 解析
- 拒绝 `/0`、超大文件、过多行、非法 UTF-8、NUL、符号链接
- 其余 nginx 配置全部由脚本内固定模板生成，不拼接用户输入
- 先写临时目录，再 `nginx -t`；失败自动回滚
- 使用 `flock` 防止并发

因此即使面板进程被攻破，攻击者也只能影响过滤规则和失败页内容，不能写入任意
nginx 指令，也不能执行任意 root 命令。

### 文件权限

| 路径 | 所有者 | 模式 | 说明 |
| --- | --- | --- | --- |
| `/opt/monitor` | root:root | 0755 | 程序目录 |
| `/opt/monitor/*` | root:root | 0644/0755 | 服务只读 |
| `/etc/monitor` | root:root | 0755 | 配置目录 |
| `/etc/monitor/monitor.env` | root:root | 0600 | 密码、secret、邮件 key |
| `/var/lib/monitor` | monsvc:monsvc | 0750 | 运行数据 |
| `/var/lib/monitor/nginx` | monsvc:monsvc | 0750 | helper 的暂存目录 |
| `/var/lib/monitor/nginx/*` | monsvc:monsvc | 0640 | map / mode / HTML |
| `/var/www/blocked.example.com` | root:root | 0755 | 静态失败页目录 |
| `/var/www/blocked.example.com/index.html` | root:root | 0644 | 由 helper 安装 |
| `/usr/local/libexec/monitor-nginx-tf` | root:root | 0755 | root helper |
| `/etc/sudoers.d/monitor-nginx-tf` | root:root | 0440 | 单条 sudo 规则 |
| `/etc/systemd/system/monitor.service` | root:root | 0644 | systemd unit |

### 端口

| 端口 | 绑定 | 用途 |
| --- | --- | --- |
| `8087/tcp` | `127.0.0.1` | Node 面板，仅本机 |
| `80/tcp` | nginx | ACME / HTTP 跳转 |
| `443/tcp` | nginx | 面板与失败页 HTTPS |
| `22/tcp` | sshd | 被监控/封锁/白名单作用的目标端口 |

面板不应直接暴露 `8087`。云安全组/防火墙只应放行 22、80、443。

---

## 安全模型

### 面板鉴权

- 密码登录，成功后签发 HMAC 签名的 `mon_session` cookie（默认 12 小时）
- 所有写操作要求 CSRF token
- cookie 默认 `HttpOnly`、`SameSite=Lax`；生产环境应通过 HTTPS 访问
- 密码和 secret 只存在 `/etc/monitor/monitor.env`（0600）
- 没有密码无法读取任何监控数据

### 防自锁设计

封锁和地区白名单都可能把管理员关在门外，因此有多层保护：

1. `PROTECTED_IPS` 硬白名单
2. 成功登录过的 IP 永久保护
3. 当前活跃 SSH 会话保护
4. 服务器自身地址保护
5. 内网 / 回环 / CGNAT / 保留地址拒绝封锁
6. 没有失败记录的 IP 不允许封锁
7. 地区白名单把上述地址并入 allow 集合
8. zone 文件条数下限校验，空集合拒绝建表
9. 拉取失败时保留旧表；首次失败则不建表，SSH 保持放行

### 失败关闭

- 读取 `ps` 或 journal 失败时，宁可认为“有人登录”，也不误判为无人登录
- `nginx -t` 或 reload 失败时恢复上一份配置
- 国家 zone 拉取失败时不替换现有规则

### 威胁边界

本项目假设：

- 服务器本身和 root 账号可信
- 面板密码、secret、邮件 API key 不泄露
- nginx、systemd、内核、Node.js 及时更新

它不能防御：

- 已经拿到 root 的攻击者
- 内核或 nginx 0day
- 物理/控制台层面的攻击
- 邮件服务本身被攻破

发现安全问题请阅读 [`SECURITY.md`](SECURITY.md)，不要在公开 issue 中贴出密码、
密钥、真实 IP 或完整日志。

---

## 数据与持久化

所有运行数据在 `/var/lib/monitor`：

| 文件 | 内容 |
| --- | --- |
| `config.json` | 开关、阈值、自动封锁参数、国家白名单 |
| `state.json` | 资源规则计数、冷却时间 |
| `known-ips.json` | 成功登录过的 IP |
| `ssh-failures.json` | 当前窗口内的失败时间戳 |
| `fail-history.json` | 每个 IP 的永久失败记录 |
| `blocked.json` | 封锁列表、来源、封锁后尝试次数 |
| `traffic-filter.json` | 流量过滤开关、模式、失败页 HTML、规则 |
| `alerts.jsonl` | 告警历史 |
| `geo-cache.json` | GeoIP 缓存 |
| `journal.cursor` | SSH journal 游标 |
| `kernel.cursor` | 内核日志游标 |
| `geoip/` | ipdeny zone 缓存 |
| `cloudflare-ranges.json` | Cloudflare 网段缓存 |
| `nginx/` | root helper 的暂存文件 |

备份时至少保留 `config.json`、`known-ips.json`、`fail-history.json`、
`blocked.json`、`traffic-filter.json`。

---

## 运维与排查

```bash
# 服务状态
systemctl status monitor
journalctl -u monitor -n 100 --no-pager

# 健康检查
curl -fsS http://127.0.0.1:8087/health

# 重新加载 unit
systemctl daemon-reload && systemctl restart monitor

# nftables 表
nft list table inet monitor_block
nft list table inet ssh_geoip
nft list table inet traffic_filter

# 手工验证 22 端口
nc -zv 203.0.113.10 22
```

常见问题：

| 现象 | 排查 |
| --- | --- |
| 面板 502 | `systemctl status monitor`；确认监听 `127.0.0.1:8087` |
| 收不到邮件 | 检查邮件 socket 权限、`MAIL_API_*`、面板告警历史 |
| SSH 监控无数据 | `sudo -u monsvc journalctl -u ssh -n 1` 是否可读 |
| 封锁按钮报权限错误 | 检查 `AmbientCapabilities=CAP_NET_ADMIN` 和 `nft` |
| 流量过滤保存失败 | 检查 sudoers、helper 权限、`NoNewPrivileges=0` |
| 证书申请失败 | 检查 DNS、80 端口、CDN 代理设置 |
| 白名单开启后仍能连 | 确认表已创建；失败时设计为保持全部放行 |

---

## 测试

```bash
npm test
```

测试完全离线，覆盖资源解析、规则判定、SSH 日志解析、封锁保护、自动封锁、
国家白名单、流量过滤、存储和邮件模板。

部署前建议额外执行：

```bash
bash -n deploy/*.sh
python3 -m py_compile deploy/*.py
node --check server.js
for f in lib/*.js test/*.js; do node --check "$f"; done
```

---

## 已知限制

- 只监控名为 `ssh` 的 systemd unit；使用 `ssh.socket` 或自定义 unit 时需调整
- GeoIP 依赖 `ipwho.is` 和 `api.country.is`；都失败时邮件显示“未知”
- 邮件告警依赖兼容的本地邮件面板 API；不配置时只有页面和记录可用
- 自动封锁默认关闭，且阈值较高（100 次 / 24 小时）
- 封锁和国家白名单只作用于目标 TCP 22
- nftables 规则在服务启动时重建；服务启动前没有这些规则
- 国家 zone 数据来自 ipdeny.com，可能滞后；失败方向是“放行”而不是“全部拒绝”
- 内核日志有速率限制，极端流量下日志计数可能小于 nft 计数器

---

## 许可证

本项目使用 **GNU Affero General Public License v3.0 only**（AGPL-3.0-only）。
完整文本见 [`LICENSE`](LICENSE)。

AGPL 的要求高于 MIT/Apache：如果你修改本项目并通过网络向用户提供服务，必须
向这些用户提供对应的完整源代码。部署前请确认你的使用方式符合许可证。
