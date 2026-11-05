# 权限要求与最小权限说明

本文说明 Server Panel 在生产环境运行所需的全部权限、为什么需要它们，以及如何
验证配置没有超出必要范围。

> 目标：服务进程不是 root；只拿到完成监控、封锁和 nginx 规则更新所需的最小权限；
> 唯一提权路径是一条固定 root helper 的 sudoers 白名单。

---

## 1. 权限清单速查

| 权限 | 授予对象 | 是否必需 | 缺失后果 |
| --- | --- | --- | --- |
| 专用系统用户 `monsvc` | systemd unit | 必需 | 不应以 root 运行 |
| 组 `systemd-journal` | `monsvc` | 必需 | 看不到 SSH 日志 |
| 组 `www-data` | `monsvc` | 可选 | 无法连接邮件面板 socket |
| `CAP_NET_ADMIN`（ambient） | `monsvc` | 封锁/过滤功能必需 | `nft` 操作失败 |
| `CAP_NET_BIND_SERVICE`（bounding） | `monsvc` | 辅助检查 | `nginx -t` 无法检查 80/443 |
| `NoNewPrivileges=false` | unit | 流量过滤必需 | sudo 拒绝提权 |
| sudoers 单条规则 | `monsvc` | 流量过滤必需 | nginx 侧规则无法更新 |
| 写 `/var/lib/monitor` | `monsvc` | 必需 | 无法保存状态 |
| 写 `/etc/nginx` | 仅 root helper | 流量过滤必需 | 无法安装 nginx 配置 |
| 写 `/var/www/blocked.example.com` | 仅 root helper | 失败页必需 | 无法更新失败页 |
| root 安装权限 | 部署人员 | 仅安装时 | 无法创建用户/目录/unit |

---

## 2. 运行用户

### 2.1 创建用户

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin monsvc
usermod -a -G systemd-journal monsvc
usermod -a -G www-data monsvc          # 只有需要邮件告警时才加
```

验证：

```bash
id monsvc
# uid=... gid=... groups=...,systemd-journal,www-data
getent group systemd-journal
getent group www-data
```

### 2.2 为什么不能用 root

- Node 进程解析网络输入、渲染 HTML、处理登录 cookie，攻击面比一个静态服务大
- 面板一旦被攻破，root 进程可以直接改系统、读所有密钥
- 以 `monsvc` 运行时，即使被攻破，攻击者也只能：
  - 读写 `/var/lib/monitor`
  - 通过 `CAP_NET_ADMIN` 修改三张 nftables 表
  - 通过唯一 sudo 规则执行固定 helper
  - 读取 journal 和 `/proc`

### 2.3 为什么不能用普通用户 + 频繁 sudo

每次 `nft` 都走 sudo 会让 sudoers 变得复杂，且日志噪声大。`CAP_NET_ADMIN`
是内核提供的、范围明确的能力，比给 `NOPASSWD: /usr/sbin/nft` 更窄：它只能改
网络管理对象，不能读文件或启动进程。

---

## 3. 组权限

### 3.1 `systemd-journal`

SSH 登录事件来自：

```bash
journalctl -u ssh
```

普通用户默认只能看自己的 journal。加入 `systemd-journal` 后可读系统 journal。

验证：

```bash
sudo -u monsvc journalctl -u ssh -n 1 --no-pager -o cat
```

如果 unit 名不是 `ssh`（例如 `sshd`），需要调整程序读取的 unit 名。

### 3.2 `www-data`

邮件通过本地 Unix socket：

```text
/run/mail-panel/api.sock    srw-rw---- www-data:www-data
```

`monsvc` 必须在 `www-data` 组里才能连接。验证：

```bash
sudo -u monsvc node -e '
  require("http").request(
    { socketPath: "/run/mail-panel/api.sock", path: "/v1/health" },
    (r) => { console.log(r.statusCode); process.exit(r.statusCode === 200 ? 0 : 1); }
  ).on("error", (e) => { console.error(e.code); process.exit(1); }).end();
'
```

不使用邮件功能时可以不加入该组；此时告警会写入失败历史，但不会影响监控和页面。

---

## 4. Linux capabilities

### 4.1 unit 中的配置

```ini
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_PTRACE
```

### 4.2 各项含义

| 能力 | 类型 | 用途 |
| --- | --- | --- |
| `CAP_NET_ADMIN` | ambient | 创建/替换 nftables 表、集合、规则 |
| `CAP_NET_BIND_SERVICE` | bounding | 辅助 `nginx -t` 检查 80/443 监听 |
| `CAP_DAC_OVERRIDE` | bounding | 供 root helper 子进程使用；不是 ambient |
| `CAP_CHOWN` | bounding | 供 root helper 安装文件时使用 |
| `CAP_SETUID` / `CAP_SETGID` | bounding | sudo 切换到 root 时由 sudo 使用 |
| `CAP_SYS_PTRACE` | bounding | 用于兼容部分 `ss`/进程检查；不是 ambient |

关键点：

- `AmbientCapabilities` 才会让**非 root 的 monsvc 进程本身**持有能力
- `CapabilityBoundingSet` 只是允许子进程获得的上限，不是直接授予
- 没有 `CAP_SYS_ADMIN`，不能挂载、改内核参数、加载模块
- 没有 `CAP_SYS_MODULE`，不能加载内核模块
- 没有 `CAP_DAC_READ_SEARCH`，不能绕过文件读权限

验证：

```bash
systemctl show monitor -p AmbientCapabilities -p CapabilityBoundingSet
pid=$(systemctl show -p MainPID --value monitor)
grep -E 'Cap(Amb|Bnd|Eff|Prm)' /proc/$pid/status
```

`CapAmb` 应包含 `cap_net_admin`；`CapBnd` 是上面那组集合。

### 4.3 如果不需要封锁/过滤

只使用资源监控和 SSH 登录审计时，可以删除：

```ini
AmbientCapabilities=CAP_NET_ADMIN
```

并删除 nginx helper / sudoers。此时：

- 资源监控、登录审计、邮件告警仍可用
- “封锁 IP”“自动封锁”“国家白名单”“流量过滤”不可用
- 不再需要 `NoNewPrivileges=false`，可以改为 `true` 并启用更多 sandbox 选项

---

## 5. systemd 沙箱

### 5.1 当前配置

```ini
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=yes
ProtectHome=true
ProtectControlGroups=true
StateDirectory=monitor
StateDirectoryMode=0750
ReadWritePaths=/var/lib/monitor
```

### 5.2 `NoNewPrivileges=false` 的原因

`monsvc` 需要执行：

```bash
sudo -n /usr/local/libexec/monitor-nginx-tf
```

sudo 在检测到 `PR_SET_NO_NEW_PRIVS` 时会拒绝提权，即使有 NOPASSWD 规则，报错类似：

```text
sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
```

因此不能启用会隐式设置该标志的选项：

- `ProtectKernelTunables=yes`
- `ProtectKernelModules=yes`
- `RestrictAddressFamilies=...`
- `LockPersonality=yes`
- `NoNewPrivileges=yes`

### 5.3 `ProtectSystem=yes` 而不是 `strict`

`strict` 会让 `/etc` 和 `/var` 在整个 unit 的 mount namespace 中只读，包括
sudo 提升后的 root helper。helper 需要写：

- `/etc/nginx/conf.d/`
- `/etc/nginx/snippets/`
- `/var/www/blocked.example.com/`

所以使用 `yes`，并通过文件权限限制 `monsvc` 自身不能写这些目录。

### 5.4 仍然生效的限制

- `ProtectHome=true`：看不到 `/home`、`/root`
- `PrivateTmp=true`：私有 `/tmp`
- `ProtectControlGroups=true`：cgroup 只读
- `ReadWritePaths=/var/lib/monitor`：明确只允许写数据目录
- `StateDirectory=monitor`：由 systemd 创建并设置 `0750`
- 没有 `CAP_SYS_ADMIN`：不能 mount、不能改内核

### 5.5 可选加固

如果不需要流量过滤的 root helper，可以追加：

```ini
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
```

每次修改后：

```bash
systemctl daemon-reload
systemctl restart monitor
systemctl show monitor -p NoNewPrivileges -p ProtectSystem
```

---

## 6. sudoers

### 6.1 唯一允许的规则

```sudoers
monsvc ALL=(root) NOPASSWD: /usr/local/libexec/monitor-nginx-tf
```

安装：

```bash
install -o root -g root -m 0440 /dev/stdin /etc/sudoers.d/monitor-nginx-tf <<'EOF'
monsvc ALL=(root) NOPASSWD: /usr/local/libexec/monitor-nginx-tf
EOF
visudo -cf /etc/sudoers.d/monitor-nginx-tf
```

### 6.2 必须避免的写法

以下任意一条都会让最小权限失效：

```sudoers
monsvc ALL=(ALL) NOPASSWD: ALL
monsvc ALL=(root) NOPASSWD: /usr/bin/nft
monsvc ALL=(root) NOPASSWD: /usr/local/libexec/monitor-nginx-tf *
```

- `NOPASSWD: ALL`：等于 root
- 直接允许 `nft`：可改任意网络规则
- 带通配符的 helper：可传任意参数，可能绕过脚本校验

### 6.3 验证

```bash
sudo -l -U monsvc
# 应只看到 /usr/local/libexec/monitor-nginx-tf

sudo -u monsvc sudo -n /usr/local/libexec/monitor-nginx-tf
echo $?    # 0
```

如果返回：

```text
sudo: The "no new privileges" flag is set
```

检查 `monitor.service` 是否误加了 `NoNewPrivileges=true` 或第 5.2 节列出的选项。

---

## 7. root helper 的安全边界

文件：`/usr/local/libexec/monitor-nginx-tf`

### 7.1 输入

只读 `/var/lib/monitor/nginx/`：

- `mode`：只能是 `drop`、`404`、`redirect`
- `cf.map`、`tf-exempt.map`、`tf-80.map`、`tf-443.map`
- `index.html`

### 7.2 校验

- 拒绝符号链接
- 限制文件大小（map 2 MiB，HTML 200 KiB）
- 限制 map 行数（80,000）
- 每行必须是 `<cidr> 1;`，CIDR 必须能被 `ipaddress` 解析
- 拒绝 `/0`
- HTML 必须是合法 UTF-8，拒绝 NUL
- 使用 `flock` 防并发

### 7.3 输出

- 只用固定模板生成 nginx 配置
- 只把校验后的 map 和 HTML 复制到目标位置
- 先 `nginx -t`，成功才 reload
- 失败时恢复上一份文件

### 7.4 权限

```bash
chown root:root /usr/local/libexec/monitor-nginx-tf
chmod 0755 /usr/local/libexec/monitor-nginx-tf
```

`monsvc` 只能执行，不能修改。

---

## 8. 文件与目录权限

```bash
# 程序
install -d -o root -g root -m 755 /opt/monitor
chown -R root:root /opt/monitor
find /opt/monitor -type d -exec chmod 755 {} +
find /opt/monitor -type f -exec chmod 644 {} +

# 配置
install -d -o root -g root -m 755 /etc/monitor
install -o root -g root -m 600 deploy/monitor.env.example /etc/monitor/monitor.env

# 数据
install -d -o monsvc -g monsvc -m 750 /var/lib/monitor
install -d -o monsvc -g monsvc -m 750 /var/lib/monitor/nginx

# helper
install -o root -g root -m 755 deploy/nginx-tf-sync.sh /usr/local/libexec/monitor-nginx-tf

# 失败页
install -d -o root -g root -m 755 /var/www/blocked.example.com
```

验证：

```bash
stat -c '%U:%G %a %n' \
  /opt/monitor /opt/monitor/server.js \
  /etc/monitor /etc/monitor/monitor.env \
  /var/lib/monitor /var/lib/monitor/nginx \
  /usr/local/libexec/monitor-nginx-tf \
  /etc/sudoers.d/monitor-nginx-tf
```

期望：

```text
root:root 755 /opt/monitor
root:root 644 /opt/monitor/server.js
root:root 755 /etc/monitor
root:root 600 /etc/monitor/monitor.env
monsvc:monsvc 750 /var/lib/monitor
monsvc:monsvc 750 /var/lib/monitor/nginx
root:root 755 /usr/local/libexec/monitor-nginx-tf
root:root 440 /etc/sudoers.d/monitor-nginx-tf
```

---

## 9. 端口与网络

| 端口 | 绑定地址 | 说明 |
| --- | --- | --- |
| 8087 | 127.0.0.1 | Node 面板 |
| 80 | 0.0.0.0 / :: | nginx ACME 与跳转 |
| 443 | 0.0.0.0 / :: | nginx HTTPS |
| 22 | 0.0.0.0 / :: | sshd |

要求：

- 不要把 `HOST` 改成 `0.0.0.0`
- 云安全组只放行 22、80、443
- 如果使用外部防火墙，允许本机访问 `127.0.0.1:8087`
- nftables 规则只匹配目标 22 端口；不要手工扩大到其它端口

---

## 10. 安装与运行权限分离

| 阶段 | 需要的权限 |
| --- | --- |
| 本地打包 | 普通用户 |
| SSH 上传 | 目标机 root 或可 sudo 用户 |
| 创建用户/目录/unit | root |
| 申请证书 | root（certbot） |
| 修改 nginx | root（部署脚本） |
| 日常运行 | `monsvc` + capabilities |
| 查看面板 | 面板密码 |
| 手工排查 | root 或 `sudo -u monsvc` |

原则：**安装用 root，运行不用 root**。

---

## 11. 验证清单

部署后逐项确认：

```bash
# 1. 进程用户
ps -o user,group,pid,cmd -p "$(systemctl show -p MainPID --value monitor)"

# 2. 不是 root
test "$(ps -o user= -p "$(systemctl show -p MainPID --value monitor)")" = monsvc

# 3. 能力
grep CapAmb /proc/"$(systemctl show -p MainPID --value monitor)"/status

# 4. no-new-privileges 为 0（仅流量过滤需要）
grep NoNewPrivs /proc/"$(systemctl show -p MainPID --value monitor)"/status

# 5. journal
sudo -u monsvc journalctl -u ssh -n 1 --no-pager -o cat

# 6. 邮件 socket（可选）
sudo -u monsvc test -r /run/mail-panel/api.sock && echo readable

# 7. sudo 白名单
sudo -l -U monsvc

# 8. helper 可执行
sudo -u monsvc sudo -n /usr/local/libexec/monitor-nginx-tf && echo helper-ok

# 9. nft
sudo -u monsvc nft list tables

# 10. 文件权限
stat -c '%U:%G %a %n' /etc/monitor/monitor.env /var/lib/monitor /usr/local/libexec/monitor-nginx-tf
```

---

## 12. 故障排查

### `nft: Operation not permitted`

- 检查 `AmbientCapabilities=CAP_NET_ADMIN`
- 检查是否被 `CapabilityBoundingSet` 排除
- 重新 `systemctl daemon-reload && systemctl restart monitor`
- 确认没有在容器里丢弃 capability

### `sudo: The "no new privileges" flag is set`

- 检查 `NoNewPrivileges=false`
- 检查是否启用了 `ProtectKernelTunables`、`ProtectKernelModules`、
  `RestrictAddressFamilies`、`LockPersonality`
- 用 `grep NoNewPrivs /proc/<pid>/status` 确认是 `0`

### `journalctl: Failed to open journal`

- `id monsvc` 是否包含 `systemd-journal`
- 修改组后必须重启服务
- 确认 journald 持久化配置没有限制访问

### 邮件发送失败 `EACCES`

- `/run/mail-panel/api.sock` 的组是否是 `www-data`
- `monsvc` 是否在 `www-data` 组
- 修改组后是否重启服务

### helper 报 `invalid mode` / `expected "<cidr> 1;"`

- 暂存文件被手工改坏
- 删除 `/var/lib/monitor/nginx/` 下对应文件，重新在面板保存
- 不要手工往暂存目录写任意内容

### `nginx -t` 失败后规则消失

这是预期行为：helper 会回滚到上一份配置，保证 nginx 可用。查看：

```bash
journalctl -u monitor -n 50 --no-pager
```

---

## 13. 进一步收紧

如果只使用资源监控和 SSH 审计：

1. 删除 `AmbientCapabilities=CAP_NET_ADMIN`
2. 删除 sudoers 规则和 helper
3. 设置 `NoNewPrivileges=true`
4. 启用第 5.5 节的 sandbox 选项
5. 从面板隐藏/禁用封锁和过滤卡片（需改前端）

如果必须保留流量过滤，至少保持：

- 单条 sudoers 规则
- helper 只接受固定目录输入
- `monsvc` 不能写 `/etc/nginx`
- `CapabilityBoundingSet` 不含 `CAP_SYS_ADMIN` / `CAP_SYS_MODULE`
