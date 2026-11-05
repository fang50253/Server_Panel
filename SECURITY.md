# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `main` / latest | ✅ |
| older tags | ❌ |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Send a private report to the maintainer:

- Email: `security@example.com`（替换为你的真实安全联系邮箱）
- 或使用 GitHub 仓库的 **Security → Report a vulnerability**

请尽量包含：

- 受影响版本 / commit
- 复现步骤
- 影响范围（能否读取数据、执行命令、绕过封锁、导致拒绝服务等）
- 相关日志（**先删除真实 IP、域名、密码、cookie、API key**）

我们会在确认后尽快回复，并在修复发布后致谢（如果你愿意）。

## 安全边界

本项目按以下前提设计：

- 服务器和 root 账号可信
- 面板通过 HTTPS 暴露，`8087` 不直接对公网开放
- `/etc/monitor/monitor.env` 仅 root 可读
- nginx、systemd、内核、Node.js 保持更新

不在威胁模型内：

- 已获得 root 的攻击者
- 内核 / nginx / Node.js 0day
- 物理接触或控制台攻击
- 邮件服务本身被攻破

## 部署安全清单

- [ ] `monitor.env` 权限 `0600`，所有者 `root:root`
- [ ] 面板密码和 `MONITOR_SECRET` 随机生成，不复用
- [ ] `HOST=127.0.0.1`，`8087` 不对公网开放
- [ ] nginx 强制 HTTPS，证书有效
- [ ] `PROTECTED_IPS` 填入管理员固定出口 IP
- [ ] 服务以 `monsvc` 运行，不以 root 运行
- [ ] sudoers 只有 helper 一条 NOPASSWD 规则
- [ ] helper 权限 `root:root 0755`，不可被 `monsvc` 修改
- [ ] 定期备份 `/var/lib/monitor` 的关键 JSON
- [ ] 定期检查 `journalctl -u monitor` 和面板告警历史
- [ ] 不要把 `deploy/monitor.env.local`、真实日志或截图提交到 Git

## 敏感信息

以下内容不应出现在 issue、PR、截图或公开日志中：

- `MONITOR_PASSWORD`
- `MONITOR_SECRET`
- `MAIL_API_KEY_ID` / `MAIL_API_SECRET`
- 真实服务器 IP、管理员 IP
- 真实域名、邮箱
- 登录 cookie、CSRF token
- 完整 journal 日志（可能包含用户名、IP、命令）

## 已知的安全设计

- 面板 cookie 使用 HMAC 签名，写操作要求 CSRF token
- 封锁和地区白名单有多层防自锁保护
- 失败关闭：读不到进程/日志时按“有人登录”处理
- root helper 只接受固定格式输入，配置由固定模板生成
- nginx 配置更新失败自动回滚
- 国家 zone 拉取失败时保留旧表，首次失败则不建表（SSH 保持放行）
