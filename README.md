# vps-setup

版本：`v26.11.22`

一键初始化 Debian / Ubuntu VPS：安装基础工具，配置时间同步、BBR、Swap、DNS 和 SSH 防护。

## 使用

以 **root** 在 VPS 或虚拟机中运行，不支持容器。支持 Debian 10–13、Ubuntu 20.04 / 22.04 / 24.04 / 26.04 LTS。

```bash
apt-get update && apt-get install -y curl
curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh && bash install.sh
```

按提示操作；主机名和 SSH 设置可留空保留。默认不修改密码登录开关、不执行系统升级或清理，重启需另行确认。

## 默认配置

- **BBR**：内核需支持 BBR（至少 4.9）；默认启用 `fq + bbr`。`--no-bbr` 改用 cubic，保留 qdisc。
- **Swap**：内存 ≤512 MiB 配 512 MiB，513–1024 MiB 配 1024 MiB，超过 1024 MiB 配 2048 MiB。总量一致则保留，否则以 `/swapfile` 替换全部现有 Swap（含分区）。`--swap 0` 停用全部 Swap，并移除启动条目及脚本使用的 `/swapfile`。
- **DNS**：IPv4 使用 `1.1.1.1 / 8.8.8.8`；检测到 IPv6 时增加 `2606:4700:4700::1111 / 2001:4860:4860::8888`。替换并锁定 `/etc/resolv.conf`，保留 search/options，停用 systemd-resolved。
- **Fail2ban**：按实际 SSH 监听端口配置（含 systemd socket），5 分钟内失败 3 次永久封禁；不改其他 jail 或 ignoreip。无法确认端口时不修改。`--no-fail2ban` 跳过配置，不停止已有服务。

完成上方下载后，可用以下命令跳过提问。未指定的设置仍按默认值执行：

```bash
bash install.sh --non-interactive --hostname my-vps --timezone Asia/Hong_Kong --swap 1024
```

更多参数：`bash install.sh --help`，支持自定义 DNS、SSH 端口等。

## 注意

- 修改 SSH 端口前先放行防火墙和安全组，保留原连接并另开连接验证；活动的 SSH socket 由管理员配置端口，脚本会拒绝改动。密码须为单行，建议交互输入。
- DNS 接管会阻止 DHCP/VPN 自动更新，可能影响云内网域名解析。原配置保存在 `/etc/resolv.conf.backup.*`；手动修改前执行 `chattr -i /etc/resolv.conf`。不支持文件锁定时会失败；系统解析库通常最多使用前三个 nameserver。
- BBR、Swap、DNS、SSH 和 Fail2ban 配置失败或中途收到 `INT` / `TERM` 时，脚本尝试恢复该步骤，不撤销已完成的步骤。强制结束或断电不保证恢复。恢复不完整时保留报出的备份，请勿并发运行。
- 日志：`/var/log/vps-init-YYYYMMDD-HHMMSS.log`。
