# vps-setup

版本：`v26.11.22`

一键初始化 Debian / Ubuntu VPS：安装基础工具，配置时间同步、BBR、Swap、DNS 和 SSH 防护。

## 使用

以 **root** 运行。支持 Debian 10–13、Ubuntu LTS 20.04 / 22.04 / 24.04 / 26.04，不支持容器。

```bash
apt-get update && apt-get install -y curl
curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh && bash install.sh
```

按提示操作；主机名和 SSH 设置可留空保留。默认不修改密码登录开关，不升级系统、不清理、不重启。

## 默认配置

- **BBR**：启用 `fq + bbr`；`--no-bbr` 改用 cubic，保留 qdisc。
- **Swap**：内存 ≤512 MiB 配 512 MiB，≤1024 MiB 配 1024 MiB，其余配 2048 MiB。现有总量一致则保留，否则停用全部现有 Swap 并替换为 `/swapfile`；`--swap 0` 禁用全部 Swap。
- **DNS**：IPv4 使用 `1.1.1.1 / 8.8.8.8`；检测到 IPv6 时增加 `2606:4700:4700::1111 / 2001:4860:4860::8888`。替换并锁定 `/etc/resolv.conf`，保留 search/options，停用 systemd-resolved。
- **Fail2ban**：按实际 SSH 监听端口配置（含 systemd socket），5 分钟内失败 3 次永久封禁；不改其他 jail 或 ignoreip。无法确认端口时不修改。`--no-fail2ban` 跳过配置，不停止已有服务。

自定义示例，需先完成上方下载；非交互模式仍执行全部默认项目：

```bash
bash install.sh --non-interactive --hostname my-vps --timezone Asia/Hong_Kong --swap 1024
```

更多参数：`bash install.sh --help`，支持自定义 DNS、SSH 端口等。

## 注意

- 修改 SSH 端口前先放行防火墙和安全组，保留原连接并另开连接验证；活动的 SSH socket 由管理员配置端口，脚本会拒绝改动。密码须为单行，建议交互输入。
- DNS 接管会阻止 DHCP/VPN 自动更新，可能影响云内网域名解析。原配置保存在 `/etc/resolv.conf.backup.*`；手动修改前执行 `chattr -i /etc/resolv.conf`。不支持文件锁定时会失败；系统解析库通常最多使用前三个 nameserver。
- BBR、Swap、DNS、SSH 和 Fail2ban 失败时尝试局部回滚，不会撤销整轮已完成步骤；配置事务捕获 INT/TERM 后也尝试恢复，不保证强杀或断电恢复。恢复不完整时按提示保留备份处理。请勿并发运行。
- 日志：`/var/log/vps-init-日期时间.log`。
