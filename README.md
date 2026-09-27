# vps-setup

Debian / Ubuntu VPS 初始化脚本。版本：`v26.09.27`。

支持 Debian 10–13、Ubuntu LTS 20.04 / 22.04 / 24.04 / 26.04，不支持容器。

## 使用

```bash
apt-get update -y && apt-get install -y curl
curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh
bash install.sh
```

非交互执行仍会运行全部默认项目：

```bash
bash install.sh --non-interactive --hostname my-vps --timezone Asia/Hong_Kong --swap 1024
```

完整参数见 `bash install.sh --help`。

## 默认行为

- 安装基础工具，配置时间同步、BBR、Swap、DNS 和 Fail2ban；不自动升级、清理或重启。
- 主机名、时区及 SSH 默认保留；交互模式可设置主机名、SSH 端口和 root 密码，不修改密码登录开关。保留已有活动 NTP 服务，否则尝试启用 systemd-timesyncd。
- BBR 使用 `fq + bbr`，备份并接管同名参数，其他设置不动；`--no-bbr` 切换 cubic，保留 qdisc。原配置备份为 `/etc/sysctl.d/99-bbr.conf.backup.*`。
- Swap auto：内存 ≤512 MiB 配 512 MiB，≤1024 MiB 配 1024 MiB，其余 2048 MiB。容量不符时停用全部现有 Swap，替换为 `/swapfile`；`--swap 0` 禁用全部 Swap。已有 `/swapfile` 必须是可识别 Swap 签名的普通文件，否则拒绝修改；等容量保留，并校验/补齐其 fstab 启动条目，冲突或 noauto 则拒绝。
- DNS：IPv4 `1.1.1.1 / 8.8.8.8`；检测到 IPv6 时使用 `2606:4700:4700::1111 / 2001:4860:4860::8888`。优先配置 systemd-resolved；其他活动管理器（NetworkManager、connman、resolvconf、dhcpcd）、符号链接或带生成标记的文件跳过直接修改。普通文件仅替换 nameserver，保留 search/options 等内容。
- Fail2ban 仅设置 `[sshd]`：5 分钟失败 3 次永久封禁，不改其他 jail 或全局 ignoreip。端口来自 SSH 有效 ListenAddress；启动后检查 jail、重试/封禁时间、journal 与 action 端口，后续配置覆盖导致策略未生效则失败并尝试恢复。`--no-fail2ban` 仅跳过配置，不停止已有服务。

## 提示

修改 SSH 端口前先放行防火墙和安全组，保留原连接另开连接验证。有效 Port / ListenAddress 有旧端口或仅本地绑定时拒绝变更；本机监听检查不等于防火墙、云安全组或远程连通性验证。密码建议交互输入，避免留在命令历史中。

BBR、Swap、resolved DNS、SSH 和 Fail2ban 各步应用失败会尝试局部回滚；直接 DNS 文件写入前备份、临时文件生成后替换。这不是整轮初始化事务：已完成步骤、包安装、主机名、时区和密码不会随后续失败自动撤销。恢复不完整时保留备份并报告路径。请勿并发运行。

日志：`/var/log/vps-init-日期时间.log`。
