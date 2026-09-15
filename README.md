# vps-setup

Debian / Ubuntu VPS 初始化脚本。版本：`v26.09.15`。

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
- 主机名、时区及 SSH 默认保留；交互模式可设置主机名、SSH 端口和 root 密码。
- BBR 使用 `fq + bbr`，备份并接管同名参数，其他设置不动；`--no-bbr` 切换 cubic，保留 qdisc。原配置备份为 `/etc/sysctl.d/99-bbr.conf.backup.*`。
- Swap：内存 <1 GiB 取内存大小，<4 GiB 为 2 GiB，其余为 4 GiB。容量不符时停用全部现有 Swap，替换为 `/swapfile`；`--swap 0` 禁用全部 Swap。
- DNS：IPv4 `1.1.1.1 / 8.8.8.8`；检测到 IPv6 时使用 `2606:4700:4700::1111 / 2001:4860:4860::8888`。已有其他 DNS 管理器时跳过直接修改。
- Fail2ban 保护 SSH，5 分钟失败 3 次永久封禁；`--no-fail2ban` 仅跳过配置，不停止已有服务。

## 提示

修改 SSH 端口前先放行防火墙和安全组，保留原连接另开连接验证。密码建议交互输入，避免留在命令历史中。

配置应用失败会尝试回滚，恢复不完整时保留备份并报告路径。请勿并发运行。

日志：`/var/log/vps-init-日期时间.log`。
