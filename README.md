# vps-setup

Debian / Ubuntu VPS 初始化脚本。版本：`v26.10.07`。

支持 Debian 10–13、Ubuntu LTS 20.04 / 22.04 / 24.04 / 26.04，不支持容器。

## 使用

```bash
apt-get update -y && apt-get install -y curl
curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh
bash install.sh
```

非交互执行仍运行全部默认项目：

```bash
bash install.sh --non-interactive --hostname my-vps --timezone Asia/Hong_Kong --swap 1024
```

完整参数：`bash install.sh --help`。

## 默认配置

- 安装基础工具并配置时间同步；保留主机名、时区及 SSH 设置，不修改密码登录开关，不自动升级、清理或重启。
- BBR：启用 `fq + bbr`，备份原配置；`--no-bbr` 切换 cubic，保留 qdisc。
- Swap：内存 ≤512 MiB 配 512 MiB，≤1024 MiB 配 1024 MiB，其余 2048 MiB。容量一致保留，否则停用全部现有 Swap 并替换为 `/swapfile`；`--swap 0` 禁用全部 Swap。
- DNS：Cloudflare 在前、Google 在后。IPv4 `1.1.1.1 / 8.8.8.8`；检测到 IPv6 时配置 `2606:4700:4700::1111 / 2001:4860:4860::8888`。优先使用 systemd-resolved；其他管理器接管、符号链接或生成文件跳过直接修改，普通文件保留 search/options。
- Fail2ban：仅保护 SSH，5 分钟内失败 3 次永久封禁，不改其他 jail 或 ignoreip；`--no-fail2ban` 跳过配置，不停止已有服务。

## 注意

- 修改 SSH 端口前放行防火墙和安全组，保留原连接另开连接验证；密码建议交互输入。
- BBR、Swap、resolved DNS、SSH 和 Fail2ban 失败会尝试局部回滚；不是整轮初始化事务，已完成步骤不会自动撤销。恢复不完整时保留备份并报告路径，请勿并发运行。
- 日志：`/var/log/vps-init-日期时间.log`。
