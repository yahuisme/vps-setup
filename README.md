# vps-setup
便捷高效的全新 VPS 开箱一键优化设置脚本。脚本面向 Debian 10–13、Ubuntu 20.04/22.04/24.04 的全新系统；其它系统请自行测试。脚本会安装软件、修改系统配置并执行系统升级，不建议直接用于已有业务的生产 VPS。

## 功能特点

- 常用软件包自动安装
- 主机名、时区和 DNS 配置
- 时间同步和 BBR 配置
- Swap 自动配置
- SSH 端口和密码配置
- Fail2ban 自动配置
- Vim 编辑器优化
- 系统更新和清理

## 一键脚本

```bash
apt-get update -y && apt-get install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh)
```

脚本会依次执行软件包安装、主机名、时区、时间同步、BBR、Swap、DNS、SSH、Fail2ban、Vim 配置，以及系统更新和清理。

## 无交互安装

以下示例需要按实际情况修改参数。`--ip-dns` 和 `--ip6-dns` 的两个地址使用空格分隔。`--ssh-password` 仅适合全新 VPS 的临时初始化，建议登录验证后立即改用密钥并关闭密码登录。

```bash
apt-get update -y && apt-get install -y curl && curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh && chmod +x install.sh && ./install.sh --hostname "hostname" --timezone "Asia/Hong_Kong" --swap 1024 --bbr-optimized --ip-dns "94.140.14.14 1.1.1.1" --ip6-dns "2a10:50c0::ad1:ff 2606:4700:4700::1111" --ssh-port 12345 --ssh-password 'CHANGE_ME_TO_A_TEMPORARY_STRONG_PASSWORD' --fail2ban 12345 --non-interactive
```

`--ssh-password` 会将密码放在命令行参数中，可能出现在 shell 历史或进程信息中。请使用临时强密码，并在初始化后更换。

## 参数

```text
--hostname <name>       设置主机名
--timezone <tz>         设置时区
--swap <auto|MB|0>      设置 Swap 大小；0 表示禁用
--ip-dns "主DNS 备用DNS" 设置 IPv4 DNS
--ip6-dns "主DNS 备用DNS" 设置 IPv6 DNS
--bbr                   启用默认 BBR
--bbr-optimized         启用优化 BBR
--no-bbr                禁用 BBR
--fail2ban [port]       启用 Fail2ban，可附加端口
--no-fail2ban           禁用 Fail2ban
--ssh-port <port>       设置 SSH 端口
--ssh-password <pass>   设置 root 密码
--non-interactive       非交互模式
-h, --help              显示帮助
```

## 重装系统

需要重装系统时，可使用：

<https://github.com/bin456789/reinstall>

```bash
curl -O https://github.com/bin456789/reinstall/raw/main/reinstall.sh && bash reinstall.sh debian 13 --ssh-port 12345 --password 'CHANGE_ME_TO_A_TEMPORARY_STRONG_PASSWORD' && reboot
```

请自行修改系统版本、SSH 端口和密码；重装会清除原系统数据。

## 注意事项

- Fail2ban 默认永久封禁 SSH 认证失败来源（`bantime = -1`），管理 IP 误封后需手动解封；脚本配置写入独立的 `jail.d/99-vps-setup.local`，不会覆盖其它 Jail：
  ```bash
  sudo fail2ban-client set sshd unbanip <IP>
  ```
- 修改 SSH 端口前，请先在云平台安全组和服务器防火墙中放行新端口。脚本无法验证云安全组，只能检查 SSH 是否监听新端口；请保持当前连接，并先用新端口验证登录成功。
- 脚本最后会执行 `apt full-upgrade`、`autoremove --purge` 和 `apt clean`。已有业务或自定义软件时，请先确认升级和清理不会产生影响。
- 修改 `/etc/resolv.conf` 前会备份；如果该文件是符号链接，脚本会停止 DNS 修改，以避免破坏系统 DNS 管理。
