# vps-setup

Debian / Ubuntu VPS 初始化脚本。

> 适用于 Debian 10–13、Ubuntu 20.04/22.04/24.04。脚本会修改系统配置并执行系统更新，建议在全新 VPS 上使用。

## 一键执行

```bash
apt-get update -y && apt-get install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh)
```

## 常用功能

- 安装常用软件
- 设置主机名、时区和 DNS
- 配置时间同步、BBR 和 Swap
- 修改 SSH 端口和 root 密码
- 安装 Fail2ban
- 更新和清理系统

## 非交互模式

按需修改参数后执行：

```bash
curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh && chmod +x install.sh
./install.sh --hostname "hostname" --timezone "Asia/Hong_Kong" --swap 1024 --bbr-optimized --ip-dns "94.140.14.14 1.1.1.1" --ip6-dns "2a10:50c0::ad1:ff 2606:4700:4700::1111" --ssh-port 12345 --ssh-password 'CHANGE_ME_TO_A_TEMPORARY_STRONG_PASSWORD' --fail2ban 12345 --non-interactive
```

## 参数

```text
--hostname <name>        设置主机名
--timezone <tz>          设置时区
--swap <auto|MB|0>       设置 Swap；0 表示禁用
--ip-dns "主DNS 备用DNS"  设置 IPv4 DNS
--ip6-dns "主DNS 备用DNS" 设置 IPv6 DNS
--bbr                    启用默认 BBR
--bbr-optimized          启用优化 BBR
--no-bbr                 禁用 BBR
--fail2ban [port]        启用 Fail2ban，可附加端口
--no-fail2ban            禁用 Fail2ban
--ssh-port <port>        设置 SSH 端口
--ssh-password <pass>    设置 root 密码
--non-interactive        非交互模式
-h, --help               显示帮助
```

## 注意

- 修改 SSH 端口前，先在云平台安全组和防火墙放行新端口。
- `--ssh-password` 会出现在 shell 历史或进程信息中，只建议临时使用。
- `--swap 0` 会关闭全部 Swap，并移除 `/etc/fstab` 中的 Swap 条目。
- Fail2ban 默认永久封禁 SSH 认证失败来源，误封可执行：

  ```bash
  sudo fail2ban-client set sshd unbanip <IP>
  ```
