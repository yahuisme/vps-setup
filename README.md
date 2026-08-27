# vps-setup

Debian / Ubuntu VPS 初始化脚本。

**版本：v26.08.27**

支持：Debian 10–13、Ubuntu 20.04 / 22.04 / 24.04。

## 一键执行

```bash
apt-get update -y && apt-get install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh)
```

脚本默认配置：

- 常用软件包
- 主机名、时区和 DNS
- 时间同步、BBR 和 Swap
- SSH 端口和 root 密码
- Fail2ban

默认不执行系统升级和清理。

## 非交互执行

```bash
curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh
chmod +x install.sh
./install.sh \
  --hostname "hostname" \
  --timezone "Asia/Hong_Kong" \
  --swap 1024 \
  --bbr \
  --ip-dns "94.140.14.14 1.1.1.1" \
  --ip6-dns "2a10:50c0::ad1:ff 2606:4700:4700::1111" \
  --ssh-port 12345 \
  --fail2ban \
  --non-interactive
```

## 参数

```text
--hostname <name>        设置主机名
--timezone <tz>          设置时区
--swap <auto|MB|0>       设置 Swap；0 表示禁用全部 Swap
--ip-dns "主DNS 备用DNS"  设置 IPv4 DNS
--ip6-dns "主DNS 备用DNS" 设置 IPv6 DNS
--bbr                    启用 BBR
--no-bbr                 禁用 BBR
--fail2ban               启用 Fail2ban，保护 SSH
--no-fail2ban            禁用 Fail2ban
--ssh-port <port>        设置 SSH 端口
--ssh-password <pass>    设置 root 密码
--upgrade                执行系统 full-upgrade
--cleanup                执行 autoremove 和 apt clean
--non-interactive        非交互模式
-h, --help               显示帮助
```

## 注意

- 仅支持完整 VPS / 虚拟机，不支持容器环境。
- 修改 SSH 端口前，请先放行云平台安全组和防火墙端口。
- `--ssh-password` 会暴露在 shell 历史和进程参数中，仅建议临时使用。
- `--swap 0` 会关闭全部 Swap 并移除 `/etc/fstab` 中的 Swap 条目。
- `/etc/resolv.conf` 由其他 DNS 管理器维护时，脚本会跳过直接修改并给出警告。
- 日志保存到 `/var/log/vps-init-日期时间.log`。
