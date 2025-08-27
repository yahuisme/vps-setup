# debian-setup
提升 Debian 系原版系统使用便捷性一键设置

脚本支持 Debian 10-13 和 Ubuntu 20.04, 22.04, 24.04

# 一键自动配置
- 常用软件包安装
- 主机名配置
- 时区配置
- BBR + TCP 优化配置
- Swap 配置
- DNS 配置
- Fail2ban 配置
- vim 编辑器优化配置
- 系统更新和清理

# 一键脚本
```
apt install curl -y && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/debian-setup/main/install.sh)
```
运行一键脚本后依次配置：
1. 自动检查并安装 sudo wget zip vim curl 常用应用
2. 询问是否设置主机名
3. 自动检测并设置 VPS 所在时区
4. 默认开启 BBR
5. 自动配置 Swap
6. 自动配置 DNS（ipv4 1.1.1.1 8.8.8.8 ; ipv6 2606:4700:4700::1111 2001:4860:4860::8888）
7. 自动安装并配置 Fail2ban，默认防护 22 端口
8. 自动优化 vim 编辑器配置
9. 系统更新及清理

# 无交互自定义脚本
```
apt install curl -y && curl -o install.sh -fsSL https://raw.githubusercontent.com/yahuisme/debian-setup/main/install.sh && chmod +x install.sh && ./install.sh --hostname "hostname" --timezone "Asia/Hong_Kong" --swap "1024" --bbr-optimized --ip-dns "94.140.14.14 1.1.1.1" --ip6-dns "2a10:50c0::ad1:ff 2606:4700:4700::1111" --fail2ban 12345 --non-interactive
```
运行无交互自定义脚本后依次配置：
1. 自动检查并安装 sudo wget zip vim curl 常用应用
2. 自动配置自定义主机名
3. 自动配置自定义时区
4. 自动配置自定义 Swap
5. 默认开启 BBR 并根据 VPS 配置智能优化 TCP 网络参数
6. 自动配置自定义 DNS
7. 自动安装并配置 Fail2ban，防护 22 端口和自定义端口
8. 自动优化 vim 编辑器配置
9. 系统更新及清理

# 配合 bin456789 一键 DD 脚本

https://github.com/bin456789/reinstall


一键 DD 脚本
```
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh debian 13 --ssh-port 12345 --password woshimima && reboot
```

DD脚本的系统版本、 ssh 端口和 password 请自行修改
