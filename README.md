# debian-setup
提升 Debian 系原版系统使用便捷性一键设置

脚本支持 Debian 10-13 和 Ubuntu 20.04, 22.04, 24.04

# 一键自动配置
- 主机名配置
- 时区、BBR 配置
- Swap 配置
- DNS 配置
- 常用软件包安装
- vim 编辑器优化配置
- 系统更新和清理

# 一键脚本
```
apt install curl -y
```

```
bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/debian-setup/main/install.sh)
```


推荐配合 bin456789 DD 脚本食用

https://github.com/bin456789/reinstall

一键 DD 脚本
```
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh debian 13 --ssh-port 12345 --password woshimima && reboot
```

DD脚本的系统版本、 ssh 端口和 password 请自行修改
