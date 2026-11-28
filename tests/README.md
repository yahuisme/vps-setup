# 维护测试

禁止直接执行或 source `install.sh`（包括 `--help`）；测试只把审读过的函数提取到普通 fixture 文件。系统配置绝对路径按 token 边界重定位至私有 `$TMPDIR`，软件包、服务、内核参数、Swap、密码和文件属性操作均用 mock。真实 `sshd -t/-T -f` 与 `fail2ban-client -c <fixture> -t/-d` 只解析私有配置，不启动服务或执行防火墙/通知 action。

依赖：Bash、Python 3、ShellCheck，以及系统已有的 `openssh-server`、`fail2ban` 配置解析器。不要为运行测试在业务 VPS 上安装或重启服务。

在仓库目录执行，使用共享测试工具限制整轮测试内存并禁止 Swap：

```bash
/opt/test-tools/bin/run-bounded-test /opt/test-tools/run-in-repo "$PWD" \
  /bin/bash -ec 'for file in install.sh tests/bbr-transaction.sh; do bash -n "$file"; done; shellcheck -S warning install.sh tests/bbr-transaction.sh; python3 tests/regression.py; python3 tests/test_transactions.py; bash tests/bbr-transaction.sh'
```

也可使用 `hermes-vps-audit.slice`；须确认所有测试位于同一个有上限的 slice（≤4 GiB、Swap=0），并将私有 `TMPDIR` 显式传给 transient service。测试最多两个任务并行。

- `regression.py`：CLI/主流程/前置校验、主机名与 hosts、时区/时间同步/软件包、BBR 键匹配、Swap、DNS、真实 SSH/Fail2ban 解析及故障回滚；可追加 `Regression.test_name` 只跑受影响测试。
- `test_transactions.py`：真实 INT/TERM、操作完成后返回失败、Swap 优先级/discard 与部分失败恢复；可追加 `Transactions.test_name`。可选 `TRANSACTION_EVIDENCE` 保留该次私有 fixture 及 stdout/stderr/status，目录不可跨测试身份复用。
- `bbr-transaction.sh`：精确键接管、所有 procps 配置目录、symlink 去重、字节保留、重复执行及各阶段故障恢复。
- `fail2ban-runtime.py`：只读模拟运行期查询，答案来自真实合并配置 dump，不连接 daemon。

这些结果不等于在真实 VPS 上完成初始化，也不证明重启、DHCP 更新、真实防火墙封禁或断电恢复。已匹配源码/依赖身份的通过证据可复用；只补跑变更影响、失败或缺失的检查。
