# 可选 systemd 部署

这是模板，不是自动安装脚本。它不会停止或管理现有矿工。

1. 创建专用 `prl-proxy` 用户和组，将源代码放到 `/opt/prl-stratum-proxy`。
2. 将填写好的私有配置放到 `/etc/prl-proxy/config.json`，设置只有该用户能读取的权限。
3. 将配置的 `data_dir` 设为 `/var/lib/prl-proxy`，创建目录并授予专用用户写权限。
4. 根据 Python 实际位置调整 `ExecStart`。模板默认不启用包头审计，不授予 raw socket 权限。
5. 检查端口没有冲突后，把服务模板安装到 systemd 的系统单元目录，重载并启动服务。

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now prl-proxy
sudo systemctl status prl-proxy
sudo journalctl -u prl-proxy -f
```

停止代理使用 `systemctl stop prl-proxy`。矿工需要独立的运行和恢复策略。频繁失败达到启动次数限制时，应先检查配置和日志，修复后再 `systemctl reset-failed prl-proxy`。
