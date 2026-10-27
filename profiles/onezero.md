# OneZeroMiner 1.8.2 / 1.8.3 / 1.8.4

1.8.3、1.8.4 沿用 `onezero` 配置和原生 SOCKS5 路由。已知规则仍为 `lproute.com` 及其子域名的 `3360` 端口；本次不改变协议核心，不假定所有未知目标都属于开发者费连接。

## 启动

在 Linux x86_64、Python 3.10+ 环境下，从 [官方发布页](https://github.com/OneZeroMiner/onezerominer/releases) 自行取得所需版本的矿工，解压到仓库外。先复制并编辑配置：

```bash
cp config.example.json config.json
# 填写自己的账号、矿工名和上游地址。
python3 -m prl_proxy check-config --config config.json
python3 -m prl_proxy run --config config.json --audit
```

`--audit` 是可选的出站包头审计；权限不足会记录，不应因此提升容器权限。另开终端：

```bash
python3 -m prl_proxy.launcher --config config.json --binary /path/to/onezerominer
```

启动器校验以下**解压后的可执行文件** SHA-256（不是压缩包）：

| 版本 | SHA-256 |
| --- | --- |
| 1.8.2 | `d29ef582a7342b4914b990337693830ce75507accf4f86565d45911b6f743140` |
| 1.8.3 | `20cd045a78849bea80e4a8b35dc278076b1fedeaa6d40acf6788d51b77cfa2b6` |
| 1.8.4 | `7c2d68d61545cb121483fef76b6a1c2ab8fbeadab8e3ce737f76e19fd229b7ec` |

这些是已测试文件的固定校验值，用于拒绝未经核验的构建，不表示上游发布者签名认证。同版本的不同构建也需要独立核验，不能只修改版本号来放行。

正常连接指向配置的本地 `main_port`；SOCKS 指向 `socks_port`。账号和矿工名从同一配置读取，转接名为 `worker + fee_suffix`。启动器设置 `--max-no-acc 60`，即 60 分钟未接受份额重连；不锁频、不设置 kernel、不修改二进制或证书库。上游 TLS 由代理按配置验证。

已有 1.8.2 / 1.8.3 配置可以复用。先准备新二进制、检查配置和端口，再停止自己管理的旧矿工并用新路径启动，避免两个矿工争用 GPU。公开启动器不会停止其他进程，也不携带生产环境的自动回退脚本；监护与回退需由自己的部署服务安排。

## 确认转接

```bash
python3 -m prl_proxy status --config config.json
python3 -m prl_proxy logs --config config.json
python3 -m prl_proxy netlogs --config config.json
```

查看 `redirect` 的 `submitted / accepted / rejected / unanswered / pending` 和事件中的 `submit_reply`。`authorize_reply` 成功只表示登录成功，不能算作接受份额。首次转接份额可能晚于主矿工开始出份额；不要仅凭几分钟未出转接份额判定故障。

1.8.3 的已知通道在运行验证中获得了真实提交接受回执；公开仓库测试使用模拟上游，不包含真实账号、机器地址、生产日志或 GPU 测试环境。回执不等同于矿池面板实际记账或长期收益验证。请独立检查面板。

1.8.4 已在独立 GPU 运行测试中复核：两次有效会话各有 3 条真实 `mining.submit` 接受回执，已关联授权身份、请求 ID、任务 target 与证明摘要，并由使用者核对了相应矿池面板的最新提交更新。另一次 20 分钟观察没有转接提交，记录为未获得新证据，没有将授权成功或零提交算作份额接受。上述结果验证已知路径可用，不证明每次短测都会出转接份额、全部通道覆盖或长期收益增长。公开仓库仅包含通用源码、虚构配置和回归测试，不上传这些运行记录。

未知目标继续按 `unknown_policy` 记录并处理，出站审计有采集和进程归属限制。未记录未知连接不能证明不存在其他通道。`stale-work` 表示任务过期，应结合时间、比例和后续接受份额判断，不能单凭一条拒绝认定转接失败。
