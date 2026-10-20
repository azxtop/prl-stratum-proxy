# SRBMiner-MULTI 3.7.8 PRL 实验原型

这是单独适配 3.7.8 的 SOCKS5/TLS 转接核心与有时限的独立运行入口，和仓库原有的 3.7.6 配置分开。请从仓库检出目录运行，不能把旧版 `profiles/srb.example.json` 或旧版内存偏移直接用于新版本。

## 已实现及验证边界

- 按实际 `mining.authorize` 内容识别主账号和开发者 PRL 钱包，不依赖固定开发者 IP 名单；主连接也解码并统计真实提交。
- 将开发者授权账号和矿工名替换为配置值，转向自己的 PRL 上游；任务号、`plain_proof`/`proof` 及其他计算字段保持不变。
- 授权回执和真实 `mining.submit` 回执分别记录；保存证明摘要、任务 target、接受、拒绝、待回执及连接关闭时未回执数量。
- 同时识别 TLS 与明文 JSON；未知协议记录后尝试原目的地址透传。已路由未知协议之后又出现 PRL 授权、或 PRL 授权格式不受支持时，报告未覆盖，控制器停止实验。
- 新启动器对自己的 SRB 子进程进行版本固定的 TLS 验证模式内存调整；整文件 SHA256、代码上下文、初始化后的输出门槛、写入和读回均检查。磁盘矿工和系统证书库不变。
- 控制器检查矿工存活、内存修改是否保留、API 算力、运行时间/份额计数重置、提交回执超时及代理错误；独立 guard 在租约过期或控制器退出后停止该次子进程。每 15 秒尝试保存一次 `ss` TCP/UDP 快照。

私有实机验证在单卡及三卡 RTX 4090 上进行了约 10–11.5 分钟，观察到两个不同的 `3360/TLS` 开发者端点和两种钱包授权；两台各有 4 条真实转接提交接受回执，单卡样本另经使用者独立确认矿池面板显示份额或算力。成功样本无拒绝、无未回执及代理错误。此处只发布脱敏汇总，不附原始机器日志。

**这不证明所有潜在通道均已覆盖。** 其他端口、未来协议、绕过 SOCKS 的连接以及短连接尚不能排除；容器内 `ss` 可能缺少进程归属。没有强制出口隔离。NOCK 收益未验证；PRL+NOCK 组合授权的 PRL 部分转接不等于 NOCK 也已转接。短测不能验证长期收益提升或用份额条数直接估算实际费率。

## 准备

需要 Linux x86_64、Python 3.10+、NVIDIA 驱动、OpenSSL 命令行，以及系统本来允许父进程调试自有子进程的权限；`ss` 不可用时会记录审计缺失。无需安装 Python 第三方包。权限不足时退出，不应为本原型关闭系统安全功能或提升容器权限。

自行从 SRBMiner 官方发布页取得原版 3.7.8 Linux 文件，不使用仓库旧版启动器。唯一接受的可执行文件 SHA256：

```text
59d71614ac508f77b4b6a338564db18e5163119059badf43175549d94634821e
```

在仓库根目录生成自己的临时证书和私钥，随后填写账号、矿工名及上游：

```bash
mkdir -p runtime/srb378
(umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj /CN=localhost -keyout runtime/srb378/client-key.pem \
  -out runtime/srb378/client-cert.pem)
cp experimental/srb378/config.example.json experimental/srb378/config.local.json
# 编辑 config.local.json；示例占位值会被拒绝。
```

`worker` 是正常矿工名，转接矿工自动使用 `worker + fee_suffix`。两者分别限制为 1–15 位小写字母和数字。`certificate`、`key`、`data_dir` 的相对路径以配置文件目录为基准。

Python 代理对上游 TLS 默认验证证书。只有自己的上游确需跳过验证时，才给相应池设置 `"verify_tls": false`；这项例外会记录在事件日志中。未知 TLS 目的地址透传仍校验证书。

**进程内修改会改变该 SRB 子进程的 TLS 身份验证模式，而不只是给某个域名信任证书。** Python 上游验证和 SRB 自身验证是两件事。本入口要求显式启用参数；哈希或初始化上下文不匹配即停止自己的子进程，不尝试猜测偏移。早期实验证明过早写入会导致启动崩溃，所以不能省略启动门槛。

## 启动与日志

先自行安排原 GPU 矿工停止和之后的恢复，避免两个矿工争抢 GPU。本入口检测到已有 GPU 计算进程会拒绝启动；不会替你停止任何已有进程。它不会管理 CPU 挖矿、SSH、闹铃或原矿工。

```bash
python3 experimental/srb378/run.py \
  --config experimental/srb378/config.local.json \
  --binary /absolute/path/to/SRBMiner-MULTI \
  --enable-process-tls-patch --seconds 900
```

运行时长限定在 60–4200 秒，默认 900 秒。Ctrl+C 停止本次子进程；到时也会停止。独立 guard 只结束记录的 SRB 进程组，不会启动另一个矿工。原机器测试使用的 OneZero/BNT/闹铃接管与恢复依赖私人部署，未包含在公开入口中。

SOCKS 监听固定回环地址。矿工 API 使用原程序的默认绑定行为和配置的端口，请在适合该 API 暴露范围的测试网络内运行。本原型不是无人值守长期安装器。

启动后终端打印本次运行目录，另开终端查看：

```bash
tail -F runtime/srb378/run-*/srb-console.log
tail -F runtime/srb378/run-*/proxy-events.jsonl
```

已有多次运行时，把通配符改成终端打印的具体目录。Ctrl+C 只退出 `tail` 查看，不停止矿工。

| 文件 | 内容 |
| --- | --- |
| `state.json` / `samples.jsonl` | 当前统计、API 算力与连续采样 |
| `proxy-events.jsonl` | 目的地址、身份改写、任务、提交及对应回执 |
| `runtime-patch.json` | 版本哈希、原字节/修改字节及验证范围 |
| `egress-samples.jsonl` | `ss` 快照或失败原因，不能当作完整出口证明 |
| `lease.json` / `guard.json` | 独立 guard 的租约与身份 |
| `result.json` / `finished.json` | 最终统计及实验是否正常结束 |
| `guard-stopped.json` | 监控失效时 guard 终止子进程的记录 |

运行目录会包含自己的账号、矿工名、网络信息和本地进程记录，不要上传。这里的日志针对短时、有时限的实验，未加入长期轮转；再次运行会创建新目录。定期自行清理旧目录。

模拟回归测试包含大 `plain_proof` 保留、主/开发者授权、接受/拒绝计数、未知协议与 TLS；CI 不下载矿工、不连接真实矿池。实机验证只覆盖上文明确列出的路径，不能替代部署后的持续核对。
