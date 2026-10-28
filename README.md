# PRL Stratum Proxy

本地 PRL Stratum 转接代理，包含 OneZeroMiner **1.8.2 / 1.8.3 / 1.8.4**、ForgeMiner 1.8.8 和 SRBMiner-MULTI 3.7.6 三种配置。转接符合已知规则及协议的连接，保留计算证明，并逐条关联真实提交回执。

SRBMiner-MULTI **3.7.8** 的独立实验适配已加入 [`experimental/srb378`](experimental/srb378/README.md)，包含明文/TLS 识别、主份额解码、`plain_proof` 转接、固定版本启动器及有时限的独立 guard。它使用单独的配置和入口；下文 SRB 主连接透传及旧版启动说明仍指 3.7.6，不适用于 3.7.8。

这是独立的通用代理。项目不包含矿工二进制、矿池账号、私人中转地址、SSH 配置、机器清单或生产日志，也不包含针对某台机器的旧矿工接管和恢复逻辑。

OneZero 使用下方说明；Forge 与 SRB 的版本校验、编译、启动及限制见 **[三种矿工配置](profiles/README.md)**。SRB 需要明确启用自有子进程的临时 TLS 验证模式修改；Forge 使用只作用于指定程序的本地连接 hook。两者不能直接套用 OneZero 的启动命令。

## 功能

- OneZero 默认识别 `lproute.com` 及其子域名的 `3360`，另精确识别 `pearl-hk.lproute.com:3361`、`prl.suprnova.cc:3373`。规则可配置；新增两条不会扩展到其他主机或端口。
- 匹配的连接改接配置的上游，将 PRL 授权账号和矿工名改为自己的账号和 `worker + fee_suffix`。
- OneZero/Forge 正常主连接经过协议代理并校验身份；SRB 主连接原字节透传，不统计其主份额。
- 提交的 `job_id`、证明字段保持不变；独立上游 RPC ID 处理重复客户端 ID、乱序回包。
- `mining.submit` 的接受、拒绝、无回执分别计数；授权成功不计作接受份额。
- 保存任务 target、证明摘要、回执和时延，可用于后续难度加权统计。
- OneZero 未知 SOCKS 目标记录后透传或拒绝；SRB 候选经 TLS 协议识别后转接或拒绝；Forge 额外记录原生连接元数据。不把新 IP 自动认定为漏转。
- 可选 Linux 出站包头审计及 `ss` 快照；不保留原始载荷。
- 默认只监听本机回环地址；Python 上游 TLS 校验默认开启，SRB 进程内模式的例外见配置说明；Python 日志采用有上限的轮转。

## 使用

需要 Python 3.10 或更新版本。转接核心只依赖标准库，无需 root；可选包头审计需要 Linux 以及已有的 raw socket 权限。`logs` 命令需要系统的 `tail`。

```bash
cp config.example.json config.json
# 编辑 config.json：填写自己的账号、矿工名和矿池地址。
python3 -m prl_proxy check-config --config config.json
python3 -m prl_proxy run --config config.json
```

示例配置故意不能直接挖矿。将 `YOUR_POOL_ACCOUNT` 和 `pool.example.org` 替换为自己的值；支持按顺序尝试多个上游。`data_dir` 的相对路径以配置文件所在目录为基准。

`redirect_rules` 中的 `domain_suffix` 匹配该域名及其子域名，`host` 仅匹配精确主机名，两者都必须同时匹配 `port`，每条规则只能指定其中一个字段。**显式配置的规则列表会完整替代默认值**：已有仅列出 `3360` 的配置需要手动加入示例中的两条 `host` 规则；更新源码不会自动改写用户配置。详见 [OneZero 通道说明](profiles/onezero.md#通道规则与更新)。

另开终端运行自行下载的原版矿工。默认端口下示例：

```bash
./onezerominer -a pearlhash \
  -o stratum+tcp://127.0.0.1:23784 \
  -w YOUR_POOL_ACCOUNT --worker rig01 -p x \
  --proxy 127.0.0.1:23783 --max-no-acc 60
```

账号和正常矿工名必须与代理配置一致；`rig01` 的转接矿工名默认为 `rig01dev`。若调整代理端口，要同步调整矿工参数。矿工版本和参数以其官方说明为准。

也可使用版本校验启动器，从同一份配置自动生成 OneZero 参数（先启动代理）：

```bash
python3 -m prl_proxy.launcher --config config.json --binary /path/to/onezerominer
```

启动器只接受已核验的 Linux x86_64 1.8.2 / 1.8.3 / 1.8.4 二进制，并要求代理状态新鲜、账号和矿工名一致。默认传入 `--max-no-acc 60`（60 分钟未接受份额重连），不设置超频或 kernel。校验值、升级方式与验证边界见 [OneZero 版本说明](profiles/onezero.md)。

矿工请从 [OneZeroMiner 官方发布页](https://github.com/OneZeroMiner/onezerominer/releases) 获取。本项目不重新分发其二进制，也不提供私人下载镜像。

对于确实需要跳过上游证书校验的自建中转，可仅在该条上游配置中设置 `"verify_tls": false`。这会降低该连接的身份验证能力，并留下事件记录；不会修改系统证书库。明文上游使用 `"tls": false`，只应在可信环境中配置。

## 状态与记录

```bash
python3 -m prl_proxy status --config config.json
python3 -m prl_proxy logs --config config.json
python3 -m prl_proxy netlogs --config config.json
# 可选：已有相应权限时启用包头审计；权限不足会明确记录。
python3 -m prl_proxy run --config config.json --audit
```

`run` 前台运行，Ctrl+C 退出代理；`logs` 的 Ctrl+C 仅关闭日志查看。后台运行可自行配置服务，示例见 [`deploy/prl-proxy.service`](deploy/prl-proxy.service)。不要对已有运行环境直接覆盖安装；先检查端口与矿工状态。

| 文件 | 用途 |
| --- | --- |
| `state.json` | 当前会话统计及状态更新时间 |
| `events.jsonl` | 路由、授权、任务 target、提交证明摘要与回执 |
| `unknown-channels.jsonl` | 未知代理目标和协议类型提示 |
| `network-status.json` | 可选审计是否启动、采集新鲜度及覆盖边界 |
| `egress-flows.jsonl` | 可选审计发现的出站 TCP/UDP 流元数据 |
| `unknown-egress.jsonl` | 需要核查归属的出站流量，含可能的正常矿池连接 |
| `socket-snapshots.jsonl` | 可选的每分钟 `ss` 快照 |

事件和快照日志默认各最多保留当前文件及 8 个 16 MiB 历史文件。统计按代理会话累计，代理重启后重新计数；旧日志仍保留到轮转覆盖。状态文件不是实时存活保证，应同时检查文件时间和进程/服务状态。

`connection_route` 将已解码会话的原 SOCKS 主机名、端口关联到 `role + connection`；可用同一组合核对授权、任务和提交回执。直接进入本地监听端口时没有原 SOCKS 目标，这两个字段为 `null`。未知目标记录不是自动警报，也不能只凭历史接受计数判断当前通道仍正常。

**这些运行文件可能含使用者填写的账号、矿工名和网络地址。请勿上传配置和运行日志。** `.gitignore` 只提供防误提交保护，不能替代发布前检查。

## 验证范围与限制

已知协议适配上述指定版本的 PRL 连接，仓库提供模拟上游、SRB 本地 TLS 和 Forge 原生路由的回归测试。公开版没有附带生产数据或 GPU 实测自动化，不能据此声称已验证某个矿池的长期收益或所有矿工版本。

原开发者费时间调度仍存在，代理只转接与配置规则匹配的连接。真实 `mining.submit` 接受回执证明协议接受，矿池面板实际记账需要独立核对。短期份额数量占比不能当作实际抽水费率。

各配置的未知目标行为不同，详见配置说明，不保证未识别通道会转到自己的账号。矿工绕过 SOCKS/hook、受保护进程、未解析的分片/IPv6 扩展头、捕获丢失和进程归属缺失均会影响完整性。出站包头审计观察同一网络命名空间的流量，可能包含平台服务，不能仅凭地址或端口认定属于矿工。没有安装系统级强制出口限制。

公开版只有显式执行的 OneZero/Forge/SRB 子进程启动器，不接管其他矿工，也不自动回退。代理异常时的矿工恢复策略应由部署者自己的监护进程负责；systemd 示例仅恢复代理服务。无需为本项目关闭系统安全功能或修改全局证书。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖授权改写、证明保留、重复 RPC ID、乱序回执、授权与份额计数分离、未知连接透传/拒绝、域名边界、配置校验和应用启停。

Linux 上有 `cc` 和 `openssl` 时，还覆盖 Forge 精确程序连接路由、未匹配连接保留、日志无载荷、SRB TLS 协议门控与主连接透传；缺少相应环境时会明确跳过这些测试。CI 在 Linux 编译原生 hook 并运行测试，不下载或运行第三方矿工。

## 许可

[MIT](LICENSE)。许可仅涵盖本仓库代码，不涵盖第三方矿工软件。本项目与上述矿工或矿池没有隶属关系；请自行遵守使用的软件和服务条款。
