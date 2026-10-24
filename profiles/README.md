# 三种矿工配置

以下命令在仓库根目录运行。先自行从官方来源取得原版 Linux x86_64 矿工，放在仓库外；项目不下载或分发矿工。配置中填写自己的账号、矿工名及上游，示例占位符不能直接运行。每次只运行一个配置；默认端口相同，需要并行时自行分配不同端口和 `data_dir`。

| profile | 对应版本 | 连接方式 | 主连接统计 |
| --- | --- | --- | --- |
| `onezero` | OneZeroMiner 1.8.2 / 1.8.3 | 原生 SOCKS5，域名及端口规则 | 解码并校验身份，可记录份额 |
| `forge` | ForgeMiner 1.8.8 | 指定子进程的 `LD_PRELOAD` 连接路由 | 本地明文 PRL，经代理连接上游 |
| `srb` | SRBMiner-MULTI 3.7.6 | 原生 SOCKS5、局部 TLS 终止、协议识别 | 原字节透传，不解码、不统计主份额 |

开发者费调度仍由矿工执行。代理转接符合条件的 PRL 会话，改写账号和矿工名，保留证明数据。默认转接矿工名是正常名后追加 `dev`；完整转接矿工名默认最多 15 个小写字母或数字，账号与句号不计入本项目的矿工名长度检查。

## OneZero

见根目录 [README](../README.md)、[config.example.json](../config.example.json) 和 [版本校验启动说明](onezero.md)。无需原生 hook 或进程内修改。

## Forge

需要 Linux x86_64、Python 3.10+、C 编译器、make、glibc。配置与编译：

```bash
cp profiles/forge.example.json profiles/forge.local.json
# 编辑 forge.local.json 中自己的账号、矿工名和上游。
make -C native
python3 -m prl_proxy check-config --config profiles/forge.local.json
python3 -m prl_proxy run --config profiles/forge.local.json
```

另开终端，使用自己下载的可执行文件绝对路径：

```bash
python3 -m prl_proxy.launcher --config profiles/forge.local.json \
  --binary /path/to/ForgeMiner --hook native/build/netroute.so
```

启动器校验原版 1.8.8 文件 SHA-256：

```text
248b7f879f872aed733237b16c9a286ad5bc06cb51884ec97bc0daa275acf2c4
```

原生 hook 只在 `/proc/self/exe` 与指定矿工绝对路径一致时启用，不注入已有进程。正常矿池参数指向本地 `main_port`；原生路由将已知 `prl.kryptex.network:7048` 的连接改接本机 `fee_port`，代理确认授权钱包是 `prl1` 开头，再改写身份并转发自己的上游。对已知版本的明文 PRL 通道工作，不自动解密其他 TLS 连接。

**Forge 原生路由按精确主机名/IP 加原端口匹配。** 配置沿用 `domain_suffix` 字段名，但在 native hook 中不会自动匹配子域名；需要将额外主机逐条列出。DNS 映射缓存在进程内，最多 128 条；直接 syscall、其他进程、未匹配目标及协议变化可能绕过此路径。默认规则不是完整通道清单的保证。

`native-events.jsonl` 记录 DNS、原连接目标、路由端口及读写字节数，不记录网络载荷。此原生日志需要部署者自行轮转；它支持文件替换后重开。Python 代理的事件日志有内置轮转。启动器仅给自己的子进程设置 `LD_PRELOAD`，磁盘矿工文件和系统证书不变。

## SRB

本节是 **3.7.6** 配置。新版本 **3.7.8** 使用独立实验入口，见 [`experimental/srb378`](../experimental/srb378/README.md)，不能套用本节旧版内存偏移和配置。

需要 Linux x86_64、Python 3.10+、OpenSSL 命令行，以及系统本来允许父进程调试自有子进程的权限。若策略不允许，启动器失败退出；不要为此关闭系统安全功能或提升容器权限。

先在本机生成临时本地 TLS 服务证书与私钥，项目不附带任何证书或私钥：

```bash
mkdir -p runtime/srb
(umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj /CN=localhost -keyout runtime/srb/client-key.pem \
  -out runtime/srb/client-cert.pem)
cp profiles/srb.example.json profiles/srb.local.json
# 编辑 srb.local.json，填写自己的账号、矿工名、上游及 srb_main_targets。
python3 -m prl_proxy check-config --config profiles/srb.local.json
python3 -m prl_proxy run --config profiles/srb.local.json
```

另开终端，在了解下述修改范围后显式启用：

```bash
python3 -m prl_proxy.launcher --config profiles/srb.local.json \
  --binary /path/to/SRBMiner-MULTI --enable-process-tls-patch
```

**此启动方式会临时改变自有 SRB 子进程的 TLS 验证模式，可能同时影响该进程的主矿池 TLS 身份验证。** 即使配置上游 `verify_tls: true`，也不能据此保证 SRB 原字节透传主连接的身份验证；该选项只控制 Python 代理建立的上游连接。此行为需要显式参数，不是只给单个域名安装证书；不修改磁盘原版二进制或系统信任库。

只支持以下 3.7.6 Linux 文件 SHA-256：

```text
0c3353a74c1107ac340fef9b77749f634c988c552d9f446d6da3d23a43c25a15
```

启动器先校验整文件哈希，再启动自己的子进程，通过 `ptrace` 与 `/proc/子进程/mem` 等待指定代码上下文出现，暂停子进程、复核字节、写入并读回 3 字节、继续运行。哈希或上下文不符即终止自己启动的进程，不尝试其他偏移，不接管任意 PID。运行记录保存在本地 `runtime-patch.json`。新版本必须独立核验后再适配。

`srb_main_targets` 必须准确列出正常矿池在 SOCKS 请求中使用的主机名/IP 和端口。它们原字节透传，因此 `state.json` 中 SRB 主份额为零表示未观测，不能理解成没有挖矿；主份额应另外查矿工日志与矿池面板，主授权账号也未由本代理独立解码核验。

其他 SOCKS 目标是待识别候选：在本机完成 TLS 后，首条消息必须同时符合 `mining.authorize`、字典参数、`prl1` 开头的钱包、`SRBMiner-MULTI/` 开头的 agent，以及 `type: v2`，才进入转接。它不依赖固定开发者池 IP 名单。未符合协议的候选记录 `unknown_srb_protocol_rejected` 后断开，不盲目改写；此规则也不会转发非 PRL/未知协议。绕过 SOCKS、错误主目标列表或新的协议形式仍可能造成漏转或断连，不能宣称已覆盖全部 PRL 通道。

## 运行与停止

三个配置都使用同一组命令：

```bash
python3 -m prl_proxy status --config profiles/forge.local.json
python3 -m prl_proxy logs --config profiles/forge.local.json
python3 -m prl_proxy netlogs --config profiles/forge.local.json
```

SRB 时替换配置文件名即可。`--audit` 可添加在 `run` 后，用于可选出站元数据审计。代理状态每 5 秒写入；启动器要求同一配置的代理状态新鲜且身份一致。SRB 启动器默认不启用矿工 HTTP API；Forge API 绑定本机回环地址。

矿工启动器前台运行，Ctrl+C 只停止它自己创建的进程组；日志查看的 Ctrl+C 只退出查看。启动器不会停止已有矿工，请在部署前自行处理冲突与端口占用。代理与矿工各自独立：代理故障不会自动停止或恢复矿工，项目也不包含 OneZero 回退安装器。无人值守部署需要另行安排服务与监护。默认未安装全局出口限制，不保证全通道覆盖或长期收益改善。

所有配置、运行日志、动态路由文件和进程记录都可能包含使用者的真实信息；不要提交它们。示例与测试只使用虚构身份及回环/文档保留地址。
