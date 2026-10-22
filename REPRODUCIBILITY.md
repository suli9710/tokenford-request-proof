# 构建与可重复范围

这里区分源码匹配、本机安装检查、电路重编和源码包复现。任何一步成功都不自动证明其余步骤，更不是代码安全认证。

## 固定环境与输入

推荐从独立目录开始，使用 Python 3.12.10、Node.js 24.11.1、Rust／Cargo 1.95.0、OpenSSH，并记录实际版本。`rust-toolchain.toml`、Python `requirements.lock`、Cargo／npm 锁文件、公开源归档摘要和 CRS 来源摘要约束各自输入。Python 安装命令必须保留：

```sh
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
```

在本地 venv 内执行，不向系统 Python 安装。平台没有匹配 wheel 时应报告不支持／安装失败，不能去掉哈希或二进制约束继续。`review.py build` 检查 Python 3.12 系列和依赖版本；安装脚本及 CI 进一步选定 3.12.10。Node 和 Cargo 由构建入口检查到固定版本。

OpenSSH 没有在本项目锁定为一个跨平台版本；安装记录保存选中的 SSH 主程序路径及摘要。系统工具、系统库和操作系统更新都可能影响环境，不能因此声称完整环境已经可重复。

## 实际步骤

先审阅安装与检查脚本，再独立认可源码基线。Linux／WSL 示例：

```sh
bash setup.sh
.venv/bin/python -B review.py check --expected-manifest '<独立认可的64位SHA256>'
.venv/bin/python -B review.py build
.venv/bin/python -B review.py runtime
.venv/bin/python -B review.py reproduce
.venv/bin/python -B review.py audit
.venv/bin/python -B scripts/package_source.py --out build/source.zip
```

`build` 调用 `request-proof/setup.py`，取得锁定公开依赖和 CRS，编译电路、重建验证密钥，并以 `cargo build --release --locked` 编译客户端。它不读取真实账号凭据。三个授权尚未明确的锁定依赖只在本地取得；完成下载／编译不意味着获得再分发许可。

| 结果 | 能复核的内容 | 没有证明的内容 |
| --- | --- | --- |
| `check` | 根清单、文件集合和两层源码检查器；指定外部源在 bootstrap 阶段可以缺失。已有外部文件仍须匹配。 | 发布者身份、基线本身安全、完整构建环境。 |
| `build/installation.json` 与 `runtime` | 当次客户端、Node 依赖及所选 Python／Node／SSH 主程序与本地记录一致；所需编译材料完整。 | 独立签名、Python 站点包哈希、系统 DLL、OS 整体。 |
| `build/recompile-result.json` | 同机器新进程电路 bytecode 和验证密钥摘要与重编前匹配。 | Rust 可执行文件位级复现、跨机器／跨系统一致。 |
| `audit` 的本地 summary | 本轮合成正例和指定负例被实际执行。 | 真实上游、完整攻击面或机构审计。 |
| `build/source.zip` 与同名 JSON | 白名单源码的固定顺序、时间戳、权限和换行规则；ZIP CRC 与摘要。 | 编译产物可重复或所有依赖已获许可。 |

## 独立检查源码包

`source-manifest.json.files` 是分发源码清单；`external_files` 是用户本地获取／重编材料的参考摘要。打包器只加入分发源码、根清单、摘要文件和可选 `VALIDATION.md`，排除外部依赖目录、所有编译产物、CRS、node_modules、target、凭据和本地构建记录。FORK_REPORT、SANITIZATION_REPORT、RELEASE_REPORT 留在源码包外，须与各自注明的候选版本和摘要对应阅读。

在相同源码和相同可选 `VALIDATION.md` 字节下，把源码包分别写入两个新的 `build/` 路径，比较 SHA256。再解压到新目录，以你独立认可的清单哈希执行 `check`。`VALIDATION.md` 不受 `files` 本体清单约束，但影响最终 ZIP 摘要；它只记录源码身份和验证范围，不应嵌入包含它的 ZIP 自身摘要。不要把报告文字当签名。Python／zlib 版本变化可能影响 ZIP 压缩字节，因此跨环境的包摘要也应实际比较，不能只依据“确定性”字样断言。

`scripts/freeze_sources.py` 是维护者发布准备工具，会重写两层源码基线及根清单；输出明确不代表独立认可。审查者发现差异时不要用它抹掉证据。

## CI 状态与来源证明

[review.yml](.github/workflows/review.yml) 只允许人工触发，先在 Ubuntu 24.04 使用固定工具链构建、重编和合成复核，成功后在另一个最小权限任务中打包源码并为 `source.zip` 创建 GitHub 构建来源证明。此候选准备时，工作流尚未在 GitHub 运行。

来源证明用于关联提交、工作流和源码包摘要；它不证明代码安全、账号真实性、依赖许可或真实上游成功。CI 不执行 `verify`，不自动推送、发版或上传本地二进制／电路／构建日志。
