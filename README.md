# Tokenford Request Proof

这是供用户在自己机器上审阅、编译和复核的交互式请求证明实验。验证端参加一次 TLS／MPC-TLS 交互，用零知识证明把新挑战、选定请求、隐藏的签名凭据、匹配的账号请求头和认证响应关联起来。

当前 V2 只有本地合成 TLS、SSH 和证明链的开发验收，没有真实上游 V2、两台机器互联或现网验收。它没有接受外部安全审计，也没有得到上游背书。`PASS`、站方签名日志、AI 审查意见和本包自带的哈希，都不能代替你的独立判断。

公开仓库为 [suli9710/tokenford-request-proof](https://github.com/suli9710/tokenford-request-proof)。初始源码已发布；当前版本的实际验收及未完成项见 [VALIDATION.md](VALIDATION.md)。工作流文件、来源证明和公开记录均不能代替实际运行结果。

## 从哪里开始

- 让自己的 AI 审源码并实际复核：[AI_REVIEW.md](AI_REVIEW.md)。其中有可直接复制的审查提示。
- 理解证明范围、攻击者和未覆盖项：[THREAT_MODEL.md](THREAT_MODEL.md)。
- 核对工具链、构建及可重复范围：[REPRODUCIBILITY.md](REPRODUCIBILITY.md)。
- 了解 SSH 验证端和证明端的部署边界：[request-proof/CLIENT_SERVER.md](request-proof/CLIENT_SERVER.md)。示例不是正在运营的证明服务。
- 查看既有开发记录：[AUDIT.md](AUDIT.md)、[HISTORICAL_RESULTS.md](HISTORICAL_RESULTS.md)。V1 的历史真实请求记录不构成可独立重验的交付物。

## 先审阅，再运行

先取得你独立认可的 commit 或 `source-manifest.json` SHA256，并审阅 `review.py`、安装及检查脚本。哈希能检查文件是否匹配某个基线；发布者同时给出的文件和哈希只能证明自洽。普通使用者和审查 AI 不应运行 `scripts/freeze_sources.py` 来消除差异，它会创建一个新的、尚未获得独立认可的维护者基线。

准备 Python **3.12.10**、Node.js **24.11.1**、Rust／Cargo **1.95.0** 和 OpenSSH。构建会访问公开依赖与 CRS 下载地址，耗时、内存及磁盘需求应以自己的环境为准。下面的命令只用于独立的本地工作目录。

Linux／macOS／WSL 已安装上述工具后：

```sh
bash setup.sh
.venv/bin/python -B review.py check --expected-manifest '<你独立认可的64位SHA256>'
.venv/bin/python -B review.py build
.venv/bin/python -B review.py runtime
.venv/bin/python -B review.py reproduce
.venv/bin/python -B review.py audit
.venv/bin/python -B review.py evidence --out build/public-evidence.json
```

`setup.sh` 只检测工具、创建本目录的 `.venv` 并按锁文件安装 Python 依赖；它不会安装全局工具或替你更新基线。Windows PowerShell 可以直接建立环境：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -c "import sys; sys.exit(0 if sys.version_info[:3] == (3, 12, 10) else 'Expected Python 3.12.10')"
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.lock
.\.venv\Scripts\python.exe -B review.py check --expected-manifest '<你独立认可的64位SHA256>'
.\.venv\Scripts\python.exe -B review.py build
.\.venv\Scripts\python.exe -B review.py runtime
.\.venv\Scripts\python.exe -B review.py reproduce
.\.venv\Scripts\python.exe -B review.py audit
.\.venv\Scripts\python.exe -B review.py evidence --out build/public-evidence.json
```

失败时保留错误并核对原因，不要修改锁文件、删除检查或重新生成基线来得到成功输出。`build` 会下载锁定的公开输入、编译本地客户端和电路，不需要真实账号凭据。`audit` 会启动本地合成 SSH／TLS 服务并做证明及必要负例，不请求真实上游。

## 命令各自证明什么

| 命令 | 检查范围 |
| --- | --- |
| `check` | 分发源码与根清单一致，实际执行两层源码检查器；bootstrap 只允许指定外部源尚未下载。 |
| `build` | 使用锁定版本取得公开输入并本地编译，记录本次安装。记录由本机生成，不是独立认证。 |
| `runtime` | 核对本地客户端、Node依赖、隔离venv的Python包文件（含元数据／`.pth`）和选定的Python／Node／SSH程序。排除字节码缓存；Python启动、标准库、系统库和OS仍须可信。 |
| `reproduce` | 在同一机器的新进程中重编电路和验证密钥并比较摘要。没有证明 Rust 二进制或跨机器位级可重复。 |
| `audit` | 运行合成正例、错误模型／正文／账号、错误SSH主机公钥、四个元数据见证负例、公钥来源受控替身，以及客户端／Node／Python依赖漂移检查。完整范围见 [AI_REVIEW.md](AI_REVIEW.md)。 |
| `evidence` | 当前源码、安装快照、重编结果和完整合成检查均匹配后，导出不含本地路径／凭据的摘要；拒绝旧源码／旧安装结果、缺失负例或不同验证密钥，并分别记录执行与导出时间。摘要仍是执行记录，不是安全认证。 |
| `verify` | 由本机验证端参加一次实际 SSH 证明交互；需要另行审阅的真实证明端与独立确认的主机公钥。 |

你要主动发起一次真实验证时，先读证明端说明并自行准备配置，再使用新的回执路径：

```sh
.venv/bin/python -B review.py verify --ssh-config /absolute/path/client-ssh.json --request /absolute/path/request.json --out /absolute/path/new-receipt.json
```

包内的 `.invalid` 域名只是占位。真实验证会请求上游并可能消耗账号配额；默认安装、合成复核和 CI 均不执行它。不要把 token、账号标识、SSH 私钥或真实回执交给 AI、Issue 或公开日志。

成功结果只对应这一轮交互和受限输入。套餐字段是被验证签名凭据内的声明，不证明当前付款／订阅状态、模型权重或全部账号池；回执中的响应哈希覆盖经过认证的元数据隐藏视图，不是原始响应。它不是可转交第三方独立验证的离线 TLS 证书。

## 源码与许可

本项目原创代码和原创修改采用 [Apache-2.0](LICENSE)，第三方内容保留各自条款，见 [NOTICE](NOTICE) 和 [THIRD_PARTY_LICENSE_STATUS.md](THIRD_PARTY_LICENSE_STATUS.md)。

三个锁定版本尚缺明确授权：`keccak256 v0.1.1`、`sha256 v0.2.1`、`nodash v0.42.0`。分发源码和公开 Git 必须排除这三个目录、其 README／Nargo 复制件，以及所有 `artifacts/` 编译产物。这里只保留来源 URL、路径和锁定摘要，用户本地构建时获取；这不代表完整依赖闭包或衍生产物的再分发许可已经解决。

维护者可在最终源码检查通过后生成确定性源码包：

```sh
.venv/bin/python -B scripts/package_source.py --out build/source.zip
```

输出路径须在 `build/` 内且尚不存在。打包白名单来自 `source-manifest.json.files`；`external_files` 只记录本地取得／重编材料的摘要，不把这些字节放入源码包。发布前流程见 [PUBLISHING.md](PUBLISHING.md)。
