# 当前源码的实际复核记录

日期：2026-10-22（UTC+08）。这是维护者的执行记录，另有独立AI增量审阅；两者均不代表外部机构审计、安全认证或上游认可。用户应按固定版本自行读码、复现并检查失败原因。

源码清单SHA256：440619514b3e89128212fc73236aec2555957bd296f571ca69776fbe5ae1c7ca。本文件在清单之外，可随包分发；最终ZIP摘要须另行核对，不嵌入包含本文件的包自身摘要。

## 本轮实际变化与执行

Python依赖原先只有版本检查，没有运行文件快照；受控追加注释后旧版runtime仍通过，此缺口已实际复现。本版将隔离venv的包文件、元数据及.pth纳入安装快照。独立增量审阅又发现普通遍历可能遗漏目录链接，随后补上Python链接、Node目录链接／逃逸链接拒绝。

重编和audit结果必须同时对应当前源码、当前安装快照、当前电路及验证密钥；执行结束再次核对安装身份。公开摘要分别记录执行时间与导出时间。同源码重新build会产生新安装记录，旧audit不能直接沿用。

Windows x64、Python3.12.10、Node24.11.1、Cargo1.95.0、本地OpenSSH下实际完成：

- 使用已有按哈希锁安装的隔离venv及公开缓存；两个电路重新编译，客户端在新目录从源码编译，没有复制旧客户端可执行文件。
- build／runtime通过，记录1400份客户端／Node文件及893份Python包文件，并核对所选Python／Node／SSH主程序。
- reproduce通过：同机器新进程重编电路与验证密钥，摘要匹配且绑定当前安装快照。没有证明原生二进制跨机器逐字节复现。
- audit的10组检查全部通过，共88.469秒；本地SSH＋TLS＋MPC＋ZK合成正例61.094秒，明确synthetic_only:true、official_openai_request_verified:false。
- check_evidence_gate.py的7个受控负例通过：旧源码audit／recompile、旧安装audit／recompile、不同密钥、缺失负例、夸大外部审计均拒绝。
- check_runtime_inventory.py在隔离临时目录真实创建Windows junction，Python／Node两处均拒绝，删除链接后原快照匹配；后续Linux symlink执行见下节。
- evidence成功导出绑定本次源码与安装的有限摘要，只有版本、摘要、计数、检查名及范围，无本地路径、账号、凭据或认证回复。
- 官方actionlint v1.7.12工作流检查通过；仅为语法检查，不能代替GitHub运行。

电路bytecode SHA256：33a1c033d8dabf1d0a6e2e054604ac20d073db2769f3c9f63fbc94ea174ec35c。

验证密钥SHA256：1aa7655e7ddc96729adc4cc011ae82e4dcc64c9529111b08b145a421b800f4ff。

两个密码学摘要与初始公开版相同。本轮没有修改电路约束或TLS／证明协议。

## 公开Linux CI与来源证明

[GitHub Actions运行39787322690](https://github.com/suli9710/tokenford-request-proof/actions/runs/39787322690)已完成，review与source-provenance两个任务均success。执行源码提交为11a16d9354f5734ec877cc1eaf4e0933f70f1d24，源码清单仍为上述440619…c7ca。运行时间为2026-10-22约21:29—21:38（UTC+08），GitHub托管Ubuntu24.04。

- 新CI工作目录从公开源码构建，重新取得缺失的锁定源归档、32MiB及128MiB量级公共CRS；完整build／runtime／reproduce／audit通过，没有上传或取用本机CRS缓存。
- Linux记录1392份客户端／Node文件及893份Python包文件；10组合成检查通过，audit144.096秒。
- 日志确认7个证据负例通过；Linux真实symlink目录夹具在Python／Node门禁均拒绝。它与Windows junction回归覆盖不同系统分支。
- 下载Linux public-evidence.json并核对：源码清单、10项检查、限定范围与预期一致，电路／验证密钥摘要与Windows相同。这是两个环境的摘要对照，不是两台机器互联SSH验收或原生二进制位级复现。
- 下载CI的source.zip，894成员、3,368,143字节，逐字节等于此前Windows已审阅源码包，SHA256为0e97d174240f9d50cf5c1b8906a10271de4871f38d1f3d8d22e6436368fa6480。
- [来源证明58657564](https://github.com/suli9710/tokenford-request-proof/attestations/58657564)已用gh attestation verify验证：限定仓库、准确workflow路径、source／signer提交11a16d9…1d24、refs/heads/codex/source-review，并拒绝self-hosted runner；命令退出0，验得1份签名，subject摘要与下载ZIP匹配。

该来源证明只覆盖提交11a16d9…1d24生成的源码ZIP，不认证代码安全、测试结论、真实套餐或模型。该ZIP含运行前的VALIDATION；本文件后续补写CI结果不包含在旧签名对象里，不能冒称新文档也已由那份证明签名。公开合成摘要只有工作流产物关联，没有单独来源签名。

独立核验这个固定CI产物的命令（需要自己的GitHub CLI环境，下载到新的目录）：

```sh
gh run download 39787322690 --repo suli9710/tokenford-request-proof --name source-11a16d9354f5734ec877cc1eaf4e0933f70f1d24 --dir ci-source
gh attestation verify ci-source/source.zip --repo suli9710/tokenford-request-proof --signer-workflow suli9710/tokenford-request-proof/.github/workflows/review.yml --signer-digest 11a16d9354f5734ec877cc1eaf4e0933f70f1d24 --source-digest 11a16d9354f5734ec877cc1eaf4e0933f70f1d24 --source-ref refs/heads/codex/source-review --deny-self-hosted-runners
```

CI源码artifact保留14天、合成证据artifact保留30天，可能到期删除；来源签名不自动保证下载长期可用。过期后可从该固定Git提交重建并核对上述ZIP摘要，但不得把新运行写成旧运行。

## 10组合成检查的实际边界

| 检查 | 覆盖 |
|---|---|
| SSH合成正例 | 固定主机公钥、公钥认证、固定命令、完整证明和认证合成文本；指定元数据被隐藏。 |
| 换模型 | 在预期模型／完成状态边界拒绝。 |
| 换正文 | 在预期请求／挑战边界拒绝。 |
| 错账号 | credential bridge失败；不声称单独定位账号电路约束错误。 |
| 错SSH主机公钥 | 拒绝，凭据提供器未启动。 |
| 元数据约束 | 正常ASCII见证通过；结构、转义、长度、承诺四个恶意见证拒绝。 |
| 公钥来源 | 受控HTTPS替身拒绝未受信任kid；不是实际上游取钥或完整伪造证明攻击。 |
| 客户端／Node／Python漂移（三组） | 分别临时追加字节，真实verify入口在运行材料门禁拒绝，随后恢复。 |

## 未完成与保留的失败

初始公开版源码清单054015a8103b08af26e44333562fa360753fc971a045f230703a366408158dc1的9组测试属于历史版本，没有作为本版验收。

此前Windows无缓存下载取得源码及较小CRS，但128MiB请求电路CRS没有在观察窗口内完成，进程被停止；本地后续使用大小及SHA均匹配的公共缓存。该历史失败保留。本轮Linux CI完整自动取得公共材料并构建成功，补上了该环境的冷启动验收，不证明Windows原网络问题已修复或所有网络都能成功。

强化版准备阶段曾出现Actions列表0及触发404，同源码树空提交未解决；更新审阅后的工作流后已登记并实际运行成功。具体登记原因未确认。WSL回退曾因Hyper-V不可用未能启动，没有安装或修改系统功能，不把它写成已修复。

本轮真实上游请求0、生产连接0、部署0、真实凭据读取0。V2真实上游、两台机器SSH、容量、长期运行及底层密码库全面安全审计尚未完成；历史V1真实样本不替代这些验收。

仍须信任Python启动／标准库／字节码缓存、系统库、加载器和OS；门禁不阻止启动时已执行的恶意.pth，本地记录没有独立安全签名。三个缺明确授权的锁定依赖与电路编译产物不分发，依赖闭包许可仍待澄清。单条结果不证明全站账号池、当前付款或模型权重。
