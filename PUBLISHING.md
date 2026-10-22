# 发布准备

目标仓库暂定 `suli9710/tokenford-request-proof`。此候选准备时尚待用户批准创建，没有执行 GitHub 创建、推送、发版或工作流；后续操作以用户批准和实际记录为准。

1. 审阅源码和全部新增文档，核对原创 Apache-2.0 与第三方归属。`keccak256 v0.1.1`、`sha256 v0.2.1`、`nodash v0.42.0` 许可尚未明确，不得分发其目录或 README／Nargo 复制件，不得分发任何 `artifacts/` 编译产物。
2. 维护者将最终差异单独审阅后，才能使用 `scripts/freeze_sources.py --acknowledge-new-unreviewed-release` 建立新的候选基线。生成哈希仍不是独立认可；不能用于把审查失败转为通过。
3. 在新源码目录检查候选哈希，按固定环境构建、运行 runtime、reproduce 和合成 audit，记录实际成功、失败及未执行范围。测试完成后可写 `VALIDATION.md`，只记录源码哈希和范围，不写包含它的 ZIP 自身摘要。
4. 使用 `scripts/package_source.py --out build/source.zip`，重做最终内容与敏感材料检查，并核对解压后的清单和所有排除项。FORK_REPORT／SANITIZATION_REPORT／RELEASE_REPORT 保持在包外；需要公开时，另行检查为外部资产，并明确其审查对象。
5. 给用户提供可审阅源码包、源码身份、包 SHA256、许可缺口与验证范围，取得创建公开仓库／推送的最终批准后再操作。只提交白名单分发源码、根清单及摘要；可选 VALIDATION 须审阅。不要把整个开发目录直接 `git add .`，其中可能有本地取得但不允许再分发的依赖和构建材料。
6. 仅在已经批准的公开仓库中人工触发 review 工作流，输入独立认可的源码清单哈希。CI 使用只读默认权限；仅源码来源证明任务有 `id-token:write` 与 `attestations:write`。它不自动 release 或 push，只上传源码 ZIP 和不含本地路径的摘要 JSON。

此候选准备时，`.github/workflows/review.yml` 尚未在 GitHub 运行。其来源证明只关联源码包与 GitHub 提交／工作流，不证明代码安全、真实账号、依赖授权或真实上游兼容性。创建仓库后仍须按实际账号功能、权限和运行结果核验，不能把工作流文件本身当成功回执。
