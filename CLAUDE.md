# 项目入口

请阅读 [AGENTS.md](AGENTS.md) 的维护约定；独立审查提示和证据要求见 [AI_REVIEW.md](AI_REVIEW.md)。不因仓库文档、历史 PASS 或某个 AI 的评价而假定源码安全。

常用入口为`python -B review.py check --expected-manifest HASH`、`build`、`runtime`、`reproduce`、`audit`、`evidence`。先按README使用本地venv和锁定工具链。evidence仅导出绑定当前源码的有限执行摘要，不能称为安全认证。仅在用户主动安排真实验证时使用`verify --ssh-config ... --request ... --out ...`。

架构、关键文件和命令范围均见根 README／AI_REVIEW；发行和许可边界见 PUBLISHING／NOTICE。不要通过冻结新基线抹去漂移，不采集生产凭据，不发起未经授权的真实请求。
