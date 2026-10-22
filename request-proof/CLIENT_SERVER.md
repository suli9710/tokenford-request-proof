# 用户验证端与证明端

当前是可审阅实验版。代码已经提供SSH通道及标准输入输出证明端，没有安装到任何生产节点。真实OpenAI成功样本属于V1；当前V2只做合成与本地SSH验收。不要直接把实验程序接到普通用户业务或宣称机构审计。

## 用户侧

1. 独立接受所审阅发行版本的哈希，按[根 README](../README.md)使用 `review.py check/build/runtime` 编译并检查自己的验证器。
2. 生成单独的SSH用户密钥，将公钥交给证明服务运营方；私钥留在自己机器。
3. 从独立可信渠道确认服务端主机公钥，写入专用known-hosts文件。首次连上即接受、`ssh-keyscan`后直接信任，都不能独立排除服务器被替换。
4. 复制 `examples/client-ssh.json`，填写实际主机、专用用户、身份文件及known-hosts文件的绝对路径；示例域名无实际服务。
5. 编辑 `examples/request.json`，用新回执文件运行：

```powershell
# 在项目根目录，以已建立本地安装记录的同一 Python 环境运行。
python -B review.py verify --ssh-config /absolute/path/client-ssh.json --request /absolute/path/request.json --out /absolute/path/new-receipt.json
```

程序通过验证后才输出 `status:verified`、Plus套餐声明、所选模型和认证回复。失败只报告未验证，不展示另一条未验证回复；不会自动重试或切到普通转发。回执文件不能复用，避免误读上次成功结果。每次实际请求可能占用套餐配额。

用户侧从固定OpenAI HTTPS取公钥，并独立验证实际交互会话／ZK证明；SSH运营方不能靠自己的签名日志替代这些步骤。SSH管理员仍可能拒绝服务、改站方业务或控制账号池，因此一条已验证请求不证明账号池完整或所有请求都通过验证。

## 证明端准备

证明端应使用独立主机或受限运行环境。它承担较重MPC及ZK计算；当前不应放入生产核心服务进程。需要在自己的安装路径重新编译Rust程序，二进制引用该路径中的固定源码及工具；直接挪动另一台机器的二进制不构成完整安装。

`examples/server-policy.json`只含模型白名单、固定凭据提供程序和独占锁路径，不应填写原始token。提供程序由管理员掌控，不接收用户参数，在10秒内从既有秘密存储只读取一个账号，向子进程管道输出如下结构：

```json
{"token":"<private access token>","account_id":"<matching account id>"}
```

这份输出只能留在证明进程的私有管道中，不写终端、日志或公开文件。包中没有真实生产凭据读取器；需要另行实现受限适配，不能把数据库管理员权限或任何生产采集脚本交给客户端。

证明端命令：

```sh
/opt/tokenford-proof/request-proof/client/target/release/tokenford-user-verifier-prototype serve-stdio /etc/tokenford-proof/policy.json
```

程序的标准输入／输出专供长度限定的交互协议，不能加shell欢迎语、JSON日志或TTY。服务端执行固定policy、全局独占锁及最多8个允许模型；只接受小型Responses正文，要求`stream:true`、`store:false`，拒绝工具等未支持字段。证明前时间窗120秒，总进程180秒；锁因强杀残留时须由管理员先确认无运行进程再清理，不自动抢锁。

`examples/server-stdio-launch.sh`仅供审阅固定启动命令。管理员可为每个试用用户的公钥配置如下限制：

```text
restrict,command="/opt/tokenford-proof/server-stdio-launch.sh" ssh-ed25519 <USER_PUBLIC_KEY>
```

专用用户不得修改启动脚本、policy、provider或审阅源码，不开放普通shell、PTY或转发；凭据读取权限须限于单个证明账号。是否采用系统服务、容器及每用户频率限制，仍需在真实试点部署前明确。这里没有执行用户／授权密钥／防火墙／服务配置修改。

## 已做的必要验证

- 使用本机真实OpenSSH公钥认证及固定远端命令，跑完整SSH＋MPC-TLS＋ZK合成链；身份元数据不出现在用户认证视图中。
- 错误主机公钥在凭据提供器启动前拒绝；补充握手超时及远端失败检测，避免失败连接等待完整证明期限。
- 隐藏值跨越JSON字段、包含转义、长度不符及承诺不符均不能通过新电路。

这些结果没有覆盖两台机器之间的网络、Linux部署、真实上游V2兼容、负载及与现网账号调度的绑定。当前仍需这些验收和外部人员审阅，才能安排受限客户试用。
