# WeChat Cloud Bot

在 Windows 云服务器上运行的微信群聊 AI 自动回复程序，复用 xwechat 的消息读取、模型调用、任务状态和受控发送代码。

当前版本基于 bot7，只处理一个指定群的普通文字消息：匹配配置的完整 `@名字` 后生成回答，在原群发送。启动前的旧问题不会补发；不确定是否发送成功的任务保留为待核对，不自动重发或重启。

## 运行条件

- Windows Server 2022、CPython 3.11 x64。
- 已登录的 Windows 微信和可操作的交互桌面，NVDA 保持运行。
- 自己的模型 API 凭据。当前已验证的模型配置为阿里云百炼 `deepseek-v4.1-flash-1017`。
- 首次安装需要访问官方 PyPI。依赖固定版本及 SHA-256，安装到独立 `.bot-venv`，不修改全局 Python 环境。

这是一份脱敏源码仓库。仓库不包含真实服务器、账号、群配置、API 凭据或离线依赖安装包。

## 配置与启动

先在目标服务器的源码目录复制三份示例配置：

```powershell
Copy-Item -LiteralPath 'cloud-deployment.example.json' -Destination 'cloud-deployment.private.json'
Copy-Item -LiteralPath 'cloud-bot.example.json' -Destination 'cloud-bot.private.json'
Copy-Item -LiteralPath 'bot-settings.example.json' -Destination 'bot-settings.json'
```

填写本地配置：

| 文件 | 内容 |
| --- | --- |
| `cloud-deployment.private.json` | `expected_host`：目标服务器的计算机名；`account`：该账号的数据文件夹名称；`self_id`：本人微信内部 ID；`group_id`：目标群内部 ID；`group_name`：准确群名；`data_root`：微信数据根目录绝对路径；`maas_base`：该百炼工作空间的 API base URL。 |
| `cloud-bot.private.json` | API key、base URL、准确模型名称和系统提示词。使用当前百炼模型时，`base_url` 与部署配置中的 `maas_base` 保持一致。 |
| `bot-settings.json` | `mention_name` 填写群里显示的机器人名字，不含 `@`。 |

这三个本地文件均被 Git 忽略。**不要把真实身份或凭据填回 `*.example.json` 或源码。** 缺少配置、配置字段不符或主机不匹配时，启动直接失败，不使用默认部署身份。

启动 NVDA，打开微信并选中目标群，然后运行：

```powershell
.\run_bot.cmd
```

核对账号、目标群和模型后，输入 `START`。显示 `Bot running` 后，用其他账号发送一条新的 `@机器人名字 问题`。

名字后需要空白和非空问题；微信 @ 列表产生的 U+2005 空白也可识别。当前匹配的是精确文字名字，不保证微信原生的被 @ 成员身份。

## 云端日常使用

日常启动、VNC 会话和异常处理见 [运行说明](CLOUD_RUNBOOK.md)。发送器依赖交互桌面，使用鼠标和窗口焦点；自动发送时不要操作该桌面。

基线 bot7 已取得真实连续文字回复，以及控制台/VNC方式关闭远程连接页面后的短时实收回复证据。图片、图片引用、类型49引用消息尚未接入；24小时稳定运行、锁屏发送和跨重启自动恢复尚未验证。

源码仓的变化仅为部署身份移入本地配置、安装方式改为官方 PyPI，以及文档脱敏。现有已部署服务器未被本次上传操作修改；本源码版本还需单独进行云端验收。

## 主要文件

- `cloud_bot.py`：配置边界、主机校验和拥有独立工作进程的监督入口。
- `cloud_bot_runtime.py`：消息来源、模型与受控发送装配。
- `cloud_source.py`、`cloud_db_reader.py`、`cloud_db_key.py`：认证消息快照、加密数据库读取和进程内密钥验证。
- `cloud_probe.py`：运行时复用的 Windows 微信窗口发现代码。
- `vendor/`：当前运行合同所需的受控 xwechat 源码副本。
- `requirements-cloud-runtime.txt`、`DEPENDENCY_PROVENANCE.json`：固定依赖及来源、哈希信息；依赖文件本身不上传。

来源与受控改动见 [VENDOR_PROVENANCE.md](VENDOR_PROVENANCE.md) 和 [RUNTIME_PROVENANCE.json](RUNTIME_PROVENANCE.json)。原来源项目未随仓库上传。

## 仓库范围

只保留当前运行源码、固定依赖清单、配置示例和必要说明。测试、历史原型、旧诊断工具、会话记录、聊天数据库、图片、密钥、运行状态、日志、备份、虚拟环境和交付压缩包均不上传；本地原件保留。

仓库内第三方代码的许可说明见 [SOURCE_NOTICES.md](SOURCE_NOTICES.md)。本仓库没有自行追加开源许可证。
