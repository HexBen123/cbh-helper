<div align="center">

# 🛡️ CBH Helper

**华为云堡垒机（CloudBastionHost）SSH 接入辅助工具**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![paramiko](https://img.shields.io/badge/paramiko-4.0.0-44A833)
![Version](https://img.shields.io/badge/version-0.2.0-2E7D32)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)

</div>

把 XShell / SecureCRT 的自动登录配置，变成一个本地工具：在**网页终端**或**本地 SSH** 里输入堡垒机账号，即可自动登录堡垒机并跳转到目标资源。

> [!IMPORTANT]
> 本工具**不绕过**堡垒机的认证与审计。所有连接仍然经过堡垒机，授权、审计、录像、MFA 策略照常生效。

---

## ✨ 特性

- 🌐 **网页终端** —— 浏览器直接连，内置 xterm.js（不依赖外部 CDN），支持中 / 英文切换、MFA、一键重连
- 💻 **本地 SSH 入口** —— 用熟悉的 `ssh` 命令接入，仅监听 `127.0.0.1`
- 🤖 **MCP 执行通道** —— 配合 `ssh-mcp-server`，让 AI / 自动化在目标机执行命令
- 🔍 **零配置启动** —— 自动读取目录下的 `*AutoLoginConfig*.zip`，识别堡垒机地址与目标资源
- 🔒 **凭据不落盘** —— 只缓存在当前进程内存，停止即清空

## 🚀 快速开始

**方式一：可执行文件（推荐）**

```powershell
.\cbh-helper.exe serve
```

查看版本：

```powershell
.\cbh-helper.exe --version
```

**方式二：Python 源码**

```powershell
pip install -r requirements.txt
python .\cbh_helper.py serve
```

启动后会自动打开网页终端，并同时开启本地 SSH 入口：

```text
Web terminal: http://127.0.0.1:8088
Local SSH:    ssh 127.0.0.1 -p 10022
```

> [!TIP]
> 把同目录下的 `*AutoLoginConfig*.zip` 准备好，工具会自动识别堡垒机入口和目标资源，无需手写配置。
> 可运行 `.\cbh-helper.exe doctor` 检查到堡垒机 / 目标的网络连通性。

## 🧭 三种接入方式

| 方式 | 入口 | 适用场景 |
| --- | --- | --- |
| 🌐 网页终端 | `http://127.0.0.1:8088` | 浏览器里操作，支持 MFA、目标下拉选择、重连 |
| 💻 本地 SSH | `ssh 127.0.0.1 -p 10022` | 习惯命令行 / 已有 SSH 客户端 |
| 🤖 MCP 通道 | `127.0.0.1:10022`（ssh-mcp-server） | AI / 自动化执行远端命令 |

三者共享同一进程的凭据缓存：在网页终端勾选 **Share this login with local SSH** 并连接成功后，本地 SSH 与 MCP 通道会自动复用堡垒机和资源凭据。

## 🌐 网页终端

打开 `http://127.0.0.1:8088`，输入堡垒机用户名、密码和可选 MFA 验证码即可。连接成功后工具会自动发送目标跳转指令。

- **重连按钮**：不刷新页面、保留已填写的密码 / MFA / 资源凭据，直接重连。
- **多目标**：在配置的 `target_profiles` 里登记多台资源后，页面会出现目标和资源账号下拉框；选不同账号自动切换对应的跳转指令。
- **资源密码**：不会从压缩包读取，只在当前页面会话内记住你手动输入过的值。

<details>
<summary>多目标配置示例（target_profiles）</summary>

```json
"target_profiles": [
  {
    "name": "web-server-01 (10.0.0.10:22)",
    "resource_name": "web-server-01",
    "resource_host": "10.0.0.10:22",
    "target_command": "?10.0.0.10_22_-1",
    "accounts": [
      { "account": "root",   "target_command": "?10.0.0.10_22_30" },
      { "account": "deploy", "target_command": "?10.0.0.10_22_35" }
    ]
  }
]
```

</details>

## 💻 本地 SSH 入口

```powershell
ssh 127.0.0.1 -p 10022
```

按提示输入堡垒机用户名、密码和可选 MFA；若配置里已有用户名则只需输密码。也可以把 SSH 用户名直接当作堡垒机用户名：

```powershell
ssh your-bastion-user@127.0.0.1 -p 10022
```

> [!TIP]
> 若已在网页终端勾选 **Share this login with local SSH** 并成功连接，这里会优先复用缓存的凭据，自动完成登录和跳转。

## 🤖 MCP 执行通道

`ssh-mcp-server` 连接 `127.0.0.1:10022` 执行命令时，会复用网页终端缓存的凭据和目标 profile。命令被包装成目标机上的临时 Bash 脚本执行，工具会自动剥离 shell 提示符和 ANSI 控制字符，只返回命令实际输出。

> [!NOTE]
> 凭据缓存仅存在于单个 `cbh-helper` 进程内。若启动了多个实例，请确保网页终端和 `ssh-mcp-server` 连接的是同一个本地端口。

## ⚙️ 配置

配置文件为 `cbh-helper.json`（首次 `serve` 会自动生成，也可手动执行 `.\cbh-helper.exe init-config`）。常用项：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `web_port` | `8088` | 网页终端端口 |
| `local_ssh_port` | `10022` | 本地 SSH 监听端口 |
| `open_browser_on_start` | `true` | 启动时自动打开浏览器 |
| `bastion_username` | `""` | 预填的堡垒机用户名 |
| `credential_cache_ttl_seconds` | `0` | 凭据缓存有效期，`0` = 进程存活期间一直有效 |
| `ssh_keepalive_seconds` | `30` | SSH 协议层保活间隔（秒） |
| `mcp_exec_timeout_seconds` | `300` | MCP 单条命令超时（秒） |

> 完整配置项（含 MCP、保活等进阶选项）见 [`cbh-helper.example.json`](./cbh-helper.example.json)。

## 🔒 安全说明

- 默认**不保存密码**；进程内缓存停止即清空，不写入磁盘。
- 本地 SSH 服务只监听 `127.0.0.1`，不对局域网开放。
- 所有连接仍经过堡垒机，授权 / 审计 / 录像 / MFA 策略照常生效。
