# HoneyDew

<p align="center">
  <img src="docs/logo.svg" alt="HoneyDew Logo" width="120" height="120">
</p>

<p align="center">
  <strong>多协议高交互蜜罐系统</strong>
</p>

<p align="center">
  <a href="https://c99standard.org/"><img src="https://img.shields.io/badge/语言-C-blue.svg" alt="C"></a>
  <a href="https://www.libssh.org/"><img src="https://img.shields.io/badge/依赖-libssh-green.svg" alt="libssh"></a>
  <a href="#支持的协议"><img src="https://img.shields.io/badge/协议-12-orange.svg" alt="协议数量"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/许可证-MIT-brightgreen.svg" alt="MIT License"></a>
</p>

---

## 目录

- [项目概述](#项目概述)
- [系统架构](#系统架构)
- [支持的协议](#支持的协议)
- [连接生命周期](#连接生命周期)
- [有限状态机](#有限状态机)
- [日志系统](#日志系统)
- [审计追踪系统](#审计追踪系统)
- [项目结构](#项目结构)
- [编译与运行](#编译与运行)
- [攻击模拟指南](#攻击模拟指南)
- [安全最佳实践](#安全最佳实践)
- [技术实现细节](#技术实现细节)
- [依赖项](#依赖项)
- [许可证](#许可证)

---

## 项目概述

HoneyDew 是一个基于 **C99** 编写的多协议高交互蜜罐系统，旨在模拟真实网络服务以捕获和分析攻击者行为。系统同时监听 **12 个常见网络协议端口**，每个协议均实现了高度仿真的服务交互逻辑，能够有效诱骗攻击者进行深度交互，从而最大化情报收集效果。

**核心特性：**

| 特性          | 描述                                                                            |
| ------------- | ------------------------------------------------------------------------------- |
| 多协议支持    | 同时模拟 12 种网络协议服务，覆盖 SSH、FTP、HTTP、数据库、邮件、DNS 等主流攻击面 |
| 并发处理      | 基于线程池的并发连接处理模型，支持最大 100 个并发连接（可配置）                 |
| 凭据捕获      | 完整的凭据捕获能力，记录所有认证尝试的用户名和密码                              |
| 高交互 SSH    | 基于 libssh 实现真实的密钥交换、认证流程和伪终端交互                            |
| 审计追踪      | 环形缓冲区审计追踪系统，异步刷写至磁盘，支持日志文件自动轮转                    |
| 双模式日志    | 彩色终端模式和 CloudWatch JSON 结构化模式                                       |
| 协议仿真      | MySQL 和 PostgreSQL 二进制协议级别的仿真实现                                    |
| 高危操作检测  | Redis RESP 协议完整解析，检测 CONFIG SET、SLAVEOF 等高危操作                    |
| DNS 攻击检测  | DNS 数据包解析，检测区域传送（AXFR）攻击                                        |
| SMTP 凭据提取 | 支持 AUTH PLAIN 和 AUTH LOGIN 的 Base64 解码                                    |

---

## 系统架构

HoneyDew 采用多线程架构，主进程为每个协议服务创建独立的监听线程，每个监听线程在接受新连接后创建独立的处理线程。所有连接通过会话哈希表统一管理，日志和审计系统贯穿全局。

<p align="center">
  <img src="docs/system_architecture.png" alt="HoneyDew 系统架构图" width="90%">
</p>

> 📁 图表源码：[system_architecture.mmd](docs/system_architecture.mmd) | 🖼️ PNG：[system_architecture.png](docs/system_architecture.png)

---

## 支持的协议

| 协议       | 监听端口 | 模拟服务                      | 捕获的攻击向量                                               |
| ---------- | -------- | ----------------------------- | ------------------------------------------------------------ |
| HTTP       | 9090     | Apache/2.4.29 + PHP/7.2.10    | HTTP 请求、路径扫描、表单提交、信息泄露探测                  |
| SSH        | 2222     | OpenSSH 8.9p1 Ubuntu (libssh) | 密钥交换、密码暴力破解、Shell 命令执行、横向移动             |
| FTP        | 2121     | vsFTPd 3.0.3                  | 凭据暴力破解、目录遍历、文件上传/下载、SITE 命令             |
| Telnet     | 2323     | BusyBox v1.35.0 (Ubuntu)      | 凭据暴力破解、Shell 命令执行、恶意软件下载（wget/curl）      |
| SMTP       | 2525     | Postfix (Ubuntu)              | AUTH PLAIN/LOGIN 凭据、邮件内容、发件人/收件人枚举           |
| MySQL      | 3306     | MySQL 5.7.42 (二进制协议)     | 登录凭据、SQL 查询注入、COM_QUERY 命令                       |
| Redis      | 6379     | Redis 6.2.6 (无认证)          | CONFIG SET 攻击、SLAVEOF 主从复制、Lua 脚本执行、MODULE LOAD |
| PostgreSQL | 5432     | PostgreSQL 14.10 (MD5 认证)   | MD5 密码哈希、SSL 降级探测、启动参数                         |
| POP3       | 1100     | Dovecot                       | USER/PASS 凭据、邮箱枚举、CAPA 探测                          |
| IMAP       | 1430     | Dovecot IMAP4rev1             | LOGIN 凭据、AUTHENTICATE 尝试、邮箱操作                      |
| DNS        | 5353     | TCP DNS 服务器                | 域名查询记录、区域传送（AXFR）攻击检测                       |
| QuestDB    | 8812     | QuestDB 7.3.10 (PG 线协议)    | MD5 凭据、SQL 查询（SELECT/INSERT/CREATE/DROP）              |

---

## 连接生命周期

每个攻击者连接从建立到销毁的完整生命周期如下：

<p align="center">
  <img src="docs/connection_lifecycle.png" alt="HoneyDew 连接生命周期时序图" width="85%">
</p>

> 📁 图表源码：[connection_lifecycle.mmd](docs/connection_lifecycle.mmd) | 🖼️ PNG：[connection_lifecycle.png](docs/connection_lifecycle.png)

---

## 有限状态机

HoneyDew 对 HTTP 和 SSH 协议实现了有限状态机（FSM）驱动的交互逻辑。

### HTTP 状态机

HTTP 蜜罐通过 FSM 控制请求处理流程，模拟一个包含管理面板登录表单和故意泄露数据库连接信息的 Apache 服务器。

<p align="center">
  <img src="docs/http_fsm.png" alt="HoneyDew HTTP 状态机图" width="70%">
</p>

> 📁 图表源码：[http_fsm.mmd](docs/http_fsm.mmd) | 🖼️ PNG：[http_fsm.png](docs/http_fsm.png)

HTTP 响应中故意包含以下诱饵信息：

- 服务器标识：`Apache/2.4.29 (Ubuntu)`
- PHP 版本：`PHP/7.2.10`
- HTML 注释中的数据库连接串：`mysql://root:root@localhost:3306/admin`
- 管理员登录表单

### SSH 状态机

SSH 蜜罐基于 libssh 实现完整的 SSH 协议交互，包括真实的密钥交换（KEX）、密码认证和伪终端 Shell 会话。

<p align="center">
  <img src="docs/ssh_fsm.png" alt="HoneyDew SSH 状态机图" width="75%">
</p>

> 📁 图表源码：[ssh_fsm.mmd](docs/ssh_fsm.mmd) | 🖼️ PNG：[ssh_fsm.png](docs/ssh_fsm.png)

SSH Shell 环境模拟 Ubuntu 22.04.3 LTS 系统，支持以下伪造命令响应：

| 命令                   | 响应                                    |
| ---------------------- | --------------------------------------- |
| `whoami`               | `root`                                  |
| `id`                   | `uid=0(root) gid=0(root)`               |
| `uname`                | `Linux honeydew 5.15.0-91-generic`      |
| `ls`                   | 包含 `.bash_history`、`.ssh` 等诱饵文件 |
| `cat /etc/passwd`      | 伪造的用户列表                          |
| `ps`                   | 伪造的进程列表                          |
| `ifconfig` / `ip addr` | 伪造的网络接口信息                      |

---

## 日志系统

HoneyDew 的日志系统支持五个日志级别和两种输出模式，通过 `pthread_mutex` 保证线程安全。

### 日志级别

| 级别    | 中文标识 | 英文标识 | 终端颜色 | 用途                   |
| ------- | -------- | -------- | -------- | ---------------------- |
| VERBOSE | 详细     | VERBOSE  | 紫色     | 最详细的调试信息       |
| DEBUG   | 调试     | DEBUG    | 青色     | 开发调试信息           |
| INFO    | 信息     | INFO     | 绿色     | 常规运行信息           |
| WARN    | 警告     | WARN     | 黄色     | 攻击行为捕获、异常情况 |
| ERROR   | 错误     | ERROR    | 红色     | 系统错误、严重异常     |

### 终端彩色模式（默认）

输出到 `stderr`，带有 ANSI 颜色编码和时间戳：

```
[2026-07-07 14:23:01.234] [信息] [蜜罐] 正在启动 HoneyDew v1.0.0
[2026-07-07 14:23:01.235] [信息] [蜜罐] 共 12 个服务待启动，最大连接数 100
[2026-07-07 14:23:01.240] [信息] [蜜罐] 端口 9090 已启动监听
[2026-07-07 14:23:01.241] [信息] [蜜罐] 端口 2222 已启动监听
[2026-07-07 14:23:15.892] [警告] [SSH蜜罐] 捕获凭据: 用户="root" 密码="123456" 来自 192.168.1.100:54321
[2026-07-07 14:23:16.001] [警告] [SSH蜜罐] 执行命令: "whoami" 来自 192.168.1.100:54321
```

### CloudWatch JSON 模式

启用后输出到 `stdout`，生成结构化 JSON 日志，适合接入 AWS CloudWatch、ELK Stack 等日志聚合平台：

```json
{
  "timestamp": "2026-07-07T14:23:01.234",
  "level": "WARN",
  "level_cn": "警告",
  "application": "HoneyDew",
  "version": "1.0.0",
  "hostname": "honeypot-01",
  "pid": 12345,
  "tid": 140234567890,
  "message": "[SSH蜜罐] 捕获凭据: 用户=\"root\" 密码=\"123456\" 来自 192.168.1.100:54321"
}
```

### 文件日志

可通过 `utilities_enable_file_logging()` 启用文件日志，以追加模式写入指定文件：

```
[2026-07-07T14:23:01.234] [WARN] [SSH蜜罐] 捕获凭据: 用户="root" 密码="123456" 来自 192.168.1.100:54321
```

---

## 审计追踪系统

审计追踪系统独立于日志系统，专门用于记录安全事件，采用环形缓冲区和异步刷写线程设计，确保高吞吐量下不阻塞协议处理线程。

### 事件类型

| 事件类型                    | 中文描述 | 严重性 |
| --------------------------- | -------- | ------ |
| AUDIT_EVENT_CONNECTION      | 连接建立 | 低     |
| AUDIT_EVENT_DISCONNECTION   | 连接断开 | 低     |
| AUDIT_EVENT_AUTH_ATTEMPT    | 认证尝试 | 中     |
| AUDIT_EVENT_AUTH_SUCCESS    | 认证成功 | 高     |
| AUDIT_EVENT_AUTH_FAILURE    | 认证失败 | 中     |
| AUDIT_EVENT_COMMAND         | 命令执行 | 高     |
| AUDIT_EVENT_FILE_ACCESS     | 文件访问 | 高     |
| AUDIT_EVENT_FILE_MODIFY     | 文件修改 | 高     |
| AUDIT_EVENT_DATA_EXFIL      | 数据外泄 | 严重   |
| AUDIT_EVENT_SCAN_PROBE      | 扫描探测 | 中     |
| AUDIT_EVENT_EXPLOIT_ATTEMPT | 漏洞利用 | 严重   |
| AUDIT_EVENT_PROTOCOL_ERROR  | 协议错误 | 低     |

### 严重性级别

| 级别     | 中文 | 说明                         |
| -------- | ---- | ---------------------------- |
| LOW      | 低   | 常规连接事件                 |
| MEDIUM   | 中   | 认证失败、扫描探测           |
| HIGH     | 高   | 认证成功、命令执行、文件操作 |
| CRITICAL | 严重 | 漏洞利用尝试、数据外泄       |

### 审计管道架构

<p align="center">
  <img src="docs/audit_pipeline.png" alt="HoneyDew 审计管道架构图" width="90%">
</p>

> 📁 图表源码：[audit_pipeline.mmd](docs/audit_pipeline.mmd) | 🖼️ PNG：[audit_pipeline.png](docs/audit_pipeline.png)

### 审计日志格式

```
[2026-07-07 14:23:15] SEQ=42 严重性=中 协议=SSH 事件=认证失败 来源=192.168.1.100:54321 会话=ssh_8_1720354995_123456789 用户=root 详情=密码="123456"
[2026-07-07 14:23:16] SEQ=43 严重性=高 协议=SSH 事件=命令执行 来源=192.168.1.100:54321 会话=ssh_8_1720354995_123456789 用户=- 详情=命令="whoami"
```

---

## 项目结构

```
HoneyDew/
├── main.c                              # 主入口：初始化、监听线程创建、信号处理
├── makefile                            # 构建脚本：编译、链接、运行、清理
├── README.md                           # 项目文档
├── docs/                               # 图表文档目录
│   ├── system_architecture.mmd         # 系统架构图（Mermaid 源码）
│   ├── system_architecture.png         # 系统架构图（PNG 渲染）
│   ├── connection_lifecycle.mmd        # 连接生命周期图（Mermaid 源码）
│   ├── connection_lifecycle.png        # 连接生命周期图（PNG 渲染）
│   ├── http_fsm.mmd                    # HTTP 状态机图（Mermaid 源码）
│   ├── http_fsm.png                    # HTTP 状态机图（PNG 渲染）
│   ├── ssh_fsm.mmd                     # SSH 状态机图（Mermaid 源码）
│   ├── ssh_fsm.png                     # SSH 状态机图（PNG 渲染）
│   ├── audit_pipeline.mmd              # 审计管道架构图（Mermaid 源码）
│   ├── audit_pipeline.png              # 审计管道架构图（PNG 渲染）
│   └── generate_png.py                 # Mermaid 转 PNG 生成脚本
├── include/
│   ├── config.h                        # 全局配置：日志路径、SSH 密钥路径、最大连接数
│   ├── connection.h                    # 连接结构体定义：套接字、IP、端口、协议、状态、缓冲区
│   ├── session.h                       # 会话表：哈希表管理、连接创建/销毁/追加数据
│   ├── state.h                         # 状态枚举：NO_STATE、IDLE、RUNNING、STOPPED、PANIC
│   ├── dispatcher.h                    # 服务分发器：协议-端口-处理函数映射表
│   ├── finite_state.h                  # 有限状态机：HTTP 和 SSH 的状态定义与处理函数
│   ├── logger.h                        # 日志系统：级别、宏、CloudWatch 模式、文件日志
│   └── audit.h                         # 审计追踪：环形缓冲区、事件类型、严重性、刷写线程
├── src/
│   ├── service/
│   │   ├── dispatcher.c                # 服务映射表 service_map[] 和 HTTP 服务入口
│   │   ├── session.c                   # 会话哈希表实现、连接对象生命周期管理
│   │   ├── finite_state.c              # HTTP/SSH 有限状态机实现
│   │   ├── ssh_honeypot.c              # SSH 蜜罐：libssh 集成、KEX、认证、伪终端
│   │   ├── ftp_honeypot.c              # FTP 蜜罐：vsFTPd 仿真、目录列表、文件操作
│   │   ├── telnet_honeypot.c           # Telnet 蜜罐：IAC 协商、BusyBox Shell 仿真
│   │   ├── smtp_honeypot.c             # SMTP 蜜罐：Postfix 仿真、AUTH 解码、邮件捕获
│   │   ├── mysql_honeypot.c            # MySQL 蜜罐：二进制握手协议、COM_QUERY 捕获
│   │   ├── redis_honeypot.c            # Redis 蜜罐：RESP 协议解析、高危命令检测
│   │   ├── postgresql_honeypot.c       # PostgreSQL 蜜罐：线协议、MD5 认证、SSL 降级
│   │   ├── pop3_honeypot.c             # POP3 蜜罐：Dovecot 仿真、USER/PASS 捕获
│   │   ├── imap_honeypot.c             # IMAP 蜜罐：IMAP4rev1 仿真、LOGIN 捕获
│   │   ├── dns_honeypot.c              # DNS 蜜罐：TCP DNS 解析、AXFR 攻击检测
│   │   └── questdb_honeypot.c          # QuestDB 蜜罐：PG 线协议、SQL 查询捕获
│   └── utilities/
│       ├── logger.c                    # 日志实现：双模式输出、JSON 转义、线程安全
│       └── audit.c                     # 审计实现：环形缓冲区、异步刷写、文件轮转
├── audit_logs/                         # 审计日志输出目录（运行时自动创建）
└── ssh_host_rsa_key                    # SSH 主机密钥（运行时自动生成）
```

---

## 编译与运行

### 前置条件

- GCC 编译器（支持 C99 标准）
- libssh 开发库
- POSIX 兼容操作系统（Linux / macOS）

### 安装 libssh

**macOS (Homebrew):**

```bash
brew install libssh
```

**Ubuntu / Debian:**

```bash
sudo apt-get install libssh-dev
```

### 编译

```bash
# 编译项目
make build

# 编译并运行
make run

# 清理编译产物
make clean
```

### SSH 主机密钥

首次运行时，系统会自动检测 SSH 主机密钥是否存在。若不存在，将自动调用 `ssh-keygen` 生成 2048 位 RSA 密钥：

```
[信息] [蜜罐] SSH 主机密钥不存在，正在自动生成: ssh_host_rsa_key
[信息] [蜜罐] SSH 主机密钥生成成功: ssh_host_rsa_key
```

### 运行输出

```
[信息] [蜜罐] 正在启动 HoneyDew v1.0.0
[信息] [蜜罐] 共 12 个服务待启动，最大连接数 100
[信息] [审计] 审计追踪系统已启动 (缓冲区=4096 条记录)
[信息] [蜜罐] 端口 9090 已启动监听
[信息] [蜜罐] 端口 2222 已启动监听
[信息] [蜜罐] 端口 2121 已启动监听
[信息] [蜜罐] 端口 2323 已启动监听
[信息] [蜜罐] 端口 2525 已启动监听
[信息] [蜜罐] 端口 3306 已启动监听
[信息] [蜜罐] 端口 6379 已启动监听
[信息] [蜜罐] 端口 5432 已启动监听
[信息] [蜜罐] 端口 1100 已启动监听
[信息] [蜜罐] 端口 1430 已启动监听
[信息] [蜜罐] 端口 5353 已启动监听
[信息] [蜜罐] 端口 8812 已启动监听
```

---

## 攻击模拟指南

以下为每个协议的测试命令、攻击者视角和蜜罐日志记录。

### HTTP (端口 9090)

**测试命令：**

```bash
curl http://localhost:9090/
```

**攻击者看到的响应：**

```html
HTTP/1.1 200 OK Server: Apache/2.4.29 (Ubuntu) X-Powered-By: PHP/7.2.10

<!DOCTYPE html>
<html>
  <head>
    <title>Admin Panel</title>
  </head>
  <body>
    <h1>Welcome to Admin Dashboard</h1>
    <!-- DB: mysql://root:root@localhost:3306/admin -->
    <form action="/login" method="POST">
      <input name="username" placeholder="admin" />
      <input name="password" type="password" />
      <button>Login</button>
    </form>
  </body>
</html>
```

**蜜罐日志：**

```
[信息] [HTTP蜜罐] 新会话建立: 127.0.0.1:54321 (套接字=8)
[调试] [HTTP蜜罐] 收到指令: "GET / HTTP/1.1" (套接字=8)
[信息] [HTTP蜜罐] 会话已关闭 (套接字=8)
```

### SSH (端口 2222)

**测试命令：**

```bash
ssh -o StrictHostKeyChecking=no -p 2222 root@localhost
```

**攻击者看到的交互：**

```
root@localhost's password: ******
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

Last login: Sun Jul  6 12:45:33 2026 from 203.0.113.42
root@honeydew:~# whoami
root
root@honeydew:~# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**蜜罐日志：**

```
[信息] [SSH蜜罐] 新会话建立: 127.0.0.1:54322 (套接字=9)
[信息] [SSH蜜罐] 密钥交换成功: 127.0.0.1:54322
[警告] [SSH蜜罐] 捕获凭据: 用户="root" 密码="123456" 来自 127.0.0.1:54322
[警告] [SSH蜜罐] 攻击者已"登录": 127.0.0.1:54322
[警告] [SSH蜜罐] 执行命令: "whoami" 来自 127.0.0.1:54322
[警告] [SSH蜜罐] 执行命令: "cat /etc/passwd" 来自 127.0.0.1:54322
```

### FTP (端口 2121)

**测试命令：**

```bash
ftp localhost 2121
# 或使用命令行
curl ftp://localhost:2121/ --user admin:password
```

**攻击者看到的交互：**

```
220 (vsFTPd 3.0.3)
USER admin
331 Please specify the password.
PASS password
230 Login successful.
LIST
150 Here comes the directory listing.
-rw-r--r--  1 www-data www-data  2048576 Jul 04 22:15 backup.sql
-rw-------  1 root     root          487 Jun 15 09:44 .htpasswd
-rw-r--r--  1 www-data www-data     3214 Jul 01 16:33 wp-config.php
-rw-r--r--  1 www-data www-data      741 Jun 20 11:22 .env
226 Directory send OK.
```

**蜜罐日志：**

```
[信息] [FTP蜜罐] 新连接建立: 127.0.0.1:54323 (套接字=10)
[警告] [FTP蜜罐] 收到用户名: "admin" 来自 127.0.0.1:54323
[警告] [FTP蜜罐] 捕获凭据: 用户="admin" 密码="password" 来自 127.0.0.1:54323 (第1次尝试)
[警告] [FTP蜜罐] 目录列表请求: "." 来自 127.0.0.1:54323
```

### Telnet (端口 2323)

**测试命令：**

```bash
telnet localhost 2323
```

**攻击者看到的交互：**

```
Ubuntu 22.04.3 LTS
honeydew login: admin
Password: ******

BusyBox v1.35.0 (Ubuntu 1:1.35.0-4ubuntu1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

root@honeydew:~# id
uid=0(root) gid=0(root) groups=0(root)
root@honeydew:~# uname -a
Linux honeydew 5.15.0-91-generic #101-Ubuntu SMP x86_64
```

**蜜罐日志：**

```
[信息] [Telnet蜜罐] 新会话建立: 127.0.0.1:54324 (套接字=11)
[警告] [Telnet蜜罐] 捕获凭据: 用户="admin" 密码="password" 来自 127.0.0.1:54324
[警告] [Telnet蜜罐] 攻击者已"登录": 127.0.0.1:54324
[警告] [Telnet蜜罐] 执行命令: "id" 来自 127.0.0.1:54324
```

### SMTP (端口 2525)

**测试命令：**

```bash
# 使用 swaks 工具
swaks --to victim@example.com --from attacker@evil.com --server localhost --port 2525 --auth-user admin --auth-password secret

# 或使用 telnet
telnet localhost 2525
EHLO evil.com
AUTH LOGIN
```

**攻击者看到的交互：**

```
220 mail.honeydew.local ESMTP Postfix (Ubuntu)
250-mail.honeydew.local
250-SIZE 10240000
250-AUTH PLAIN LOGIN
250 OK
```

**蜜罐日志：**

```
[信息] [SMTP蜜罐] 新会话建立: 127.0.0.1:54325 (套接字=12)
[警告] [SMTP蜜罐] 客户端标识: "evil.com" 来自 127.0.0.1:54325
[警告] [SMTP蜜罐] AUTH LOGIN 用户名(base64): "YWRtaW4=" 来自 127.0.0.1:54325
[警告] [SMTP蜜罐] 捕获凭据: 用户="admin" 密码="secret" 来自 127.0.0.1:54325
```

### MySQL (端口 3306)

**测试命令：**

```bash
mysql -h 127.0.0.1 -P 3306 -u root -p
```

**攻击者看到的响应：**

```
ERROR 1045 (28000): Access denied for user 'root'@'127.0.0.1' (using password: YES)
```

**蜜罐日志：**

```
[信息] [MySQL蜜罐] 新连接建立: 127.0.0.1:54326 (套接字=13)
[调试] [MySQL蜜罐] 握手包已发送 (78 字节): 127.0.0.1:54326
[警告] [MySQL蜜罐] 捕获登录尝试: 用户="root" 来自 127.0.0.1:54326
[信息] [MySQL蜜罐] 会话已关闭: 127.0.0.1:54326
```

### Redis (端口 6379)

**测试命令：**

```bash
redis-cli -h 127.0.0.1 -p 6379
```

**攻击者看到的交互：**

```
127.0.0.1:6379> INFO
# Server
redis_version:6.2.6
...
127.0.0.1:6379> KEYS *
1) "session:abc123"
2) "users:admin"
3) "tokens:refresh_key"
4) "api_keys:production"
127.0.0.1:6379> CONFIG SET dir /var/www/html
OK
```

**蜜罐日志：**

```
[信息] [Redis蜜罐] 新连接建立: 127.0.0.1:54327 (套接字=14)
[警告] [Redis蜜罐] 收到命令: "INFO" 来自 127.0.0.1:54327
[警告] [Redis蜜罐] 收到命令: "KEYS *" 来自 127.0.0.1:54327
[警告] [Redis蜜罐] KEYS 扫描: 模式="*" 来自 127.0.0.1:54327
[警告] [Redis蜜罐] CONFIG SET 攻击检测: 键="dir" 值="/var/www/html" 来自 127.0.0.1:54327
```

### PostgreSQL (端口 5432)

**测试命令：**

```bash
psql -h 127.0.0.1 -p 5432 -U postgres
```

**攻击者看到的响应：**

```
psql: error: connection to server at "127.0.0.1", port 5432 failed:
FATAL:  password authentication failed for user "postgres"
```

**蜜罐日志：**

```
[信息] [PostgreSQL蜜罐] 新连接建立: 127.0.0.1:54328 (套接字=15)
[信息] [PostgreSQL蜜罐] 启动参数: 用户="postgres" 来自 127.0.0.1:54328
[警告] [PostgreSQL蜜罐] 捕获认证凭据: 用户="postgres" MD5哈希="md5abc123..." 来自 127.0.0.1:54328
```

### POP3 (端口 1100)

**测试命令：**

```bash
telnet localhost 1100
USER admin@example.com
PASS secret123
```

**攻击者看到的交互：**

```
+OK Dovecot ready.
+OK
-ERR Authentication failed.
```

**蜜罐日志：**

```
[信息] [POP3蜜罐] 新连接建立: 127.0.0.1:54329 (套接字=16)
[信息] [POP3蜜罐] 用户名: "admin@example.com" 来自 127.0.0.1:54329
[警告] [POP3蜜罐] 捕获凭据: 用户="admin@example.com" 密码="secret123" 来自 127.0.0.1:54329
```

### IMAP (端口 1430)

**测试命令：**

```bash
telnet localhost 1430
a001 LOGIN admin@example.com password123
```

**攻击者看到的交互：**

```
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS AUTH=PLAIN] Dovecot ready.
a001 NO [AUTHENTICATIONFAILED] Authentication failed.
```

**蜜罐日志：**

```
[信息] [IMAP蜜罐] 新连接建立: 127.0.0.1:54330 (套接字=17)
[警告] [IMAP蜜罐] 捕获凭据: 用户="admin@example.com" 密码="password123" 来自 127.0.0.1:54330
```

### DNS (端口 5353)

**测试命令：**

```bash
# A 记录查询
dig @127.0.0.1 -p 5353 +tcp example.com

# 区域传送攻击测试
dig @127.0.0.1 -p 5353 +tcp example.com AXFR
```

**攻击者看到的响应（A 记录）：**

```
;; ANSWER SECTION:
example.com.    300    IN    A    10.0.2.15
```

**蜜罐日志：**

```
[信息] [DNS蜜罐] 新连接建立: 127.0.0.1:54331 (套接字=18)
[警告] [DNS蜜罐] 查询域名: "example.com" (类型=1) 来自 127.0.0.1:54331
[信息] [DNS蜜罐] 返回伪造 A 记录 10.0.2.15: "example.com" -> 127.0.0.1:54331
```

**AXFR 攻击检测日志：**

```
[错误] [DNS蜜罐] 检测到区域传送 (AXFR) 攻击: 域名="example.com" 来自 192.168.1.100:54331
```

### QuestDB (端口 8812)

**测试命令：**

```bash
psql -h 127.0.0.1 -p 8812 -U admin
# 登录后执行 SQL
SELECT * FROM trades;
```

**攻击者看到的交互：**

```
Password for user admin: ******
psql (14.10)
Type "help" for help.

admin=> SELECT * FROM trades;
(0 rows)
```

**蜜罐日志：**

```
[信息] [QuestDB蜜罐] 新连接建立: 127.0.0.1:54332 (套接字=19)
[信息] [QuestDB蜜罐] 启动参数: 用户="admin" 来自 127.0.0.1:54332
[警告] [QuestDB蜜罐] 捕获认证凭据: 用户="admin" MD5哈希="md5..." 来自 127.0.0.1:54332
[警告] [QuestDB蜜罐] SQL 查询: "SELECT * FROM trades" 来自 127.0.0.1:54332
```

---

## 安全最佳实践

### 部署建议

1. **以非 root 用户运行** -- HoneyDew 使用高端口号（均 > 1024），无需 root 权限。创建专用用户运行蜜罐服务：

   ```bash
   useradd -r -s /sbin/nologin honeydew
   su -s /bin/bash honeydew -c "./蜜罐"
   ```

2. **使用高端口映射** -- 若需在标准端口（如 22、80）上运行，使用 iptables 端口转发而非直接绑定：

   ```bash
   iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
   iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9090
   iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
   ```

3. **防火墙隔离** -- 蜜罐主机应部署在隔离网段，限制其对内网的访问：

   ```bash
   # 允许入站连接到蜜罐端口
   iptables -A INPUT -p tcp -m multiport --dports 9090,2222,2121,2323,2525,3306,6379,5432,1100,1430,5353,8812 -j ACCEPT
   # 禁止蜜罐主机发起对外连接
   iptables -A OUTPUT -m owner --uid-owner honeydew -j DROP
   ```

4. **日志轮转** -- 配置 logrotate 管理审计日志文件：

   ```
   /path/to/HoneyDew/audit_logs/*.log {
       daily
       rotate 30
       compress
       missingok
       notifempty
   }
   ```

5. **监控告警** -- 对高严重性审计事件配置实时告警，特别关注：

   - `AUDIT_EVENT_AUTH_SUCCESS` -- 攻击者成功"登录"
   - `AUDIT_EVENT_EXPLOIT_ATTEMPT` -- 漏洞利用尝试（如 DNS AXFR）
   - `AUDIT_EVENT_FILE_MODIFY` -- 文件修改尝试
   - Redis `CONFIG SET`、`SLAVEOF`、`MODULE LOAD` 等高危命令

6. **定期更新** -- 保持蜜罐服务的版本号和横幅信息与当前主流版本一致，避免被攻击者通过过时的版本号识别为蜜罐。

---

## 技术实现细节

### 线程模型

HoneyDew 采用 **每连接一线程（thread-per-connection）** 模型，通过自定义信号量 `conn_semaphore_t` 限制最大并发连接数。信号量基于 `pthread_mutex` 和 `pthread_cond` 实现：

- `conn_semaphore_acquire()` -- 当并发连接数达到上限时阻塞等待
- `conn_semaphore_release()` -- 连接关闭后释放信号量，唤醒等待线程
- 默认最大并发连接数为 100，可通过 `config_t.max_connections` 配置

### 线程安全

- 会话哈希表 `session_table_t` 使用 `pthread_mutex` 保护所有读写操作
- 每个 `connection_t` 对象拥有独立的 `pthread_mutex`，保护 TCP 重组缓冲区和状态字段
- 日志系统使用全局 `pthread_mutex` 序列化所有日志输出
- 审计系统的环形缓冲区通过 `pthread_mutex` + `pthread_cond` 实现生产者-消费者模式

### 环形缓冲区

审计系统使用固定大小（4096 条记录）的环形缓冲区：

- 协议处理线程作为生产者，通过 `audit_record_event()` 写入记录
- 独立的刷写线程作为消费者，每秒唤醒一次或被 `pthread_cond_signal` 唤醒
- 缓冲区满时丢弃新记录并递增 `dropped_records` 计数器
- 关闭时刷写线程会排空缓冲区中的所有剩余记录

### MySQL 二进制协议

MySQL 蜜罐实现了完整的 MySQL 线协议握手流程：

- 构建符合规范的 `HandshakeV10` 问候包，包含协议版本、服务器版本、连接 ID、认证盐值、能力标志
- 解析客户端 `HandshakeResponse41` 数据包，提取用户名
- 返回标准的 `ERR_Packet`（错误码 1045，SQLSTATE 28000）
- 继续监听后续数据，捕获 `COM_QUERY`（0x03）命令中的 SQL 查询

### PostgreSQL 线协议

PostgreSQL 蜜罐实现了 v3 线协议的认证流程：

- 处理 `SSLRequest`（协议号 80877103），返回 `N` 拒绝 SSL
- 解析 `StartupMessage`，提取键值对参数中的 `user` 字段
- 发送 `AuthenticationMD5Password` 消息，附带随机 4 字节盐值
- 解析客户端 `PasswordMessage`，捕获 MD5 哈希
- 返回 `ErrorResponse`（FATAL, 28P01）拒绝认证

### libssh 集成

SSH 蜜罐通过 libssh 库实现真实的 SSH 协议交互：

- 使用 `ssh_bind` 绑定 RSA 主机密钥
- `ssh_handle_key_exchange()` 执行完整的密钥交换（Diffie-Hellman）
- 通过 `ssh_message_get()` 循环处理认证请求，捕获用户名和密码
- 第 3 次认证尝试后允许登录，最大化凭据收集
- 建立 SSH 通道和伪终端，提供交互式 Shell 环境
- 逐字符处理输入，支持退格、Ctrl+C 等终端控制字符

### SMTP Base64 解码

SMTP 蜜罐实现了完整的 Base64 解码器，用于解析 AUTH PLAIN 和 AUTH LOGIN 中的凭据：

- AUTH LOGIN：分两步接收 Base64 编码的用户名和密码（挑战码 `VXNlcm5hbWU6` = "Username:"，`UGFzc3dvcmQ6` = "Password:"）
- AUTH PLAIN：解析 `\0authzid\0username\0password` 格式的 Base64 编码数据

### DNS 数据包解析

DNS 蜜罐实现了 TCP DNS 消息的完整解析：

- 自动检测 TCP 帧头（2 字节长度前缀）
- 解析 DNS 头部（ID、QD 计数）
- 递归解析域名标签（支持压缩指针 0xC0）
- 提取查询类型（QTYPE），对 A 记录返回伪造 IP（10.0.2.15），对 AXFR 返回 REFUSED
- 对其他查询类型返回 SERVFAIL

### Redis RESP 协议解析

Redis 蜜罐实现了双模式命令解析：

- **RESP 数组格式**：解析 `*N\r\n$len\r\ndata\r\n...` 格式的标准 RESP 协议
- **内联命令格式**：解析空格分隔的简单命令字符串
- 支持流式解析，通过接收缓冲区累积数据并循环提取完整命令
- 对 30+ 种 Redis 命令提供仿真响应

### Telnet IAC 处理

Telnet 蜜罐实现了 IAC（Interpret As Command）协商字节的剥离：

- 识别并跳过 3 字节 IAC 命令（WILL/WONT/DO/DONT + 选项）
- 处理子协商序列（IAC SB ... IAC SE）
- 处理转义的 0xFF 字面量
- 使用 IAC WILL ECHO / IAC WONT ECHO 控制密码输入回显

---

## 依赖项

| 依赖                    | 版本要求     | 用途                                     |
| ----------------------- | ------------ | ---------------------------------------- |
| GCC                     | 支持 C99     | 编译器                                   |
| libssh                  | >= 0.9       | SSH 协议实现（密钥交换、认证、通道管理） |
| POSIX Threads (pthread) | POSIX.1-2001 | 多线程并发处理                           |
| 标准 C 库               | C99          | 套接字、内存管理、字符串处理、时间函数   |

---

## 许可证

本项目采用 MIT 许可证发布。详见 [LICENSE](LICENSE) 文件。

```
MIT License

Copyright (c) 2026 钟智强

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
