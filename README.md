写在最前主力机请勿使用，大厂云请勿使用。推荐各种抗投诉VPS。家宽请勿一天多次使用。
# asn123

从 **ASN 编号** 或 **手动 CIDR** 出发，自动完成 IP 段拉取 → **多端口扫描** → Cloudflare 反代节点检测，输出可用 CF 节点 CSV。无测速，纯扫描。

---

## 目录

- [快速开始](#快速开始)
- [安装](#安装)
  - [Linux / macOS](#linux--macos)
  - [Windows（WSL2）](#windowswsl2)
- [使用](#使用)
  - [命令行模式](#命令行模式)
  - [交互模式](#交互模式)
  - [多端口扫描](#多端口扫描)
- [工作流程](#工作流程)
- [输出格式](#输出格式)
- [硬件自适应](#硬件自适应)
- [依赖](#依赖)
- [卸载](#卸载)

---

## 快速开始

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/snll66/asn123/main/install.sh | bash
```

**Windows**（需先装 WSL2）
```powershell
# PowerShell 管理员模式，装完重启
wsl --install

# 重启后进 Ubuntu 终端
curl -fsSL https://raw.githubusercontent.com/snll66/asn123/main/install.sh | bash
```

---

## 安装

### Linux / macOS

一条命令安装所有依赖（masscan、prips）并注册全局命令：

```bash
curl -fsSL https://raw.githubusercontent.com/snll66/asn123/main/install.sh | bash
```

安装完成后，在任意目录输入 `asn123` 即可启动。

> **手动安装**：如果不想用一键脚本，可以 clone 仓库后手动运行 `python3 run.py`。需自行安装 masscan 和 prips。

### Windows（WSL2）

Windows 10/11 自带 WSL2，装上就能用 Linux 环境：

**第一步：安装 WSL2**

PowerShell 管理员模式运行：

```powershell
wsl --install
```

系统会自动安装 Ubuntu + WSL2 内核。完成后**重启电脑**。

**第二步：安装 asn123**

重启后开始菜单会多一个「Ubuntu」应用，打开它，输入：

```bash
curl -fsSL https://raw.githubusercontent.com/snll66/asn123/main/install.sh | bash
```

> WSL2 默认使用桥接模式，正式测试时需调整为 NAT 模式才能正常使用 masscan。

---

## 使用

### 命令行模式

直接指定 ASN 或 CIDR 启动扫描：

```bash
# ASN 模式
asn123 AS209242            # 单个 ASN
asn123 AS209242,AS3214     # 多个 ASN（逗号分隔）

# CIDR 模式
asn123 103.21.244.0/24     # 单个 CIDR
asn123 1.1.1.0/24,8.8.8.0/24  # 多个 CIDR

# 混合模式
asn123 AS209242,103.21.244.0/24  # ASN + CIDR 同时
```

> 手动运行时用 `python3 run.py` 代替 `asn123`。支持 ASN、CIDR、混合输入。

### 多端口扫描

默认扫描 `ports.txt` 中定义的端口（443, 8443, 2053, 2083, 2087, 2096）。可通过 `-p` 参数自定义：

```bash
# 扫描单个端口
asn123 AS209242 -p 443

# 扫描多个端口（逗号分隔）
asn123 AS209242 -p 443,8443,2053,2083,2087,2096

# 扫描端口范围
asn123 AS209242 -p 1-1000

# 混合端口
asn123 AS209242 -p 80,443,8000-9000
```

交互模式下也可在提示时输入自定义端口。

### 后台运行（SSH 断线不杀）

长扫描（5-30分钟），担心 SSH 断线可以用 `screen`：

```bash
# 安装 screen（仅首次）
apt install -y screen

# 启动 screen 会话
screen -S scan

# 在里面正常跑 asn123 AS209242
# 按 Ctrl+A 再按 D 断开（进程继续跑）
```

下次 SSH 连回来，`screen -r scan` 即可恢复查看。

> 如果记不清会话名，`screen -ls` 列出所有会话。

### 交互模式

不带参数运行，进入交互提示：

```bash
asn123
```

```
  硬件: 4核 2048MB → masscan 4000pps ...

  本机公网 IP: 1.2.3.4
  地区: Tokyo, JP  运营商: xxx

  输入 ASN 或 CIDR (逗号分隔): _
  默认端口: 443,8443,2053,2083,2087,2096
  回车使用默认，或输入自定义端口: _
```

输入 ASN 或 CIDR 后自动开始扫描。完成后自动提供 CSV 下载链接。

---

## 工作流程

```
用户输入 ASN
    │
    ▼
┌──────────────────────┐
│ 1. ASN → CIDR        │  RIPEStat API 查询该 ASN 广播的所有 IPv4 前缀
├──────────────────────┤
│ 2. masscan 多端口扫描 │  高速 SYN 扫描（支持多端口，CIDR 直接传入）
├──────────────────────┤
│ 3. cf-scanner 粗筛   │  TLS 握手检测，命中 Cloudflare 反代节点
├──────────────────────┤
│ 4. API 精筛          │  api.090227.xyz/check 二次验证（TLS + 数据中心 + 地区）
├──────────────────────┤
│ 5. 输出结果           │  生成 CSV + 临时 HTTP 下载服务
└──────────────────────┘
```

> 无测速步骤，扫描完成后直接输出结果。

---

## 输出格式

运行完成后生成 CSV 文件并启动临时下载服务：

```
📥 下载链接 (临时, 按回车关闭):
http://1.2.3.4:8899/output_AS209242_20260617_120000.csv

结果: 42 条 → output_AS209242_20260617_120000.csv
```

**CSV 列说明：**

| 列 | 说明 | 示例 |
|---|---|---|
| IP地址 | Cloudflare 节点 IP | `162.159.192.1` |
| 端口 | TLS 端口 | `443` |
| TLS | TLS 版本 | `TRUE` |
| 数据中心 | CF 数据中心代号 | `HKG` |
| 地区 | 国家/地区代码 | `HK` |
| 城市 | 城市名 | `Hong Kong` |
| 网络延迟 | TCP 延迟 (ms) | `42` |
| 下载速度 | CF 下载带宽 (Mbps) | `5.12` |
| ASN | 源 ASN 编号 | `AS209242` |

> 下载链接自动检测本机 IP，同时显示局域网和公网地址（公网不同时）。按 **回车** 关闭下载服务。

---

## 硬件自适应

启动时自动探测网卡实际发包能力（取最优速率的 80%），同时根据 CPU 核数和内存调整并发：

| 硬件配置 | masscan 速率 | cf-scanner 并发 | API 并发 |
|---|---|---|---|
| 任何配置 | 自动实测网卡上限×80% | 200~500 | 8~32 |

> 速率探测耗时约 30 秒，使用前 50 个 CIDR 样本以递增速率测试，找到网卡瓶颈后稳定运行。探测失败时回退 CPU×1000 估算。cf-scanner 并发最低 200，最高 500。

---

## 依赖

| 工具 | 用途 | 安装方式 |
|---|---|---|
| [masscan](https://github.com/robertdavidgraham/masscan) | 高速端口扫描 | `apt install masscan` 或源码编译 |
| cf-scanner | CF 反代节点检测 | 内置，自动编译 |
| [RIPEStat API](https://stat.ripe.net/) | ASN → CIDR | 免费公开，无需注册 |

> `install.sh` 自动处理所有依赖。

### 不支持的环境

masscan 依赖 **raw socket**（CAP_NET_RAW），以下环境有限制：

- ❌ NAT 容器（独角鲸/小鲸等，缺少 CAP_NET_RAW）
- ❌ OpenVZ / LXC 未开启特权模式
- ⚠️ WSL2 需切换为 NAT 网络模式（默认桥接不支持 raw socket）

> 换到 KVM VPS 或物理机即可正常使用。

---

## 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/snll66/asn123/main/uninstall.sh | bash
```

这会删除 `asn123` 命令和 `~/asn123` 目录。

---

## 鸣谢

- [**cmliu**](https://github.com/cmliu) — 提供 [CF-Workers-CheckProxyIP](https://github.com/cmliu/CF-Workers-CheckProxyIP) 公共 API 接口 (`api.090227.xyz/check`)，用于节点二次验证。
