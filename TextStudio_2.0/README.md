# TextStudio

> 面向大型日志 / 文本文件的桌面查看与标注工具，支持 SSH/SFTP 远程浏览。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![平台](https://img.shields.io/badge/平台-Linux%20%7C%20Windows-green.svg)]()
[![许可证](https://img.shields.io/badge/许可证-MIT-orange.svg)](LICENSE)

TextStudio 是一款基于 Python 和 tkinter 的轻量级桌面应用，专为流畅浏览和标注大型 `.log` / `.txt` 文件而设计——即使文件达到数百 MB 也不会卡顿。

它还支持通过 SSH/SFTP 连接远程 Linux 服务器，你可以像在本地一样浏览远程目录、打开远程日志文件，甚至直接上传 / 下载文件，全部在一个窗口内完成。

**当前版本：2.0**

---

## ✨ 主要特性

### 大文件性能优化
- **虚拟页渲染**——只绘制当前视口可见的行，行号区按实际显示行渲染，不会为整个文件计算排版。
- **字节定位二分搜索**——按行号、字节偏移或标注跳转均使用 `bisect` 在缓存索引上查找，无需扫描整个文件。
- **懒加载行索引**——文本索引按需构建，打开 GB 级日志也能在毫秒内显示首屏。

### 远程文件支持（SSH / SFTP）
- **原生跳板机 / ProxyJump 支持**——两级 SSH 直连，无需手动配置 `ssh -L` 端口转发。
- **远程文件体验接近本地**——首屏仅需约 256 KiB 远程读取；后台预读当前视口附近约 4 MiB，翻页时无需等待网络。
- **SFTP 并行分块读取**——服务器支持 `readv` 时使用流水化分块请求，否则自动退回串行读取。
- **远程目录浏览器**——浏览远程文件系统，按名称搜索（支持递归），双击即可打开文件或进入目录；符号链接会自动解析目标。
- **上传与下载**——支持从浏览器拖拽或点击上传本地文件；支持递归下载整个目录。两者均在后台线程执行并显示进度。

### 标注与搜索
- **多标签页**——同时打开多个文件，支持 `Ctrl+W` 或鼠标中键关闭标签。
- **标注与书签**——高亮文本、添加备注，随时跳转回原位置。标注保存在本地 `~/.textstudio/annotations.sqlite3`，不修改服务器原文件。
- **正则搜索**——对当前可见文本执行正则表达式搜索，ERROR / WARN 自动着色。
- **双击选词 → Ctrl+F**——在正文中双击选中单词后按 `Ctrl+F`，搜索框自动填入选中内容。

### 跨平台
- **Linux**——运行 `./run_linux.sh` 即可。
- **Windows**——双击 `run_windows.bat` 从源码启动，或用 `build_windows_exe.bat` 打包为独立 `.exe`。

---

## 📦 安装

### 前置要求

- Python 3.10 或以上版本
- `tkinter`（通常随系统 Python 包一起安装）
- Linux 下需安装 `python3-tk` 和 `python3-venv`

### Linux（Ubuntu / Debian）

```bash
sudo apt update
sudo apt install -y python3 python3-tk python3-venv
```

然后从项目根目录执行：

```bash
chmod +x install_ubuntu.sh run_linux.sh
./install_ubuntu.sh
./run_linux.sh
```

`install_ubuntu.sh` 会在项目目录创建独立的 `.venv`，并安装以下两个第三方依赖：

| 依赖 | 用途 |
|---|---|
| `paramiko` | SSH / SFTP 连接 |
| `tkinterdnd2` | 桌面原生拖放支持 |

安装完成后，后续直接运行：

```bash
./run_linux.sh
```

> 请勿使用 `sudo ./run_linux.sh`。

### Windows

双击 `run_windows.bat` 即可从源码启动（需 Python 3.10+ 且已安装 tkinter）。

如需打包为独立可执行文件：

```cmd
build_windows_exe.bat
```

这会在本地 `.venv` 中安装 PyInstaller，并生成 `dist/TextStudio.exe`。

---

## 🚀 快速开始

```bash
./run_linux.sh
```

或在 Windows 上双击 `run_windows.bat`。

启动后打开空白标签页。将文件拖拽到窗口内，或通过 **文件 → 打开** 加载本地文本 / 日志文件。

---

## 🔌 SSH / SFTP 使用指南

### 直连单跳

如果你的常用命令是：

```bash
ssh test@192.168.1.1
```

在连接对话框中填写：

| 字段 | 值 |
|---|---|
| 主机 | `192.168.1.1` |
| 端口 | `22` |
| 用户 | `test` |
| 密码 / 密钥 | 对应凭证 |

### 两级跳板（ProxyJump）

```bash
ssh test@192.168.1.1   # 跳板机（第一级）
ssh test@192.168.1.10     # 目标机（第二级）
```

在 TextStudio 中填写：

```
目标 SSH（第二级）
  主机：    192.168.1.10
  端口：    22
  用户：    test
  密码/私钥：<test 用户的凭证>

☑ 使用跳板机 / ProxyJump

跳板机 SSH（第一级）
  主机：    192.168.1.1
  端口：    22
  用户：    test
  密码/私钥：<test 用户的凭证>
```

连接链路：

```
TextStudio → test@192.168.1.1 → test@192.168.1.10 → SFTP 文件
```

### 远程目录浏览

连接成功后会弹出远程浏览器窗口。双击目录进入，双击文件在标签页中打开；符号链接会自动解析目标。工具栏的**远程文件**按钮可随时恢复浏览器窗口（已连接时显示活动连接数，如 `远程文件(1)`）。

### 远程目录搜索

浏览器内置搜索栏，默认搜索当前目录；勾选**包含子目录**后递归搜索所有子目录。结果会显示文件所在的相对路径，双击可直接打开或进入，也可从结果中直接下载。最多显示 2000 条结果，超出时在状态栏提示。

---

## ⌨️ 快捷键

| 快捷键 | 功能 |
|---|---|
| `Ctrl+O` | 打开本地文件 |
| `Ctrl+F` | 搜索（自动填入当前选中文本） |
| `Ctrl+W` | 关闭当前标签 |
| `Ctrl+G` | 跳转到指定行号或字节偏移 |
| `Ctrl+D` | 切换自动跟随尾部 |
| `F3` / `Shift+F3` | 下一个 / 上一个匹配项 |
| `Alt+↑` / `Alt+↓` | 跳转到上一个 / 下一个标注 |

---

## 💾 数据存储

所有本地数据保存在 `~/.textstudio/` 目录下：

| 文件 | 用途 |
|---|---|
| `annotations.sqlite3` | 标注和书签数据 |
| `known_hosts` | SSH 主机密钥（首次连接时自动记录） |
| `remote_connections.json` | 最近连接记录及密码 |

> **安全提示**：`remote_connections.json` 以明文存储 SSH 密码（未加密）。Linux / macOS 下程序会将文件权限设为 `0600`。请在可信的本地账户环境中启用密码保存功能。

远程 SSH 连接在浏览器窗口隐藏后仍保持活跃（发送 keepalive 保活），直到 TextStudio 退出时才统一关闭。

---

## ✅ 自检

```bash
python3 TextStudio.py --self-test
```

自检覆盖以下检查项：

- Python 语法与模块导入验证
- SSH/SFTP 首屏读取模拟
- 后台预读缓存命中验证
- Tkinter GUI 浏览器窗口隐藏 / 恢复行为
- Shell 脚本语法检查
- `.pyz` 归档完整性（CRC 校验）

---

## 🏗️ 项目结构

```
TextStudio.py            — 主程序入口（tkinter GUI、标签管理、文本查看器）
remote_support.py      — SSH/SFTP 会话、远程文件读取、目录浏览器
install_ubuntu.sh      — 创建 .venv 并安装依赖（Linux）
run_linux.sh           — 启动脚本（优先使用 .venv Python）
run_windows.bat        — Windows 启动脚本
build_windows_exe.bat  — PyInstaller 打包脚本（Windows）
requirements.txt       — paramiko（SSH/SFTP）
requirements-dnd.txt   — tkinterdnd2（桌面拖放）
```

本项目仅依赖 tkinter（Python 标准库），外加 `paramiko` 和 `tkinterdnd2` 两个第三方包用于远程连接和拖放功能。

---

## 📄 许可证

MIT 许可证，详见 [LICENSE](LICENSE)。

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request。请确保：

1. 自检通过：`python3 TextStudio.py --self-test`
2. 应用可在 Python 3.10+ 环境下正常启动
3. 新增依赖请先在 Issue 中说明

---

## 🙏 致谢

- [Paramiko](https://paramiko.org/) — SSH2 协议 Python 实现
- [TkinterDnD2](https://github.com/techtonik/tkinterdnd2) — tkinter 跨平台拖放扩展
