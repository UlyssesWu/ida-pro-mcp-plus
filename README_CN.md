# 🔧 ida-pro-mcp-plus

**增强版 IDA Pro MCP 服务器** - 让 AI 助手直接分析二进制文件

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**作者**: oxygen (304914289@qq.com)  
**版本**: 1.0.0  
**仓库**: https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus

---

## ✨ 核心特性

- 🚀 **多实例支持** - 同时分析多个二进制文件，互不干扰
- 🎯 **无需打开 IDA** - 全自动批处理模式，使用 IDA 无头版本 (idat.exe)
- 🔄 **智能缓存** - 自动管理 .i64 数据库，加速后续分析
- 💾 **高效通信** - 共享内存 IPC，处理大数据量无压力
- 📦 **34 个强大工具** - 覆盖静态分析、代码修改、类型系统全方位需求
- 🧩 **模块化架构** - 7 个独立脚本模块，易于维护扩展
- ✅ **100% 测试覆盖** - 完整测试套件，生产环境可用
- 🎨 **一键安装即用** - `pip install` → `ida-mcp-plus --install` → 完成！

## 🆚 为什么选择 ida-pro-mcp-plus？

### 与原版 ida-pro-mcp 对比

| 特性 | ida-pro-mcp | ida-pro-mcp-plus |
|------|-------------|------------------|
| **多实例分析** | ❌ 单实例 | ✅ **支持并行分析** |
| **IDA 界面** | ⚠️ 需要 idalib + GUI | ✅ **无头批处理模式** |
| **智能缓存** | ❌ 无缓存 | ✅ **.i64 智能缓存** |
| **架构设计** | 单体式 | ✅ **模块化 (7模块)** |
| **安装方式** | pip install | ✅ **pip install** |
| **内存操作** | 基础 | ✅ **完整读写补丁** |
| **代码修改** | ❌ | ✅ **汇编补丁、重命名、注释** |
| **栈帧分析** | ❌ | ✅ **栈变量+类型** |
| **类型系统** | ❌ | ✅ **声明、应用、搜索类型** |

### 核心优势

1. **🔥 真正的并行处理**: 同时分析多个二进制文件，无资源冲突
2. **⚡ 闪电般的速度**: 无 GUI 开销，纯批处理执行 + 智能缓存（缓存文件快 10 倍）
3. **🎯 生产级可用**: 智能缓存 + 超时处理 + 错误恢复
4. **🛠️ 功能更强大**: 34 个工具覆盖所有逆向工程需求
5. **📦 安装简单**: `pip install` → `ida-mcp-plus --install` → 完成！

## 📥 安装

### 方法 1：从 GitHub 直接安装（推荐）

```bash
# 从 master 分支直接安装
pip install git+https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git

# 一键配置所有 MCP 客户端
ida-mcp-plus --install
```

**其他安装方式：**

```bash
# 从 ZIP 压缩包安装
pip install https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/archive/refs/heads/master.zip

# 或明确指定分支
pip install git+https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git@master
```

`--install` 安装向导会：
- ✅ 提示输入 IDA Pro 路径（ida.exe 和 idat.exe）
- ✅ 自动检测所有已安装的 MCP 客户端（Cursor、Claude Desktop、VS Code 等）
- ✅ 为每个客户端配置正确的环境变量
- ✅ 提供每个客户端的重启说明

### 方法 2：从源码安装（开发者）

```bash
git clone https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git
cd ida-pro-mcp-plus
pip install -e .
ida-mcp-plus --install
```

---

## 🚀 快速开始

### 第 1 步：安装软件包

```bash
pip install git+https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git
```

**这个命令会：**
- 安装 `ida-pro-mcp-plus` 到 Python 环境
- 创建全局命令 `ida-mcp-plus`（任意位置可用）
- 安装所有依赖（mcp>=0.9.0）

### 第 2 步：配置 MCP 客户端

```bash
ida-mcp-plus --install
```

**交互式向导提示：**
```
🚀 ida-pro-mcp-plus Installer
==================================================

Configure once, use with all AI clients!

Enter path to ida.exe (or ida64):  F:/tools/analyze/ida9.0/ida.exe
Enter path to idat.exe (or idat64): F:/tools/analyze/ida9.0/idat.exe
```

**自动配置这些 MCP 客户端：**
- ✅ **Cursor** (`%APPDATA%\Cursor\User\globalStorage\...`)
- ✅ **Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json`)
- ✅ **Cline**（VS Code 扩展）
- ✅ **Roo Code**（VS Code 扩展）
- ✅ **Windsurf**
- ✅ **Codebuddy Code**
- ✅ **Continue**、**LM Studio** 等更多...

### 第 3 步：重启并验证

1. **重启 MCP 客户端**（关闭并重新打开）
2. **在 AI 聊天中测试**：
   ```
   用户："列出所有 ida-pro-mcp-plus 工具"
   AI：[显示 34 个工具，包括 list_functions、decompile_function 等]
   ```
3. **成功！** 🎉 现在可以通过 AI 聊天分析二进制文件了

### 第 4 步：首次分析

```
用户："分析 C:/samples/malware.exe 这个二进制文件，
      给我看 main 函数的反编译代码"

AI：[自动使用 decompile_function 工具显示伪代码]
```

---

## 验证安装

### Cursor / Cline
在 Cline 面板查看 MCP 服务器是否已连接

### Codebuddy Code
```
Ctrl+Shift+P → /mcp
```
应该看到 `ida-pro-mcp-plus ✔ Connected`

### Claude Desktop
对 Claude 说：
```
你能看到 ida-pro-mcp-plus 的工具吗？
```

如果能看到 34 个工具，说明配置成功！🎉

## 🛠️ 工具列表（34个）

<details>
<summary><b>📊 基础分析（10个工具）</b></summary>

1. **list_functions** - 列出所有函数（支持分页/过滤）
2. **get_function_info** - 获取函数详细信息
3. **disassemble_function** - 反汇编函数
4. **decompile_function** - 反编译为伪代码（F5）
5. **list_strings** - 提取所有字符串
6. **list_imports** - 列出导入函数
7. **xrefs_to** - 查找交叉引用
8. **get_callees** - 获取函数调用关系
9. **read_bytes** - 读取原始字节
10. **ping** - 测试连接

</details>

<details>
<summary><b>🔬 高级分析（7个工具）</b></summary>

11. **basic_blocks** - 基本块 CFG 分析
12. **find_bytes** - 字节模式搜索（支持通配符）
13. **find** - 立即数搜索
14. **export_funcs** - 列出导出函数
15. **callgraph** - 完整调用图（双向）
16. **find_regex** - 正则表达式搜索字符串
17. **lookup_funcs** - 批量查找函数

</details>

<details>
<summary><b>💾 内存操作（7个工具）</b></summary>

18. **list_globals** - 列出全局变量
19. **int_convert** - 数字进制转换
20. **get_int** - 读取类型化整数（i8/u16/i32le/u64be等）
21. **get_string** - 读取字符串
22. **get_global_value** - 读取全局变量值
23. **patch** - 修改内存字节
24. **put_int** - 写入类型化整数

</details>

<details>
<summary><b>✏️ 代码修改（3个工具）</b></summary>

25. **set_comments** - 设置注释
26. **patch_asm** - 汇编指令补丁
27. **rename** - 统一重命名（函数/全局/局部/栈变量）

</details>

<details>
<summary><b>📚 栈帧工具（3个工具）</b></summary>

28. **stack_frame** - 获取栈帧变量
29. **declare_stack** - 声明栈变量类型
30. **delete_stack** - 删除栈变量

</details>

<details>
<summary><b>🏗️ 类型系统（4个工具）</b></summary>

31. **declare_type** - 声明 C 类型到 Local Types
32. **read_struct** - 读取结构体实例
33. **search_structs** - 搜索结构体定义
34. **set_type** - 应用类型到地址

</details>

## 💡 使用示例

### 反编译函数

```
用户：反编译地址 0x140001000 的函数
AI：[使用 decompile_function 工具]
    返回完整的 C 伪代码
```

### 查找字符串

```
用户：找出所有包含 "password" 的字符串
AI：[使用 find_regex 工具]
    返回所有匹配的字符串及地址
```

### 修改代码

```
用户：把地址 0x140001234 的指令改成 nop
AI：[使用 patch_asm 工具]
    成功修改指令
```

### 并行分析

```
用户：同时分析 main.exe 和 helper.dll
AI：[并行使用多个工具]
    同时分析两个二进制文件，互不干扰
```

## 🔧 配置选项

### 必需配置

| 变量 | 说明 | 示例 |
|------|------|------|
| `IDA64_PATH` | IDA Pro 可执行文件 | `C:/Program Files/IDA Pro 9.0/ida.exe` |
| `IDAT64_PATH` | IDA 无头版本 | `C:/Program Files/IDA Pro 9.0/idat.exe` |

### 可选配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `I64_CACHE_DIR` | `.i64_cache` | 数据库缓存目录（相对路径时，与输入二进制同目录解析） |
| `IDA_TIMEOUT` | `120` | 单次 **工具调用** 在 `idat.exe` 中执行脚本的超时（秒） |
| `IDA_BUILD_TIMEOUT` | `1800` | **首次**从二进制生成缓存 `.i64` 时的超时（秒）；大文件（如 `GameAssembly.dll`）可适当调大 |
| `IDA_SKIP_AUTO_WAIT` | *未设置* | 设为 `1`、`true` 或 `yes` 时，默认跳过 `idaapi.auto_wait()`（各工具仍可单独覆盖）。用于自动分析卡死、永不结束的场景 |
| `IDA_SHM_SIZE` | `20971520` | 共享内存大小（20MB） |

### `file_path`：二进制还是已有数据库

各工具的 `file_path` 可以是：

1. **已有 IDA 数据库** — 直接传 `.i64` 或 `.idb` 路径，会按该库打开，不会从 PE 重新建库。
2. **二进制文件** — 传 exe/dll 等路径。会依次查找同目录下的 `<路径>.i64`、`<去扩展名>.i64`，以及对应的 `.idb`；若都不存在，则在二进制所在目录下的 `I64_CACHE_DIR` 中生成 `<文件名>.i64`（若 `I64_CACHE_DIR` 为绝对路径，则在该目录下生成）。

## 🧪 测试

运行完整测试套件：

```bash
python test_mcp_direct.py
```

预期输出：

```
Total: 34 | Passed: 34 | Failed: 0
```

## 📂 项目结构

```
ida-pro-mcp-plus/
├── ida-pro-mcp-server.py       # 主 MCP 服务器（34个工具）
├── ida_scripts_*.py (7个)      # 模块化脚本
├── __version__.py              # 版本信息
│
├── setup_mcp.py                # ⭐ 一键配置脚本
├── test_mcp_direct.py          # 测试套件
├── .mcp.json                   # 项目 MCP 配置
│
├── README.md                   # 英文文档
├── README_CN.md                # 本文件（中文）
├── MCP_SETUP.md                # MCP 配置详解
├── INSTALL.md                  # 详细安装指南
├── QUICK_START.md              # 快速开始
├── COMPARISON.md               # 详细对比
├── CHANGELOG.md                # 更新日志
├── CONTRIBUTING.md             # 贡献指南
└── LICENSE                     # MIT 许可证
```

## 🤝 贡献

欢迎贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md)

## 📝 更新日志

查看 [CHANGELOG.md](CHANGELOG.md) 了解详细版本历史。

## 🙏 致谢

基于 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 项目，感谢 mrexodia 的原始实现！

## 📄 许可证

[MIT License](LICENSE) - 可自由使用、修改和分发

---

## 📞 联系方式

- **作者**: oxygen
- **邮箱**: 304914289@qq.com
- **Issues**: https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/issues

## ⭐ 收藏

如果这个项目对你有帮助，请给个 Star！⭐

---

**中文** | [English](README.md)
