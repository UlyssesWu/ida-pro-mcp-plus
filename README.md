**[中文文档](README_CN.md)** | English
# 🔧 ida-pro-mcp-plus

**Enhanced IDA Pro MCP Server** - Let AI assistants analyze binaries directly

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Author**: oxygen (304914289@qq.com)  
**Version**: 1.0.0  
**Repository**: https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus

---

## ✨ Key Features

- 🚀 **Multi-Instance Support** - Analyze multiple binaries simultaneously without conflicts
- 🎯 **No GUI Required** - Fully automated batch-mode analysis via IDA headless (idat.exe)
- 🔄 **Smart Caching** - Automatic .i64 database management for faster subsequent analyses
- 💾 **Efficient IPC** - Shared memory communication for large data transfers
- 📦 **34 Powerful Tools** - Complete static analysis, modification, and type system capabilities
- 🧩 **Modular Architecture** - 7 independent script modules for easy maintenance
- ✅ **100% Tested** - Comprehensive test suite with full coverage
- 🎨 **One-Click Install** - `pip install` and you're ready to go!

## 🆚 Why ida-pro-mcp-plus?

### vs. Original ida-pro-mcp

| Feature | ida-pro-mcp | ida-pro-mcp-plus |
|---------|-------------|------------------|
| **Multi-Instance** | ❌ Single instance only | ✅ **Parallel analysis** |
| **IDA GUI** | ⚠️ Requires idalib + GUI | ✅ **Headless batch mode** |
| **Caching** | ❌ No caching | ✅ **Smart .i64 cache** |
| **Architecture** | Monolithic | ✅ **Modular (7 modules)** |
| **Installation** | pip install | ✅ **pip install** |
| **Memory Ops** | Basic | ✅ **Full read/write/patch** |
| **Code Modification** | ❌ | ✅ **ASM patch, rename, comment** |
| **Stack Analysis** | ❌ | ✅ **Frame vars + types** |
| **Type System** | ❌ | ✅ **Declare, apply, search types** |

### Key Advantages

1. **🔥 True Parallel Processing**: Analyze multiple binaries at once without resource conflicts
2. **⚡ Lightning Fast**: No GUI overhead, pure batch-mode execution + smart caching (10x faster on cached files)
3. **🎯 Production Ready**: Smart caching + timeout handling + error recovery
4. **🛠️ More Powerful**: 34 tools covering all reverse engineering needs
5. **📦 Easy Install**: `pip install` → `ida-mcp-plus --install` → Done!

---

## 📥 Installation

### Method 1: Direct Install from GitHub (Recommended)

```bash
# Install directly from master branch
pip install git+https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git

# One-line setup: Configure all MCP clients automatically
ida-mcp-plus --install
```

**Alternative install methods:**

```bash
# From ZIP archive
pip install https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/archive/refs/heads/master.zip

# Or specify branch explicitly
pip install git+https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git@master
```

The `--install` wizard will:
- ✅ Prompt for your IDA Pro paths (ida.exe and idat.exe)
- ✅ Auto-detect all installed MCP clients (Cursor, Claude Desktop, VS Code, etc.)
- ✅ Configure each client with proper environment variables
- ✅ Restart instructions for each client

### Method 2: Install from Source (For Development)

```bash
git clone https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git
cd ida-pro-mcp-plus
pip install -e .
ida-mcp-plus --install
```

---

## 🚀 Quick Start

### Step 1: Install the Package

```bash
pip install git+https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git
```

**What this does:**
- Installs `ida-pro-mcp-plus` package to your Python environment
- Creates global command `ida-mcp-plus` available anywhere
- Installs all dependencies (mcp>=0.9.0)

### Step 2: Configure MCP Clients

```bash
ida-mcp-plus --install
```

**Interactive wizard prompts:**
```
🚀 ida-pro-mcp-plus Installer
==================================================

Configure once, use with all AI clients!

Enter path to ida.exe (or ida64):  F:/tools/analyze/ida9.0/ida.exe
Enter path to idat.exe (or idat64): F:/tools/analyze/ida9.0/idat.exe
```

**Auto-configures these MCP clients:**
- ✅ **Cursor** (`%APPDATA%\Cursor\User\globalStorage\...`)
- ✅ **Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json`)
- ✅ **Cline** (VS Code extension)
- ✅ **Roo Code** (VS Code extension)
- ✅ **Windsurf**
- ✅ **Codebuddy Code**
- ✅ **Continue**, **LM Studio**, and more...

### Step 3: Restart & Verify

1. **Restart your MCP client** (close and reopen)
2. **Test in AI chat**: 
   ```
   User: "List all available ida-pro-mcp-plus tools"
   AI: [Shows 34 tools including list_functions, decompile_function, etc.]
   ```
3. **Success!** 🎉 You can now analyze binaries through AI chat

### Step 4: First Analysis

```
User: "Analyze the binary at C:/samples/malware.exe, 
       show me the main function decompiled code"

AI: [Automatically uses decompile_function tool to show pseudocode]
```

---

## 🛠️ Available Tools (34)

<details>
<summary><b>📊 Basic Analysis (10 tools)</b></summary>

1. **list_functions** - List all functions (paginated/filtered)
2. **get_function_info** - Get detailed function metadata
3. **disassemble_function** - Disassemble function
4. **decompile_function** - Decompile to pseudocode (F5)
5. **list_strings** - Extract all strings
6. **list_imports** - List imported functions
7. **xrefs_to** - Find cross-references
8. **get_callees** - Get function call relationships
9. **read_bytes** - Read raw bytes
10. **ping** - Test connection

</details>

<details>
<summary><b>🔬 Advanced Analysis (7 tools)</b></summary>

11. **basic_blocks** - Basic block CFG analysis
12. **find_bytes** - Byte pattern search (wildcards supported)
13. **find** - Immediate value search
14. **export_funcs** - List exported functions
15. **callgraph** - Complete call graph (bidirectional)
16. **find_regex** - Regex string search
17. **lookup_funcs** - Batch function lookup

</details>

<details>
<summary><b>💾 Memory Operations (7 tools)</b></summary>

18. **list_globals** - List global variables
19. **int_convert** - Number base conversion
20. **get_int** - Read typed integers (i8/u16/i32le/u64be etc.)
21. **get_string** - Read strings
22. **get_global_value** - Read global variable values
23. **patch** - Modify memory bytes
24. **put_int** - Write typed integers

</details>

<details>
<summary><b>✏️ Code Modification (3 tools)</b></summary>

25. **set_comments** - Set comments
26. **patch_asm** - Assembly instruction patching
27. **rename** - Unified rename (func/global/local/stack vars)

</details>

<details>
<summary><b>📚 Stack Frame Tools (3 tools)</b></summary>

28. **stack_frame** - Get stack frame variables
29. **declare_stack** - Declare stack variable types
30. **delete_stack** - Delete stack variables

</details>

<details>
<summary><b>🏗️ Type System (4 tools)</b></summary>

31. **declare_type** - Declare C types to Local Types
32. **read_struct** - Read struct instances
33. **search_structs** - Search struct definitions
34. **set_type** - Apply types to addresses

</details>

---

## 💡 Usage Examples

### Example 1: Decompile Function

```
User: Decompile function at 0x140001000
AI: [Uses decompile_function tool]
    Returns complete C pseudocode
```

### Example 2: Find Strings

```
User: Find all strings containing "password"
AI: [Uses find_regex tool]
    Returns all matching strings with addresses
```

### Example 3: Patch Code

```
User: Change instruction at 0x140001234 to nop
AI: [Uses patch_asm tool]
    Successfully patches instruction
```

### Example 4: Parallel Analysis

```
User: Analyze main.exe and helper.dll simultaneously
AI: [Uses multiple tools in parallel]
    Analyzes both binaries without conflicts
```

---

## 🔧 Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `IDA64_PATH` | IDA Pro executable | `C:/Program Files/IDA Pro 9.0/ida.exe` |
| `IDAT64_PATH` | IDA headless version | `C:/Program Files/IDA Pro 9.0/idat.exe` |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `I64_CACHE_DIR` | `.i64_cache` | Database cache directory (relative paths are resolved next to the input binary) |
| `IDA_TIMEOUT` | `120` | Timeout in seconds for each **tool** run (`idat.exe` executing a one-off script) |
| `IDA_BUILD_TIMEOUT` | `1800` | Timeout in seconds for **first-time** creation of a cached `.i64` from a binary (large modules like `GameAssembly.dll` often need a higher value) |
| `IDA_SKIP_AUTO_WAIT` | *(unset)* | If `1`, `true`, or `yes`, tools skip `idaapi.auto_wait()` by default (individual tools can still override). Use when auto-analysis never finishes (heavy obfuscation) |
| `IDA_SHM_SIZE` | `20971520` | Shared memory size (20MB) |

### `file_path`: binary vs existing database

Every tool’s `file_path` argument can be either:

1. **An existing IDA database** — pass a `.i64` or `.idb` file. It is opened directly; nothing is rebuilt from the PE.
2. **A binary** — pass the executable or library path. The server checks, in order: `<path>.i64`, `<basename-without-ext>.i64`, same pair for `.idb` next to the file; if none exist, it generates `<I64_CACHE_DIR>/<basename>.i64` under the binary’s directory (or under `I64_CACHE_DIR` when it is absolute).

### Manual Configuration

If auto-install doesn't work, get the config template:

```bash
ida-mcp-plus --config
```

Then paste into your MCP client's configuration file.

---

## 🧪 Testing

Run complete test suite:

```bash
python test_mcp_direct.py
```

Expected output:

```
Total: 34 | Passed: 34 | Failed: 0
```

---

## 📂 Project Structure

```
ida-pro-mcp-plus/
├── src/ida_pro_mcp_plus/
│   ├── server.py              # Main MCP server (34 tools)
│   ├── ida_scripts.py         # Original 9 tools
│   ├── ida_scripts_analysis.py # Advanced analysis (7 tools)
│   ├── ida_scripts_core.py    # Core utilities (2 tools)
│   ├── ida_scripts_memory.py  # Memory operations (5 tools)
│   ├── ida_scripts_modify.py  # Modification tools (3 tools)
│   ├── ida_scripts_stack.py   # Stack frame tools (3 tools)
│   └── ida_scripts_types.py   # Type system (4 tools)
│
├── test_mcp_direct.py         # Test suite (34 tests)
├── pyproject.toml             # Package configuration
├── README.md                  # This file
├── README_CN.md               # Chinese version
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md            # Contribution guide
└── LICENSE                    # MIT License
```

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

---

## 🙏 Acknowledgments

Based on [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by mrexodia. Thanks for the original implementation!

---

## 📄 License

[MIT License](LICENSE) - Free to use, modify, and distribute

---

## 📞 Contact

- **Author**: oxygen
- **Email**: 304914289@qq.com
- **Issues**: https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/issues

---

## ⭐ Star History

If this project helps you, please give it a Star! ⭐

---

**[中文文档](README_CN.md)** | English
