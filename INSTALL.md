# 📦 Installation Guide - ida-pro-mcp-plus

## 🚀 Quick Install (Recommended)

### One-Line Installation

```bash
pip install https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/archive/refs/heads/master.zip && ida-mcp-plus --install
```

This will:
1. Install the package globally
2. Launch the configuration wizard
3. Auto-configure all detected MCP clients

---

## 📋 Detailed Steps

### Step 1: Install Package

```bash
pip install https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/archive/refs/heads/master.zip
```

### Step 2: Configure MCP Clients

```bash
ida-mcp-plus --install
```

**You'll be prompted for:**
- Path to `ida.exe` (or `ida64` on macOS/Linux)
- Path to `idat.exe` (or `idat64` on macOS/Linux)

**Example:**
```
Enter path to ida.exe (or ida64): C:\Program Files\IDA Pro 9.0\ida.exe
Enter path to idat.exe (or idat64): C:\Program Files\IDA Pro 9.0\idat.exe
```

### Step 3: Restart MCP Client

Restart your MCP client:
- **Cursor**: Restart application
- **Claude Desktop**: Restart application
- **VS Code**: Restart or reload window
- **Cline/Continue**: Reload window

### Step 4: Verify Installation

Ask your AI:
```
List all ida-pro-mcp-plus tools
```

Expected: 34 tools displayed ✅

---

## 🔄 Update to Latest Version

```bash
pip uninstall ida-pro-mcp-plus
pip install https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/archive/refs/heads/master.zip
```

No need to reconfigure - your settings are preserved!

---

## 🛠️ Installation from Source (Developers)

```bash
# Clone repository
git clone https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus.git
cd ida-pro-mcp-plus

# Install in editable mode
pip install -e .

# Configure
ida-mcp-plus --install
```

---

## 📍 Find IDA Pro Paths

### Windows

**Common locations:**
- `C:\Program Files\IDA Pro 9.0\`
- `C:\Program Files\IDA Pro 8.4\`
- `C:\Program Files (x86)\IDA Pro 9.0\`

**Files needed:**
- `ida.exe` - IDA Pro GUI version
- `idat.exe` - IDA Pro headless version

### macOS

**Common locations:**
- `/Applications/IDA Pro 9.0/ida.app/Contents/MacOS/`
- `/Applications/IDA Pro 8.4/ida.app/Contents/MacOS/`

**Files needed:**
- `ida64` - IDA Pro GUI version
- `idat64` - IDA Pro headless version

### Linux

**Common locations:**
- `/opt/ida/`
- `~/ida/`

**Files needed:**
- `ida64` - IDA Pro GUI version
- `idat64` - IDA Pro headless version

---

## 🎯 Supported MCP Clients

The installer auto-detects and configures:

| Client | Platform | Config File |
|--------|----------|-------------|
| **Cline** | Windows/Mac/Linux | `cline_mcp_settings.json` |
| **Cursor** | Windows/Mac/Linux | `mcp.json` |
| **Claude Desktop** | Windows/Mac | `claude_desktop_config.json` |
| **Roo Code** | Windows/Mac/Linux | `mcp_settings.json` |
| **Kilo Code** | Windows/Mac/Linux | `mcp_settings.json` |
| **Windsurf** | Windows/Mac/Linux | `mcp_config.json` |
| **Claude Code** | Windows/Mac/Linux | `.claude.json` |
| **LM Studio** | Windows/Mac/Linux | `mcp.json` |
| **Codebuddy Code** | Windows/Mac/Linux | `mcp.json` |

---

## 🔧 Manual Configuration

If auto-install doesn't work, get the config template:

```bash
ida-mcp-plus --config
```

**Example output:**
```json
{
  "mcpServers": {
    "ida-pro-mcp-plus": {
      "command": "python",
      "args": ["-m", "ida_pro_mcp_plus.server"],
      "env": {
        "IDA64_PATH": "C:/Program Files/IDA Pro 9.0/ida.exe",
        "IDAT64_PATH": "C:/Program Files/IDA Pro 9.0/idat.exe",
        "I64_CACHE_DIR": ".i64_cache",
        "IDA_TIMEOUT": "120"
      },
      "timeout": 1800,
      "disabled": false
    }
  }
}
```

### Configuration File Locations

**Windows:**
- Cline: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`
- Cursor: `%USERPROFILE%\.cursor\mcp.json`
- Claude Desktop: `%APPDATA%\Claude\claude_desktop_config.json`
- Windsurf: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`
- Codebuddy: `%USERPROFILE%\.codebuddy\mcp.json`

**macOS:**
- Cline: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- Cursor: `~/.cursor/mcp.json`
- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windsurf: `~/.codeium/windsurf/mcp_config.json`
- Codebuddy: `~/.codebuddy/mcp.json`

**Linux:**
- Cline: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- Cursor: `~/.cursor/mcp.json`
- Windsurf: `~/.codeium/windsurf/mcp_config.json`
- Codebuddy: `~/.codebuddy/mcp.json`

---

## ✅ Verification Checklist

After installation:

- [ ] Package installed: `pip show ida-pro-mcp-plus`
- [ ] Command available: `ida-mcp-plus --help`
- [ ] IDA paths configured correctly
- [ ] MCP client restarted
- [ ] AI can see 34 tools
- [ ] Test tool works: `ping`

---

## 🐛 Troubleshooting

### Issue: `ida-mcp-plus: command not found`

**Solution:**
```bash
# Ensure Python Scripts directory is in PATH
# Windows: Add C:\Python3X\Scripts to PATH
# Linux/Mac: Ensure ~/.local/bin is in PATH

# Or use full path:
python -m ida_pro_mcp_plus.server --help
```

### Issue: Import errors

**Solution:**
```bash
# Reinstall package
pip uninstall ida-pro-mcp-plus
pip install --no-cache-dir https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/archive/refs/heads/master.zip
```

### Issue: MCP client can't find server

**Solution:**
1. Check config file syntax (valid JSON)
2. Verify Python path in config: `which python` or `where python`
3. Test server manually: `python -m ida_pro_mcp_plus.server`

### Issue: IDA Pro not found

**Solution:**
1. Use full absolute paths (not relative)
2. Verify files exist:
   - Windows: `ida.exe` and `idat.exe`
   - Mac/Linux: `ida64` and `idat64`
3. Check file permissions (must be executable)

---

## 📚 Next Steps

After successful installation:

1. **Read the docs**: [README.md](README.md)
2. **Try examples**: [QUICK_START.md](QUICK_START.md)
3. **Learn tools**: Ask AI "Explain each ida-pro-mcp-plus tool"
4. **Report issues**: [GitHub Issues](https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/issues)

---

## 📞 Get Help

- **Email**: 304914289@qq.com
- **Issues**: https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/issues
- **Discussions**: https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus/discussions

---

**Happy reversing!** 🎉
