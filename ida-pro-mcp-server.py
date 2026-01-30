from __future__ import annotations

import json
import logging
import mmap
import os
import shutil
import subprocess
import tempfile
import uuid
from typing import Annotated, Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

# Windows MessageBox for debugging
try:
    import ctypes

    def show_message(title: str, message: str) -> None:
        """Show Windows MessageBox for debugging"""
        # ctypes.windll.user32.MessageBoxW(0, message, title, 0)
        logging.info("[MSGBOX] %s: %s", title, message)
    MESSAGEBOX_AVAILABLE = True
except:
    def show_message(title: str, message: str) -> None:
        """Fallback: just log"""
        logging.info("[MSGBOX] %s: %s", title, message)
    MESSAGEBOX_AVAILABLE = False

mcp = FastMCP("ida-pro-mcp")

IDA64_PATH = os.getenv("IDA64_PATH", r"F:\\tools\\analyze\\ida7.x\\ida64.exe")
IDAT64_PATH = os.getenv(
    "IDAT64_PATH", r"F:\\tools\\analyze\\ida7.x\\idat64.exe")
I64_CACHE_DIR = os.getenv("I64_CACHE_DIR", ".i64_cache")
IDA_TIMEOUT = int(os.getenv("IDA_TIMEOUT", "120"))
SHM_SIZE = int(os.getenv("IDA_SHM_SIZE", str(20 * 1024 * 1024)))


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(message)s",
    )


def _ensure_paths() -> None:
    if not os.path.exists(IDA64_PATH):
        raise FileNotFoundError(f"IDA64_PATH not found: {IDA64_PATH}")
    if not os.path.exists(IDAT64_PATH):
        raise FileNotFoundError(f"IDAT64_PATH not found: {IDAT64_PATH}")


def _cache_i64_path(file_path: str) -> str:
    base = os.path.basename(file_path)
    # If I64_CACHE_DIR is absolute path, use it directly
    if os.path.isabs(I64_CACHE_DIR):
        cache_dir = I64_CACHE_DIR
    else:
        # Otherwise, use .i64_cache in the same directory as the target file
        cache_dir = os.path.join(os.path.dirname(file_path), I64_CACHE_DIR)
    return os.path.join(cache_dir, f"{base}.i64")


def _local_i64_path(file_path: str) -> str:
    return f"{file_path}.i64"


def _generate_i64(file_path: str, cache_path: str) -> str:
    """Generate i64 file using IDA in batch mode"""
    logging.info("Generating i64: %s", file_path)

    cache_dir = os.path.dirname(cache_path)
    os.makedirs(cache_dir, exist_ok=True)

    cmd = [
        IDA64_PATH,
        "-A",
        "-B",
        f"-o{cache_path}",
        file_path
    ]

    logging.info("Running IDA: %s", " ".join(cmd))

    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        timeout=600,
        shell=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"IDA analysis failed with exit code {result.returncode}")

    if not os.path.exists(cache_path):
        raise FileNotFoundError(f"i64 not generated at: {cache_path}")

    logging.info("i64 generated at: %s", cache_path)
    return cache_path


def ensure_i64(file_path: str) -> str:
    show_message("ensure_i64", f"Input: {file_path}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    local_i64 = _local_i64_path(file_path)
    show_message(
        "ensure_i64", f"Check local i64: {local_i64}\nExists: {os.path.exists(local_i64)}")
    if os.path.exists(local_i64):
        return local_i64

    cache_path = _cache_i64_path(file_path)
    show_message(
        "ensure_i64", f"Check cache: {cache_path}\nExists: {os.path.exists(cache_path)}")
    if os.path.exists(cache_path):
        return cache_path

    show_message(
        "ensure_i64", f"Need to generate i64!\nThis will take time...")
    return _generate_i64(file_path, cache_path)


def _create_shared_memory() -> str:
    shm_path = os.path.join(tempfile.gettempdir(),
                            f"ida_shm_{uuid.uuid4().hex}.bin")
    with open(shm_path, "wb") as handle:
        handle.write(b"\x00" * SHM_SIZE)
    return shm_path


def _read_shared_memory(shm_path: str) -> Dict[str, Any]:
    with open(shm_path, "rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            data = mm.read().decode("utf-8", errors="ignore")
    text = data.strip("\x00").strip()
    if not text:
        raise ValueError("Shared memory is empty")
    return json.loads(text)


def _cleanup_file(path: Optional[str]) -> None:
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            logging.warning("Failed to remove file: %s", path)


def _run_ida_script(idb_path: str, script_content: str, shm_path: str) -> Dict[str, Any]:
    """RUN ida script"""
    script_path = None
    try:
        script_path = os.path.join(
            tempfile.gettempdir(),
            f"ida_script_{uuid.uuid4().hex}.py"
        )
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(script_content)
        cmd = [
            IDAT64_PATH,
            "-A",
            f'-S"{script_path}"',
            idb_path
        ]
        # cmd = [IDAT64_PATH, "-A", "-S", script_path, idb_path]

        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=IDA_TIMEOUT,
            shell=False,
            check=True
        )
        # import time
        # time.sleep(0.5)

        return _read_shared_memory(shm_path)

    finally:
        _cleanup_file(script_path)
        _cleanup_file(shm_path)


def _script_list_strings(shm_path: str, count: int) -> str:
    return f"""
import idaapi
import idautils
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
MAX_COUNT = {count}

idaapi.auto_wait()

result = {{"success": True, "strings": []}}

for index, s in enumerate(idautils.Strings()):
    if MAX_COUNT and index >= MAX_COUNT:
        break
    value = str(s)
    result["strings"].append({{
        "ea": hex(s.ea),
        "string": value,
        "length": len(value)
    }})

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

import idc
idc.qexit(0)
"""


def _script_disassemble_function(shm_path: str, address: int) -> str:
    script_template = r"""
import idaapi
import idautils
import idc
import ida_bytes
import json
import mmap

SHARED_MEM_PATH = r"%(shm_path)s"
TARGET_EA = %(address)d

idaapi.auto_wait()

result = {"success": True, "functions": []}

func = idaapi.get_func(TARGET_EA)
if not func:
    result["success"] = False
    result["error"] = "No function found for address " + hex(TARGET_EA)
else:
    lines = []
    for ea in idautils.FuncItems(func.start_ea):
        size = idc.get_item_size(ea)
        data = ida_bytes.get_bytes(ea, size) or b""
        bytes_hex = " ".join("{:02x}".format(b) for b in data)
        mnem = idc.print_insn_mnem(ea)
        op0 = idc.print_operand(ea, 0)
        op1 = idc.print_operand(ea, 1)
        operands = ", ".join([op for op in [op0, op1] if op])
        
        if operands:
            line = "{}: {:<20} {} {}".format(hex(ea), bytes_hex, mnem, operands)
        else:
            line = "{}: {:<20} {}".format(hex(ea), bytes_hex, mnem)
        lines.append(line)

    result["functions"].append({
        "function_name": idc.get_func_name(func.start_ea),
        "function_start": hex(func.start_ea),
        "function_size": hex(func.end_ea - func.start_ea),
        "disassembled_code": "\n".join(lines)
    })

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
    return script_template % {"shm_path": shm_path, "address": address}

def _script_decompile_function(shm_path: str, address: int) -> str:
    """get pseudocode"""
    script_template = r"""
import idaapi
import idc
import json
import mmap

SHARED_MEM_PATH = r"%(shm_path)s"
TARGET_EA = %(address)d

idaapi.auto_wait()

result = {"success": True, "functions": []}

func = idaapi.get_func(TARGET_EA)
if not func:
    result["success"] = False
    result["error"] = "No function found for address " + hex(TARGET_EA)
else:
    func_start = func.start_ea
    func_name = idc.get_func_name(func_start)
    try:
        cfunc = idaapi.decompile(func_start)
        
        if cfunc:
            result["functions"].append({
                "function_name": func_name,
                "function_start": hex(func_start),
                "function_size": hex(func.end_ea - func.start_ea),
                "pseudocode": str(cfunc)
            })
        else:
            result["success"] = False
            result["error"] = "Decompilation failed for function " + func_name
    except Exception as e:
        result["success"] = False
        result["error"] = "Decompilation error: " + str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
    return script_template % {"shm_path": shm_path, "address": address}


@mcp.tool()
def ping() -> str:
    """
    Simple ping test to verify MCP connection.

    Returns:
        JSON string with pong message
    """
    try:
        logging.info("ping called")
        result = {"success": True, "message": "pong",
                  "timestamp": str(uuid.uuid4())}
        logging.info("ping completed successfully")
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("ping failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def list_strings(
    file_path: Annotated[str, "Target binary file path"],
    count: Annotated[int, "Max number of strings, 0 means unlimited"] = 0,
) -> str:
    """
    List strings from the binary.

    Args:
        file_path: Target binary file path
        count: Max number of strings, 0 means unlimited

    Returns:
        JSON string with success and strings
    """
    try:
        show_message("list_strings",
                     f"Step 1: Called with file={file_path}, count={count}")
        logging.info("list_strings called: file_path=%s, count=%d",
                     file_path, count)

        show_message("list_strings", "Step 2: Setup logging and paths")
        _setup_logging()
        _ensure_paths()

        show_message("list_strings", "Step 3: Ensure i64 exists")
        idb_path = ensure_i64(os.path.abspath(file_path))

        show_message("list_strings", f"Step 4: Create shared memory")
        shm_path = _create_shared_memory()

        show_message("list_strings", "Step 5: Generate script")
        script = _script_list_strings(shm_path, count)

        show_message("list_strings",
                     "Step 6: Run IDA script (this may take time)")
        data = _run_ida_script(idb_path, script, shm_path)

        show_message("list_strings", "Step 7: Completed successfully!")
        logging.info("list_strings completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        show_message("list_strings ERROR", str(e))
        logging.error("list_strings failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def disassemble_function(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[str, "Hex or decimal address string (e.g. 0x14001e2a0)"],
) -> str:
    """
    Disassemble the function containing the target address.

    Args:
        file_path: Target binary file path
        address: Hex or decimal address string (e.g. 0x14001e2a0)

    Returns:
        JSON string with success and functions
    """
    try:
        logging.info(
            "disassemble_function called: file_path=%s, address=%s", file_path, address)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        target = int(address, 0)
        shm_path = _create_shared_memory()
        script = _script_disassemble_function(shm_path, target)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("disassemble_function completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("disassemble_function failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def decompile_function(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[str, "Hex or decimal address string (e.g. 0x14001e2a0)"],
) -> str:
    """
    Decompile the function to pseudocode (C code).

    Args:
        file_path: Target binary file path
        address: Hex or decimal address string (e.g. 0x14001e2a0)

    Returns:
        JSON string with success and pseudocode
    """
    try:
        logging.info(
            "decompile_function called: file_path=%s, address=%s", file_path, address)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        target = int(address, 0)
        shm_path = _create_shared_memory()
        script = _script_decompile_function(shm_path, target)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("decompile_function completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("decompile_function failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    _setup_logging()
    _ensure_paths()
    logging.info("MCP server starting (IDA64=%s, IDAT64=%s, cache=%s)",
                 IDA64_PATH, IDAT64_PATH, I64_CACHE_DIR)
    mcp.run()
