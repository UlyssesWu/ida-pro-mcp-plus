"""
IDA Pro MCP Server Plus

An enhanced Model Context Protocol (MCP) server for IDA Pro binary analysis.
Provides 34+ tools for automated reverse engineering workflows including:
- Static analysis (disassembly, decompilation)
- Pattern searching (bytes, strings, immediates)
- Cross-reference analysis
- Memory operations (read/write)
- Code modification (assembly patching, renaming)
- Stack frame management
- Type system operations

Project: ida-pro-mcp-plus
Version: 1.0.0
Author: oxygen
Email: 304914289@qq.com
License: MIT
Repository: https://github.com/oxygen1a1/ida-pro-mcp-plus
"""

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

# Version info
try:
    from __version__ import __version__, __author__, __email__
except ImportError:
    __version__ = "1.0.0"
    __author__ = "oxygen"
    __email__ = "304914289@qq.com"

# Import IDA script generators
from .ida_scripts import (
    script_list_strings,
    script_disassemble_function,
    script_decompile_function,
    script_list_functions,
    script_get_function_info,
    script_list_imports,
    script_xrefs_to,
    script_get_callees,
    script_read_bytes,
)
# Category 1: Advanced Analysis Tools
from .ida_scripts_analysis import (
    script_basic_blocks,
    script_find_bytes,
    script_find,
    script_export_funcs,
    script_callgraph,
    script_find_regex,
    script_lookup_funcs,
)
# Category 2: Core Utilities
from .ida_scripts_core import (
    script_list_globals,
    script_int_convert,
    script_stop_auto_analysis,
)
# Category 3: Memory Operations
from .ida_scripts_memory import (
    script_get_int,
    script_get_string,
    script_get_global_value,
    script_patch,
    script_put_int,
)
# Category 4: Modification Tools
from .ida_scripts_modify import (
    script_set_comments,
    script_patch_asm,
    script_rename,
)
# Category 5: Stack Frame Tools
from .ida_scripts_stack import (
    script_stack_frame,
    script_declare_stack,
    script_delete_stack,
)
# Category 6: Type System Tools
from .ida_scripts_types import (
    script_declare_type,
    script_read_struct,
    script_search_structs,
    script_set_type,
    script_infer_types,
)

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
IDA_BUILD_TIMEOUT = int(os.getenv("IDA_BUILD_TIMEOUT", "1800"))
SHM_SIZE = int(os.getenv("IDA_SHM_SIZE", str(20 * 1024 * 1024)))

_UNPACKED_EXTS = (".id0", ".id1", ".id2", ".nam", ".til")


def _keep_unpacked() -> bool:
    val = os.getenv("IDA_KEEP_UNPACKED", "").strip().lower()
    return val in ("1", "true", "yes")


def _env_skip_auto_wait() -> bool:
    val = os.getenv("IDA_SKIP_AUTO_WAIT", "").strip().lower()
    return val in ("1", "true", "yes")


def _should_skip_auto_wait(wait_for_auto_analysis: Optional[bool]) -> bool:
    """Whether to replace idaapi.auto_wait() with ida_auto.enable_auto(False)."""
    if wait_for_auto_analysis is True:
        return False
    if wait_for_auto_analysis is False:
        return True
    return _env_skip_auto_wait()


def _rewrite_script_skip_auto_wait(script_content: str) -> str:
    if "idaapi.auto_wait()" not in script_content:
        return script_content
    modified = script_content.replace(
        "idaapi.auto_wait()", "ida_auto.enable_auto(False)"
    )
    if "import ida_auto" not in modified:
        modified = "import ida_auto\n" + modified
    return modified


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(message)s",
    )


def _ensure_paths() -> None:
    """Validate IDA executable paths and provide clear error messages."""
    if not os.path.exists(IDA64_PATH):
        raise FileNotFoundError(
            f"IDA64_PATH not found: {IDA64_PATH}\n"
            f"Please verify your IDA Pro installation and configure the correct path.\n"
            f"You can set this via:\n"
            f"  1. MCP settings.json env section (recommended)\n"
            f"  2. Environment variable IDA64_PATH\n"
            f"Example: \"IDA64_PATH\": \"C:/Program Files/IDA Pro 9.0/ida.exe\""
        )
    if not os.path.exists(IDAT64_PATH):
        raise FileNotFoundError(
            f"IDAT64_PATH not found: {IDAT64_PATH}\n"
            f"Please verify your IDA Pro installation and configure the correct path.\n"
            f"You can set this via:\n"
            f"  1. MCP settings.json env section (recommended)\n"
            f"  2. Environment variable IDAT64_PATH\n"
            f"Example: \"IDAT64_PATH\": \"C:/Program Files/IDA Pro 9.0/idat.exe\""
        )


def _log_configuration() -> None:
    """Log all configuration settings on startup for troubleshooting."""
    logging.info("=" * 60)
    logging.info("IDA Pro MCP Server Plus - Configuration")
    logging.info("=" * 60)
    logging.info(f"Project: ida-pro-mcp-plus")
    logging.info(f"Version: {__version__}")
    logging.info(f"Author: {__author__}")
    logging.info(f"Email: {__email__}")
    logging.info("=" * 60)
    
    # Check configuration source
    config_source = "defaults"
    if "IDA64_PATH" in os.environ:
        config_source = "environment variables / MCP settings.json"
    
    logging.info(f"Configuration source: {config_source}")
    logging.info(f"IDA64_PATH: {IDA64_PATH}")
    logging.info(f"IDAT64_PATH: {IDAT64_PATH}")
    logging.info(f"I64_CACHE_DIR: {I64_CACHE_DIR}")
    logging.info(f"IDA_TIMEOUT: {IDA_TIMEOUT} seconds")
    logging.info(f"IDA_BUILD_TIMEOUT: {IDA_BUILD_TIMEOUT} seconds")
    logging.info(f"IDA_SKIP_AUTO_WAIT: {_env_skip_auto_wait()}")
    logging.info(f"IDA_KEEP_UNPACKED: {_keep_unpacked()}")
    logging.info(f"IDA_SHM_SIZE: {SHM_SIZE} bytes ({SHM_SIZE // (1024*1024)} MB)")
    if _keep_unpacked():
        logging.info("  >> Unpacked mode ON: databases stored as component files")
        logging.info("  >> (.id0/.id1/.id2/.nam/.til) next to the binary")
        logging.info("  >> Avoids pack/unpack overhead on every operation")
    logging.info("=" * 60)



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


def _local_db_candidates(file_path: str) -> List[str]:
    stem, _ = os.path.splitext(file_path)
    candidates = [
        f"{file_path}.i64",
        f"{stem}.i64",
        f"{file_path}.idb",
        f"{stem}.idb",
    ]
    # Keep order stable while removing duplicates.
    return list(dict.fromkeys(candidates))


def _is_ida_database_path(file_path: str) -> bool:
    return os.path.splitext(file_path)[1].lower() in {".i64", ".idb"}


def _unpacked_db_exists(binary_path: str) -> bool:
    """Check if unpacked database component files (.id0, etc.) exist for a binary."""
    return os.path.exists(f"{binary_path}.id0")


def _strip_i64_ext(i64_path: str) -> str:
    """Strip the .i64/.idb extension to get the database base path.

    e.g. 'foo.dll.i64' -> 'foo.dll'
    """
    stem, ext = os.path.splitext(i64_path)
    if ext.lower() in (".i64", ".idb"):
        return stem
    return i64_path


def _convert_packed_to_unpacked(i64_path: str) -> None:
    """Open a packed .i64 database and re-save it in unpacked format (-P-).

    After this call the component files (.id0, .id1, …) sit next to *i64_path*.
    The caller is responsible for deleting the stale .i64 and/or moving the
    component files to the desired location.
    """
    logging.info("Converting packed database to unpacked: %s", i64_path)
    script_path = None
    try:
        script_path = os.path.join(
            tempfile.gettempdir(),
            f"ida_convert_unpack_{uuid.uuid4().hex}.py",
        )
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write("import idc\nidc.qexit(1)\n")

        cmd = [
            IDAT64_PATH,
            "-A",
            "-P-",
            f'-S"{script_path}"',
            i64_path,
        ]
        logging.info("Running IDAT (convert to unpacked): %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=IDA_BUILD_TIMEOUT,
                shell=False,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"IDA database conversion timed out after {IDA_BUILD_TIMEOUT}s."
            ) from exc

        if result.returncode not in (0, 1):
            details = _format_process_error_output(result.stdout, result.stderr)
            raise RuntimeError(
                f"IDA conversion failed with exit code {result.returncode}{details}"
            )
    finally:
        _cleanup_file(script_path)


def _move_unpacked_files(src_base: str, dst_base: str) -> None:
    """Move unpacked database component files from *src_base* to *dst_base*.

    src_base: e.g. 'cache_dir/myfile.dll'  (expects cache_dir/myfile.dll.id0 …)
    dst_base: e.g. 'bin_dir/myfile.dll'    (creates bin_dir/myfile.dll.id0 …)
    """
    for ext in _UNPACKED_EXTS:
        src = f"{src_base}{ext}"
        if os.path.exists(src):
            dst = f"{dst_base}{ext}"
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)


def _cleanup_unpacked_files(base_path: str) -> None:
    """Remove unpacked database component files for a base path."""
    for ext in _UNPACKED_EXTS:
        _cleanup_file(f"{base_path}{ext}")


def _generate_unpacked_db(file_path: str) -> str:
    """Generate an unpacked database directly (no .i64 container)."""
    logging.info("Generating unpacked database for: %s", file_path)
    script_path = None
    try:
        script_path = os.path.join(
            tempfile.gettempdir(),
            f"ida_build_unpacked_{uuid.uuid4().hex}.py",
        )
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(
                "import idaapi\nimport idc\n"
                "idaapi.auto_wait()\nidc.qexit(1)\n"
            )

        cmd = [
            IDAT64_PATH,
            "-A",
            "-P-",
            f'-S"{script_path}"',
            file_path,
        ]
        logging.info("Running IDAT (generate unpacked): %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=IDA_BUILD_TIMEOUT,
                shell=False,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"IDA unpacked DB generation timed out after {IDA_BUILD_TIMEOUT}s. "
                f"Increase IDA_BUILD_TIMEOUT for large binaries."
            ) from exc

        if result.returncode not in (0, 1):
            details = _format_process_error_output(result.stdout, result.stderr)
            raise RuntimeError(
                f"IDA analysis failed with exit code {result.returncode}{details}"
            )
    finally:
        _cleanup_file(script_path)

    if not _unpacked_db_exists(file_path):
        raise FileNotFoundError(
            f"Unpacked database not generated. Expected: {file_path}.id0"
        )

    # Clean up any .i64 that IDA might have created alongside
    for candidate in _local_db_candidates(file_path):
        if os.path.exists(candidate):
            _cleanup_file(candidate)

    logging.info("Unpacked database generated for: %s", file_path)
    return file_path


def _generate_i64(file_path: str, cache_path: str) -> str:
    """Generate i64 file using IDA in batch mode"""
    logging.info("Generating i64: %s", file_path)

    cache_dir = os.path.dirname(cache_path)
    os.makedirs(cache_dir, exist_ok=True)

    # Use an explicit script + qexit(1) to save DB and exit, which avoids
    # generating massive .asm outputs from -B for large binaries.
    script_path = None
    try:
        script_path = os.path.join(
            tempfile.gettempdir(),
            f"ida_build_i64_{uuid.uuid4().hex}.py"
        )
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(
                "import idaapi\n"
                "import idc\n"
                "idaapi.auto_wait()\n"
                "idc.qexit(1)\n"
            )

        cmd = [
            IDAT64_PATH,
            "-A",
            f'-S"{script_path}"',
            f"-o{cache_path}",
            file_path,
        ]
        logging.info("Running IDAT: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=IDA_BUILD_TIMEOUT,
                shell=False,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"IDA i64 generation timed out after {IDA_BUILD_TIMEOUT}s. "
                f"Increase IDA_BUILD_TIMEOUT for large binaries."
            ) from exc

        # idc.qexit(1) indicates successful save-and-exit. Accept both 0/1.
        if result.returncode not in (0, 1):
            details = _format_process_error_output(result.stdout, result.stderr)
            raise RuntimeError(
                f"IDA analysis failed with exit code {result.returncode}{details}"
            )
    finally:
        _cleanup_file(script_path)

    if not os.path.exists(cache_path):
        raise FileNotFoundError(f"i64 not generated at: {cache_path}")

    logging.info("i64 generated at: %s", cache_path)
    return cache_path


def ensure_i64(file_path: str) -> str:
    file_path = os.path.abspath(file_path)
    show_message("ensure_i64", f"Input: {file_path}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    # --- Unpacked database mode ------------------------------------------
    if _keep_unpacked():
        # When user passes a .i64/.idb directly, use it with -P- (partial
        # optimisation: avoids re-packing on exit but still needs one unpack).
        if _is_ida_database_path(file_path):
            show_message("ensure_i64", f"Unpacked mode: .i64 passed directly, using as-is: {file_path}")
            return file_path

        # Fast path: unpacked component files already next to the binary
        if _unpacked_db_exists(file_path):
            show_message("ensure_i64", f"Unpacked DB found: {file_path}")
            logging.info("Found existing unpacked database for: %s", file_path)
            return file_path

        # Check for local packed databases that can be converted
        for local_db in _local_db_candidates(file_path):
            if os.path.exists(local_db):
                show_message("ensure_i64", f"Converting local .i64 to unpacked: {local_db}")
                try:
                    _convert_packed_to_unpacked(local_db)
                    if _unpacked_db_exists(file_path):
                        _cleanup_file(local_db)
                        return file_path
                except Exception:
                    logging.warning("Failed to convert %s, falling back", local_db, exc_info=True)
                break

        # Check cache directory for packed database to convert
        cache_path = _cache_i64_path(file_path)
        if os.path.exists(cache_path):
            show_message("ensure_i64", f"Converting cached .i64 to unpacked: {cache_path}")
            try:
                _convert_packed_to_unpacked(cache_path)
                cache_base = _strip_i64_ext(cache_path)
                _move_unpacked_files(cache_base, file_path)
                _cleanup_file(cache_path)
                if _unpacked_db_exists(file_path):
                    return file_path
            except Exception:
                logging.warning("Failed to convert cached %s, falling back", cache_path, exc_info=True)

        # Generate a fresh unpacked database
        show_message("ensure_i64", "Generating new unpacked database (first time, will take a while)...")
        return _generate_unpacked_db(file_path)

    # --- Standard packed database mode -----------------------------------
    if _is_ida_database_path(file_path):
        show_message("ensure_i64", f"Input is IDA DB, use directly: {file_path}")
        return file_path

    for local_db in _local_db_candidates(file_path):
        exists = os.path.exists(local_db)
        show_message("ensure_i64", f"Check local DB: {local_db}\nExists: {exists}")
        if exists:
            return local_db

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


def _format_process_error_output(stdout: str, stderr: str, lines: int = 20) -> str:
    parts: List[str] = []
    if stderr and stderr.strip():
        parts.append("stderr:\n" + "\n".join(stderr.strip().splitlines()[-lines:]))
    if stdout and stdout.strip():
        parts.append("stdout:\n" + "\n".join(stdout.strip().splitlines()[-lines:]))
    if not parts:
        return ""
    return "\n" + "\n\n".join(parts)


def _run_ida_script(
    idb_path: str,
    script_content: str,
    shm_path: str,
    wait_for_auto_analysis: Optional[bool] = None,
) -> Dict[str, Any]:
    """RUN ida script"""
    if _should_skip_auto_wait(wait_for_auto_analysis):
        script_content = _rewrite_script_skip_auto_wait(script_content)

    unpacked = _keep_unpacked()
    if unpacked:
        # Persist analysis results so subsequent opens skip auto-analysis.
        # qexit(1) saves; with -P- the save is cheap (no packing).
        script_content = script_content.replace("idc.qexit(0)", "idc.qexit(1)")

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
        ]
        if unpacked:
            cmd.append("-P-")
        cmd.extend([f'-S"{script_path}"', idb_path])

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=IDA_TIMEOUT,
                shell=False,
                check=False,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"IDA subprocess timed out after {IDA_TIMEOUT}s. For binaries where "
                f"auto-analysis never finishes (e.g. heavy obfuscation), set environment "
                f"variable IDA_SKIP_AUTO_WAIT=1, call list_strings with "
                f"wait_for_auto_analysis=False, and/or use stop_auto_analysis to clear "
                f"analysis queues."
            ) from exc
        if result.returncode not in (0, 1):
            details = _format_process_error_output(result.stdout, result.stderr)
            raise RuntimeError(
                f"IDA script failed with exit code {result.returncode}{details}"
            )

        return _read_shared_memory(shm_path)

    finally:
        _cleanup_file(script_path)
        _cleanup_file(shm_path)


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
def stop_auto_analysis(
    file_path: Annotated[str, "Target binary file path (same as other tools)"],
    save_idb: Annotated[
        bool,
        "If true, save the database when exiting IDA (idc.qexit(1)) so cleared queues persist",
    ] = False,
) -> str:
    """
    Suspend IDA auto-analysis and clear analyzer queues (no auto_wait).

    Use when auto-analysis never finishes (e.g. obfuscated binaries) so subsequent
    tools can run. Optionally save the .i64 so the cleared state is kept.
    """
    try:
        logging.info(
            "stop_auto_analysis called: file_path=%s save_idb=%s",
            file_path,
            save_idb,
        )
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_stop_auto_analysis(shm_path, save_idb)
        data = _run_ida_script(
            idb_path, script, shm_path, wait_for_auto_analysis=True
        )
        logging.info("stop_auto_analysis completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("stop_auto_analysis failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def list_strings(
    file_path: Annotated[str, "Target binary file path"],
    count: Annotated[int, "Max number of strings, 0 means unlimited"] = 0,
    wait_for_auto_analysis: Annotated[
        Optional[bool],
        "None: use env IDA_SKIP_AUTO_WAIT. True: always wait for auto-analysis. "
        "False: skip idaapi.auto_wait() (use for stuck/obfuscated analysis).",
    ] = None,
) -> str:
    """
    List strings from the binary.

    Args:
        file_path: Target binary file path
        count: Max number of strings, 0 means unlimited
        wait_for_auto_analysis: Override auto-analysis wait (see annotated type hint)

    Returns:
        JSON string with success and strings
    """
    try:
        show_message("list_strings",
                     f"Step 1: Called with file={file_path}, count={count}")
        logging.info(
            "list_strings called: file_path=%s, count=%d, wait_for_auto_analysis=%s",
            file_path,
            count,
            wait_for_auto_analysis,
        )

        show_message("list_strings", "Step 2: Setup logging and paths")
        _setup_logging()
        _ensure_paths()

        show_message("list_strings", "Step 3: Ensure i64 exists")
        idb_path = ensure_i64(os.path.abspath(file_path))

        show_message("list_strings", f"Step 4: Create shared memory")
        shm_path = _create_shared_memory()

        show_message("list_strings", "Step 5: Generate script")
        script = script_list_strings(shm_path, count)

        show_message("list_strings",
                     "Step 6: Run IDA script (this may take time)")
        data = _run_ida_script(
            idb_path, script, shm_path, wait_for_auto_analysis=wait_for_auto_analysis
        )

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
        script = script_disassemble_function(shm_path, target)
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
        script = script_decompile_function(shm_path, target)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("decompile_function completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("decompile_function failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def list_functions(
    file_path: Annotated[str, "Target binary file path"],
    offset: Annotated[int, "Start offset for pagination"] = 0,
    count: Annotated[int, "Max number of functions, 0 means unlimited"] = 100,
    filter: Annotated[str, "Function name filter (case-insensitive substring)"] = "",
) -> str:
    """
    List functions from the binary with pagination and filtering.

    Args:
        file_path: Target binary file path
        offset: Start offset for pagination
        count: Max number of functions, 0 means unlimited
        filter: Function name filter (case-insensitive substring)

    Returns:
        JSON string with success, functions list, total_count, and has_more flag
    """
    try:
        logging.info("list_functions called: file_path=%s, offset=%d, count=%d, filter=%s",
                     file_path, offset, count, filter)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_list_functions(shm_path, offset, count, filter)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("list_functions completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("list_functions failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def get_function_info(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[str, "Hex or decimal address string (e.g. 0x14001e2a0)"],
) -> str:
    """
    Get detailed information about a specific function.

    Args:
        file_path: Target binary file path
        address: Hex or decimal address string

    Returns:
        JSON string with function metadata (name, size, flags, xref_count, etc.)
    """
    try:
        logging.info("get_function_info called: file_path=%s, address=%s", file_path, address)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        target = int(address, 0)
        shm_path = _create_shared_memory()
        script = script_get_function_info(shm_path, target)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("get_function_info completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("get_function_info failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def list_imports(
    file_path: Annotated[str, "Target binary file path"],
    offset: Annotated[int, "Start offset for pagination"] = 0,
    count: Annotated[int, "Max number of imports, 0 means unlimited"] = 100,
) -> str:
    """
    List imported functions from the binary with pagination.

    Args:
        file_path: Target binary file path
        offset: Start offset for pagination
        count: Max number of imports, 0 means unlimited

    Returns:
        JSON string with imports list including module, name, address, ordinal
    """
    try:
        logging.info("list_imports called: file_path=%s, offset=%d, count=%d",
                     file_path, offset, count)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_list_imports(shm_path, offset, count)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("list_imports completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("list_imports failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def xrefs_to(
    file_path: Annotated[str, "Target binary file path"],
    addresses: Annotated[
        str,
        "Comma-separated EAs (hex with 0x or decimal), e.g. '0x401000,0x402000' or '4198400,4206592'",
    ],
) -> str:
    """
    Find cross-references to one or more addresses.

    Args:
        file_path: Target binary file path
        addresses: Comma-separated addresses (hex or decimal)

    Returns:
        JSON string with xrefs grouped by target address
    """
    try:
        addr_list = [addr.strip() for addr in addresses.split(",")]
        logging.info("xrefs_to called: file_path=%s, addresses=%s", file_path, addr_list)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_xrefs_to(shm_path, addr_list)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("xrefs_to completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("xrefs_to failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def get_callees(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[str, "Hex or decimal address string (e.g. 0x14001e2a0)"],
) -> str:
    """
    Get functions called by a specific function.

    Args:
        file_path: Target binary file path
        address: Hex or decimal address string

    Returns:
        JSON string with list of called functions (callees)
    """
    try:
        logging.info("get_callees called: file_path=%s, address=%s", file_path, address)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        target = int(address, 0)
        shm_path = _create_shared_memory()
        script = script_get_callees(shm_path, target)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("get_callees completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("get_callees failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def read_bytes(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[str, "Hex or decimal address string (e.g. 0x404000)"],
    size: Annotated[int, "Number of bytes to read"] = 16,
) -> str:
    """
    Read raw bytes from memory address.

    Args:
        file_path: Target binary file path
        address: Hex or decimal address string
        size: Number of bytes to read (default 16)

    Returns:
        JSON string with hex-encoded bytes
    """
    try:
        logging.info("read_bytes called: file_path=%s, address=%s, size=%d",
                     file_path, address, size)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        target = int(address, 0)
        shm_path = _create_shared_memory()
        script = script_read_bytes(shm_path, target, size)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("read_bytes completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("read_bytes failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# ============================================================================
# Category 1: Advanced Analysis Tools
# ============================================================================

@mcp.tool()
def basic_blocks(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[str, "Hex or decimal function address"],
) -> str:
    """
    Get basic block information for a function.

    Args:
        file_path: Target binary file path
        address: Function address

    Returns:
        JSON string with basic blocks and control flow
    """
    try:
        logging.info("basic_blocks called: file_path=%s, address=%s", file_path, address)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        target = int(address, 0)
        shm_path = _create_shared_memory()
        script = script_basic_blocks(shm_path, target)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("basic_blocks completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("basic_blocks failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def find_bytes(
    file_path: Annotated[str, "Target binary file path"],
    pattern: Annotated[str, "Hex pattern with wildcards (e.g. '48 8B ? C3')"],
    start_ea: Annotated[str, "Start search address (hex or decimal)"] = "0",
    end_ea: Annotated[str, "End search address (hex or decimal)"] = "0xFFFFFFFFFFFFFFFF",
) -> str:
    """
    Search for byte patterns in binary.

    Args:
        file_path: Target binary file path
        pattern: Hex pattern with ? for wildcards
        start_ea: Start address (default: beginning)
        end_ea: End address (default: end)

    Returns:
        JSON string with matching addresses
    """
    try:
        logging.info("find_bytes called: file_path=%s, pattern=%s", file_path, pattern)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        start = int(start_ea, 0)
        end = int(end_ea, 0)
        shm_path = _create_shared_memory()
        script = script_find_bytes(shm_path, pattern, start, end)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("find_bytes completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("find_bytes failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def find(
    file_path: Annotated[str, "Target binary file path"],
    value: Annotated[str, "Immediate value to search for (hex or decimal)"],
) -> str:
    """
    Find immediate values in instructions.

    Args:
        file_path: Target binary file path
        value: Immediate value to search for

    Returns:
        JSON string with instructions containing the value
    """
    try:
        logging.info("find called: file_path=%s, value=%s", file_path, value)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        search_val = int(value, 0)
        shm_path = _create_shared_memory()
        script = script_find(shm_path, search_val)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("find completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("find failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def export_funcs(
    file_path: Annotated[str, "Target binary file path"],
    count: Annotated[int, "Max exports to return (0 = unlimited)"] = 100,
) -> str:
    """
    List exported functions from binary.

    Args:
        file_path: Target binary file path
        count: Maximum exports (default 100, 0 for all)

    Returns:
        JSON string with exported functions
    """
    try:
        logging.info("export_funcs called: file_path=%s, count=%d", file_path, count)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_export_funcs(shm_path, count)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("export_funcs completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("export_funcs failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def callgraph(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[str, "Hex or decimal function address"],
) -> str:
    """
    Get call graph (callers and callees) for a function.

    Args:
        file_path: Target binary file path
        address: Function address

    Returns:
        JSON string with callers and callees
    """
    try:
        logging.info("callgraph called: file_path=%s, address=%s", file_path, address)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        target = int(address, 0)
        shm_path = _create_shared_memory()
        script = script_callgraph(shm_path, target)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("callgraph completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("callgraph failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def find_regex(
    file_path: Annotated[str, "Target binary file path"],
    pattern: Annotated[str, "Regex pattern to search strings"],
    max_results: Annotated[int, "Maximum matches to return"] = 100,
) -> str:
    """
    Search strings using regular expressions.

    Args:
        file_path: Target binary file path
        pattern: Regex pattern
        max_results: Maximum results (default 100)

    Returns:
        JSON string with matching strings
    """
    try:
        logging.info("find_regex called: file_path=%s, pattern=%s", file_path, pattern)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_find_regex(shm_path, pattern, max_results)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("find_regex completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("find_regex failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def lookup_funcs(
    file_path: Annotated[str, "Target binary file path"],
    queries: Annotated[
        list[str],
        "Each entry: function name (e.g. 'sub_401000') or EA string ('0x401000' / decimal). Batch metadata lookup.",
    ],
) -> str:
    """
    Batch lookup functions by name or address.

    Args:
        file_path: Target binary file path
        queries: Function names or address strings

    Returns:
        JSON string with function metadata for each query
    """
    try:
        logging.info("lookup_funcs called: file_path=%s, queries=%s", file_path, queries)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_lookup_funcs(shm_path, queries)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("lookup_funcs completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("lookup_funcs failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# ============================================================================
# Category 2: Core Utilities
# ============================================================================

@mcp.tool()
def list_globals(
    file_path: Annotated[str, "Target binary file path"],
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0 = unlimited)"] = 100,
    filter: Annotated[str, "Name filter pattern"] = "",
) -> str:
    """
    List global variables with pagination and filtering.

    Args:
        file_path: Target binary file path
        offset: Pagination offset (default 0)
        count: Maximum results (default 100, 0 for all)
        filter: Name filter pattern (default: no filter)

    Returns:
        JSON string with global variables
    """
    try:
        logging.info("list_globals called: file_path=%s, offset=%d, count=%d, filter=%s",
                     file_path, offset, count, filter)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_list_globals(shm_path, offset, count, filter)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("list_globals completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("list_globals failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def int_convert(
    numbers: Annotated[
        list[dict],
        "Each dict: text (integer string, int(text,0): 0x.., decimal, 0b..), optional size 8|16|32|64 "
        "(masks value to that bit width; default 64).",
    ],
) -> str:
    """
    Convert numbers between hex, decimal, binary, and ASCII formats.

    Args:
        numbers: List of dicts with 'text' and optional 'size'

    Returns:
        JSON string with conversions
    """
    try:
        logging.info("int_convert called: numbers=%s", numbers)
        _setup_logging()
        shm_path = _create_shared_memory()
        script = script_int_convert(shm_path, numbers)
        # For int_convert, we don't need IDA - just run the script directly
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            temp_script = f.name
            f.write(script)
        
        try:
            result = subprocess.run(
                ["python", temp_script],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            with open(shm_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    data_bytes = mm.read().rstrip(b'\x00')
                    data = json.loads(data_bytes.decode('utf-8'))
            
            logging.info("int_convert completed successfully")
            return json.dumps(data, ensure_ascii=False, indent=2)
        finally:
            os.unlink(temp_script)
            os.unlink(shm_path)
    except Exception as e:
        logging.error("int_convert failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# ============================================================================
# Category 3: Memory Operations
# ============================================================================

@mcp.tool()
def get_int(
    file_path: Annotated[str, "Target binary file path"],
    queries: Annotated[
        list[dict],
        "Each dict: addr (hex/dec string), ty (i8|u8|i16|u16|i32|u32|i64|u64 + optional le|be, default le), "
        "e.g. 'u32le', 'i64be'.",
    ],
) -> str:
    """
    Read typed integers from memory.

    Args:
        file_path: Target binary file path
        queries: List of dicts with 'addr' and 'ty' (endian-sized integer format)

    Returns:
        JSON string with integer values
    """
    try:
        logging.info("get_int called: file_path=%s, queries=%s", file_path, queries)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_get_int(shm_path, queries)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("get_int completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("get_int failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def get_string(
    file_path: Annotated[str, "Target binary file path"],
    addresses: Annotated[
        list[str],
        "Each string is an EA (hex with 0x or decimal). Reads a C-style null-terminated string at that address.",
    ],
) -> str:
    """
    Read null-terminated strings from memory.

    Args:
        file_path: Target binary file path
        addresses: List of address strings

    Returns:
        JSON string with string values
    """
    try:
        logging.info("get_string called: file_path=%s, addresses=%s", file_path, addresses)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_get_string(shm_path, addresses)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("get_string completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("get_string failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def get_global_value(
    file_path: Annotated[str, "Target binary file path"],
    names: Annotated[
        list[str],
        "IDA public names for globals (as in the Names list), e.g. 'dword_403000', 'g_Initialized'.",
    ],
) -> str:
    """
    Read global variable values by name.

    Args:
        file_path: Target binary file path
        names: Global symbol names known to IDA

    Returns:
        JSON string with variable values
    """
    try:
        logging.info("get_global_value called: file_path=%s, names=%s", file_path, names)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_get_global_value(shm_path, names)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("get_global_value completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("get_global_value failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def patch(
    file_path: Annotated[str, "Target binary file path"],
    patches: Annotated[
        list[dict],
        "Each dict: addr (hex/dec EA string), bytes (space-separated hex byte tokens, e.g. '90 90 C3').",
    ],
) -> str:
    """
    Patch memory with arbitrary bytes.

    Args:
        file_path: Target binary file path
        patches: List of dicts with 'addr' and 'bytes' (space-separated hex)

    Returns:
        JSON string with patch results
    """
    try:
        logging.info("patch called: file_path=%s, patches=%s", file_path, patches)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_patch(shm_path, patches)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("patch completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("patch failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


@mcp.tool()
def put_int(
    file_path: Annotated[str, "Target binary file path"],
    writes: Annotated[
        list[dict],
        "Each dict: addr (hex/dec), ty (same as get_int: u32le, i64be, ...), value (integer or hex string like '0x10').",
    ],
) -> str:
    """
    Write typed integers to memory.

    Args:
        file_path: Target binary file path
        writes: List of dicts with 'addr', 'ty', and 'value'

    Returns:
        JSON string with write results
    """
    try:
        logging.info("put_int called: file_path=%s, writes=%s", file_path, writes)
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_put_int(shm_path, writes)
        data = _run_ida_script(idb_path, script, shm_path)
        logging.info("put_int completed successfully")
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("put_int failed: %s", str(e), exc_info=True)
        error_result = {"success": False, "error": str(e)}
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# ============================================================================
# Category 4-6: Modification, stack, and type tools
# ============================================================================

@mcp.tool()
def set_comments(
    file_path: Annotated[str, "Target binary file path (opens/creates cached .i64 like other tools)"],
    items: Annotated[
        list[dict],
        "Each dict: addr (hex/dec string, e.g. '0x401000'), comment (plain text). "
        "Sets a disassembly comment at that EA via idc.set_cmt (repeatable comment flag 0).",
    ],
) -> str:
    """
    Set disassembly comments at explicit addresses.

    Does not set decompiler-only comments; each item maps one EA to one string.
    """
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_set_comments(shm_path, items)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def patch_asm(
    file_path: Annotated[str, "Target binary file path"],
    items: Annotated[
        list[dict],
        "Each dict: addr (hex/dec string or int EA), asm (single instruction text as IDA accepts, "
        "e.g. 'nop' or 'mov rax, 1'). Uses idautils.Assemble then patch_byte per emitted byte.",
    ],
) -> str:
    """
    Assemble instructions in-place at given addresses.

    One list item = one instruction at one address. If assembly fails, that item returns an error in results.
    """
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_patch_asm(shm_path, items)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def rename(
    file_path: Annotated[str, "Target binary file path"],
    batch: Annotated[
        dict,
        "Batch spec: optional keys funcs, globals, locals, stack_vars (see long description). "
        "Omitted keys are treated as empty.",
    ],
) -> str:
    """
    Batch-rename functions, globals, Hex-Rays locals, or stack frame members in the IDB.

    Pass **one JSON object** with any of these optional array fields:

    **funcs** — rename a function (symbol at function start).
    Each element: `{"old": "<name|0xaddress>", "new": "<new name>"}`.
    `old` is resolved with `get_name_ea_simple` unless it starts with `0x`, then parsed as hex.

    **globals** — rename a global label / named data (same `old` / `new` shape as funcs).

    **locals** — rename a **decompiler local variable** inside one function.
    Each element: `{"func": "<function name|0xaddress>", "old": "<current lvar name>", "new": "<new name>"}`.
    Requires Hex-Rays decompilation; `old` must match the local name shown in pseudocode.

    **stack_vars** — rename a **stack frame member** (debugger/stack view name).
    Same shape as locals: `func`, `old`, `new`. Uses frame members, not pseudocode-only names.

    **Return value:** JSON with `success`, and per-category arrays `functions`, `globals`, `locals`,
    `stack_vars`. Each entry includes `ok`, `error` when failed, and may include `address` on success.

    **Minimal example:**
    ```json
    {
      "funcs": [{"old": "sub_401000", "new": "main"}],
      "globals": [{"old": "dword_403000", "new": "g_config"}]
    }
    ```

    **Local variable example:**
    ```json
    {
      "locals": [
        {"func": "0x401000", "old": "v5", "new": "user_count"}
      ]
    }
    ```
    """
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_rename(shm_path, batch)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def stack_frame(
    file_path: Annotated[str, "Target binary file path"],
    address: Annotated[
        str,
        "Function entry address (hex or decimal string). Stack layout is read for the function containing this EA.",
    ],
) -> str:
    """
    List stack frame members for a function (names, offsets, sizes, types).
    """
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        addr_int = int(address, 0)
        shm_path = _create_shared_memory()
        script = script_stack_frame(shm_path, addr_int)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def declare_stack(
    file_path: Annotated[str, "Target binary file path"],
    func_addr: Annotated[str, "Function entry EA (hex or decimal string)"],
    name: Annotated[str, "Name for the new stack variable"],
    offset: Annotated[int, "Stack offset (IDA frame member offset / soff, as used by ida_frame)"],
    type_str: Annotated[str, "C-style type string, e.g. 'int', 'char *', 'DWORD'"],
) -> str:
    """Declare or type a stack frame variable at the given offset for a function."""
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        addr_int = int(func_addr, 0)
        shm_path = _create_shared_memory()
        script = script_declare_stack(shm_path, addr_int, name, offset, type_str)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def delete_stack(
    file_path: Annotated[str, "Target binary file path"],
    func_addr: Annotated[str, "Function entry EA (hex or decimal string)"],
    name: Annotated[str, "Existing stack member name to remove"],
) -> str:
    """Remove a stack frame member by name from the given function."""
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        addr_int = int(func_addr, 0)
        shm_path = _create_shared_memory()
        script = script_delete_stack(shm_path, addr_int, name)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def declare_type(
    file_path: Annotated[str, "Target binary file path"],
    decls: Annotated[
        list[str],
        "C declarations to parse into the local type library, e.g. 'struct foo { int x; }', "
        "'typedef unsigned long ulong_t'. Each string is passed to parse_decl (PT_SIL).",
    ],
) -> str:
    """Parse C type declarations and validate/import into IDA local types (tinfo)."""
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_declare_type(shm_path, decls)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def read_struct(
    file_path: Annotated[str, "Target binary file path"],
    queries: Annotated[
        list[dict],
        "Each dict: addr (hex/dec EA string), type (struct type name as in IDA). "
        "Reads raw bytes for the struct size at addr; non-struct types return an error in that result.",
    ],
) -> str:
    """Read memory at an address as a struct: returns size and raw hex bytes (field decode is simplified)."""
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_read_struct(shm_path, queries)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def search_structs(
    file_path: Annotated[str, "Target binary file path"],
    pattern: Annotated[
        str,
        "Case-insensitive regex matched against struct names in the local types (e.g. '.*NET.*', '^my_').",
    ],
) -> str:
    """List structs whose names match a regex (name, size, member_count)."""
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_search_structs(shm_path, pattern)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def set_type(
    file_path: Annotated[str, "Target binary file path"],
    items: Annotated[
        list[dict],
        "Each dict: addr (hex/dec EA string), type (C type expression IDA accepts: 'int', 'void *', "
        "'struct foo', etc.). Applies at runtime via apply_type / SetType / apply_tinfo.",
    ],
) -> str:
    """Apply a C type to a program address (variable, data, or function prototype context per IDA rules)."""
    try:
        _setup_logging()
        _ensure_paths()
        idb_path = ensure_i64(os.path.abspath(file_path))
        shm_path = _create_shared_memory()
        script = script_set_type(shm_path, items)
        data = _run_ida_script(idb_path, script, shm_path)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)

@mcp.tool()
def infer_types(
    file_path: Annotated[str, "Reserved for future use; currently ignored"],
    address: Annotated[str, "Reserved for future use; currently ignored"],
) -> str:
    """
    Placeholder for automated type inference at a function or address.

    Not implemented yet; returns a JSON error. Use decompile_function, set_type, or declare_type instead.
    """
    return json.dumps({"success": False, "error": "infer_types not yet implemented"}, indent=2)


def install_mcp_servers(ida_path: str, idat_path: str) -> int:
    """
    Install MCP server configuration to all detected MCP clients
    Returns number of clients configured
    """
    import sys
    from pathlib import Path
    
    # Get configuration paths for all MCP clients
    if sys.platform == "win32":
        configs = {
            "Cline": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude Desktop": (os.path.join(os.getenv("APPDATA", ""), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.expanduser("~"), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codebuddy Code": (os.path.join(os.path.expanduser("~"), ".codebuddy"), "mcp.json"),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude Desktop": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.expanduser("~"), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codebuddy Code": (os.path.join(os.path.expanduser("~"), ".codebuddy"), "mcp.json"),
        }
    else:  # Linux
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.expanduser("~"), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codebuddy Code": (os.path.join(os.path.expanduser("~"), ".codebuddy"), "mcp.json"),
        }
    
    # Create server configuration
    server_config = {
        "command": sys.executable,
        "args": ["-m", "ida_pro_mcp_plus.server"],
        "env": {
            "IDA64_PATH": str(ida_path).replace("\\", "/"),
            "IDAT64_PATH": str(idat_path).replace("\\", "/"),
            "I64_CACHE_DIR": ".i64_cache",
            "IDA_TIMEOUT": "120",
            "IDA_BUILD_TIMEOUT": "1800",
            "IDA_SHM_SIZE": "20971520",
            "IDA_KEEP_UNPACKED": "0"
        },
        "timeout": 1800,
        "disabled": False,
    }
    
    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        
        # Skip if client not installed
        if not os.path.exists(config_dir):
            continue
        
        # Load existing config
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = f.read().strip()
                    config = json.loads(data) if data else {}
            except:
                config = {}
        else:
            config = {}
        
        # Ensure mcpServers exists
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        
        # Add/update server
        config["mcpServers"]["ida-pro-mcp-plus"] = server_config
        
        # Save config
        try:
            os.makedirs(config_dir, exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"✅ Configured {name}: {config_path}")
            installed += 1
        except Exception as e:
            print(f"❌ Failed to configure {name}: {e}")
    
    return installed

def main():
    """Main entry point for ida-mcp-plus command"""
    import argparse
    import sys
    from pathlib import Path
    
    parser = argparse.ArgumentParser(
        description="ida-pro-mcp-plus - Enhanced IDA Pro MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ida-mcp-plus                    # Run MCP server
  ida-mcp-plus --install          # Install to all MCP clients
  ida-mcp-plus --config           # Show configuration template
  ida-mcp-plus --help             # Show this help

Documentation: https://github.com/GameSecurityFrontierLib/ida-pro-mcp-plus
"""
    )
    parser.add_argument("--install", action="store_true", help="Install MCP server to all detected clients")
    parser.add_argument("--config", action="store_true", help="Print configuration template")
    
    args = parser.parse_args()
    
    if args.install:
        print("\n" + "=" * 70)
        print("🚀 ida-pro-mcp-plus Installation")
        print("=" * 70)
        print()
        
        # Get IDA paths
        ida_path = input("Enter path to ida.exe (or ida64): ").strip().strip('"').strip("'")
        idat_path = input("Enter path to idat.exe (or idat64): ").strip().strip('"').strip("'")
        
        if not Path(ida_path).exists():
            print(f"❌ File not found: {ida_path}")
            sys.exit(1)
        if not Path(idat_path).exists():
            print(f"❌ File not found: {idat_path}")
            sys.exit(1)
        
        print()
        print("📝 Installing to all detected MCP clients...")
        print()
        
        installed = install_mcp_servers(ida_path, idat_path)
        
        print()
        if installed > 0:
            print("=" * 70)
            print(f"🎉 Successfully configured {installed} client(s)!")
            print("=" * 70)
            print()
            print("Next steps:")
            print("  1. Restart your MCP client(s)")
            print("  2. Verify connection")
            print()
        else:
            print("⚠️  No MCP clients found")
            print("   Install an MCP client and run again")
            print()
        
        return
    
    if args.config:
        print("\n" + "=" * 70)
        print("ida-pro-mcp-plus Configuration Template")
        print("=" * 70)
        print()
        config = {
            "mcpServers": {
                "ida-pro-mcp-plus": {
                    "command": sys.executable,
                    "args": ["-m", "ida_pro_mcp_plus.server"],
                    "env": {
                        "IDA64_PATH": "<PATH_TO_IDA>",
                        "IDAT64_PATH": "<PATH_TO_IDAT>",
                        "I64_CACHE_DIR": ".i64_cache",
                        "IDA_TIMEOUT": "120",
                        "IDA_BUILD_TIMEOUT": "1800",
                        "IDA_KEEP_UNPACKED": "0"
                    },
                    "timeout": 1800,
                    "disabled": False
                }
            }
        }
        print(json.dumps(config, indent=2))
        print()
        return
    
    # Default: Run MCP server
    _setup_logging()
    _log_configuration()
    _ensure_paths()
    logging.info("Path validation successful - Server ready to accept requests")
    mcp.run()

if __name__ == "__main__":
    main()
