"""
IDA Script Generation Module - Core Utilities

This module contains script generators for core utility operations:
- Global variable listing
- Number format conversion


Project: ida-pro-mcp-plus
Author: oxygen
Email: 304914289@qq.com
"""


def script_list_globals(shm_path: str, offset: int, count: int, filter_str: str) -> str:
    """
    Generate IDA script to list global variables.
    
    Args:
        shm_path: Path to shared memory file for results
        offset: Pagination offset
        count: Maximum results (0 = unlimited)
        filter_str: Name filter pattern
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idautils
import idc
import ida_name
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
OFFSET = {offset}
COUNT = {count}
FILTER = r"{filter_str}"

idaapi.auto_wait()

result = {{"success": True, "globals": [], "total_count": 0}}

try:
    all_globals = []
    
    for ea in idautils.Names():
        name = ida_name.get_name(ea[0])
        if name:
            if FILTER and FILTER.lower() not in name.lower():
                continue
            
            all_globals.append({{
                "name": name,
                "address": hex(ea[0]),
                "size": idc.get_item_size(ea[0]) if idc.get_item_size(ea[0]) > 0 else None
            }})
    
    result["total_count"] = len(all_globals)
    
    end_idx = OFFSET + COUNT if COUNT > 0 else len(all_globals)
    result["globals"] = all_globals[OFFSET:end_idx]
    result["has_more"] = end_idx < len(all_globals)
    
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_stop_auto_analysis(shm_path: str, save_idb: bool) -> str:
    """
    Generate IDA script to suspend auto-analysis and clear analyzer queues.

    Does not call idaapi.auto_wait(). Optional save via idc.qexit(1).
    """
    return f"""
import json
import mmap
import idc
import ida_auto
import ida_ida

SHARED_MEM_PATH = r"{shm_path}"
SAVE_IDB = {save_idb}

ida_auto.enable_auto(False)
min_ea = ida_ida.inf_get_min_ea()
max_ea = ida_ida.inf_get_max_ea()

QUEUE_TYPES = (
    ida_auto.AU_UNK,
    ida_auto.AU_CODE,
    ida_auto.AU_WEAK,
    ida_auto.AU_PROC,
    ida_auto.AU_TAIL,
    ida_auto.AU_FCHUNK,
    ida_auto.AU_USED,
    ida_auto.AU_USD2,
    ida_auto.AU_TYPE,
    ida_auto.AU_LIBF,
    ida_auto.AU_LBF2,
    ida_auto.AU_LBF3,
    ida_auto.AU_CHLB,
    ida_auto.AU_FINAL,
)
errors = []
for qt in QUEUE_TYPES:
    try:
        ida_auto.auto_unmark(min_ea, max_ea, qt)
    except Exception as e:
        errors.append({{"queue": repr(qt), "error": str(e)}})

try:
    ida_auto.auto_cancel(min_ea, max_ea)
except Exception as e:
    errors.append({{"op": "auto_cancel", "error": str(e)}})

result = {{
    "success": True,
    "auto_is_ok": ida_auto.auto_is_ok(),
    "is_auto_enabled": ida_auto.is_auto_enabled(),
    "queue_clear_errors": errors,
}}

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

if SAVE_IDB:
    idc.qexit(1)
else:
    idc.qexit(0)
"""


def script_int_convert(shm_path: str, numbers: list) -> str:
    """
    Generate script to convert numbers to different formats.
    
    Args:
        shm_path: Path to shared memory file for results
        numbers: List of dicts with 'text' and optional 'size'
    
    Returns:
        Complete Python script as string
    """
    import json as json_module
    numbers_json = json_module.dumps(numbers)
    
    return f"""
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
NUMBERS = {numbers_json}

result = {{"success": True, "results": []}}

try:
    for item in NUMBERS:
        text = item.get('text', '')
        size = item.get('size', 64)
        
        try:
            value = int(text, 0)
            
            if size == 8:
                value = value & 0xFF
            elif size == 16:
                value = value & 0xFFFF
            elif size == 32:
                value = value & 0xFFFFFFFF
            elif size == 64:
                value = value & 0xFFFFFFFFFFFFFFFF
            
            result_item = {{
                "decimal": value,
                "hex": hex(value),
                "binary": bin(value),
                "ascii": chr(value) if 32 <= value <= 126 else None
            }}
            result["results"].append(result_item)
        except Exception as e:
            result["results"].append({{"error": str(e)}})
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))
"""
