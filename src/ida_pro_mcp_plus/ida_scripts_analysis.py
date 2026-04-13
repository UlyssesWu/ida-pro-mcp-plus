"""
IDA Script Generation Module - Advanced Analysis Tools

This module contains script generators for advanced code analysis operations:
- Basic block analysis
- Byte pattern searching
- Immediate value finding
- Export function listing
- Call graph analysis
- Regex string searching
- Batch function lookup


Project: ida-pro-mcp-plus
Author: oxygen
Email: 304914289@qq.com
"""


def script_basic_blocks(shm_path: str, address: int) -> str:
    """
    Generate IDA script to get basic block information for a function.
    
    Args:
        shm_path: Path to shared memory file for results
        address: Target function address
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idautils
import idc
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
TARGET_EA = {address}

idaapi.auto_wait()

result = {{"success": True, "blocks": []}}

try:
    func = idaapi.get_func(TARGET_EA)
    if not func:
        result["success"] = False
        result["error"] = f"No function found at {{hex(TARGET_EA)}}"
    else:
        flowchart = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
        for block in flowchart:
            successors = []
            for succ_block in block.succs():
                successors.append(hex(succ_block.start_ea))
            
            result["blocks"].append({{
                "start_ea": hex(block.start_ea),
                "end_ea": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "successors": successors
            }})
        result["function"] = hex(func.start_ea)
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_find_bytes(shm_path: str, pattern: str, start_ea: int, end_ea: int) -> str:
    """
    Generate IDA script to search for byte patterns.
    
    Args:
        shm_path: Path to shared memory file for results
        pattern: Hex pattern with wildcards (e.g., "48 8B ? C3")
        start_ea: Start search address
        end_ea: End search address
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import ida_bytes
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
PATTERN = "{pattern}"
START_EA = {start_ea}
END_EA = {end_ea}

# IDA 9.x: BIN_SEARCH_* lives in ida_bytes (optional BIN_SEARCH_NOSHOW). IDA 7.x: some builds only expose it on ida_search.
_fwd = getattr(ida_bytes, "BIN_SEARCH_FORWARD", None)
if _fwd is not None:
    _SEARCH_FLAGS = _fwd | getattr(ida_bytes, "BIN_SEARCH_NOSHOW", 0)
else:
    import ida_search
    _SEARCH_FLAGS = ida_search.BIN_SEARCH_FORWARD


def _bin_search_compat(start_ea, end_ea, image, mask, pat_len, flags):
    try:
        return ida_bytes.bin_search(start_ea, end_ea, image, mask, pat_len, flags)
    except TypeError:
        if mask is not None:
            return ida_bytes.bin_search(start_ea, end_ea, image, mask, flags)
        return ida_bytes.bin_search(start_ea, end_ea, image, None, flags)


idaapi.auto_wait()

result = {{"success": True, "matches": [], "pattern": PATTERN}}

try:
    # Convert pattern string to bytes for searching
    pattern_parts = PATTERN.split()
    search_bytes = []
    mask_bytes = []
    
    for part in pattern_parts:
        if part == '?':
            search_bytes.append(0)
            mask_bytes.append(0)
        else:
            search_bytes.append(int(part, 16))
            mask_bytes.append(0xFF)
    
    pattern_bytes = bytes(search_bytes)
    mask = bytes(mask_bytes) if 0 in mask_bytes else None
    pat_len = len(pattern_bytes)
    
    ea = START_EA
    while ea < END_EA:
        ea = _bin_search_compat(ea, END_EA, pattern_bytes, mask, pat_len, _SEARCH_FLAGS)
        
        if ea == idaapi.BADADDR:
            break
        
        result["matches"].append(hex(ea))
        ea += 1
        
        if len(result["matches"]) >= 1000:
            result["truncated"] = True
            break
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

import idc
idc.qexit(0)
"""


def script_find(shm_path: str, value: int) -> str:
    """
    Generate IDA script to find immediate values in instructions.
    
    Args:
        shm_path: Path to shared memory file for results
        value: Immediate value to search for
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idautils
import idc
import ida_ua
import ida_segment
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
SEARCH_VALUE = {value}

idaapi.auto_wait()

result = {{"success": True, "instructions": [], "value": SEARCH_VALUE}}

try:
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or seg.type != ida_segment.SEG_CODE:
            continue
        
        ea = seg.start_ea
        while ea < seg.end_ea:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) > 0:
                for op_idx in range(8):
                    op = insn.ops[op_idx]
                    if op.type == ida_ua.o_void:
                        break
                    if op.type == ida_ua.o_imm:
                        if op.value == SEARCH_VALUE:
                            result["instructions"].append({{
                                "address": hex(ea),
                                "operand_index": op_idx,
                                "disassembly": idc.GetDisasm(ea)
                            }})
                            break
                ea = insn.ea + insn.size
            else:
                ea += 1
            
            if len(result["instructions"]) >= 1000:
                result["truncated"] = True
                break
        
        if result.get("truncated"):
            break
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_export_funcs(shm_path: str, count: int) -> str:
    """
    Generate IDA script to list exported functions.
    
    Args:
        shm_path: Path to shared memory file for results
        count: Maximum number of exports to return (0 = unlimited)
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idautils
import idc
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
MAX_COUNT = {count}

idaapi.auto_wait()

result = {{"success": True, "exports": []}}

try:
    for entry in idautils.Entries():
        # IDA may return either 3-tuple or 4-tuple depending on version.
        if len(entry) == 4:
            _, ordinal, ea, name = entry
        elif len(entry) == 3:
            ea, name, ordinal = entry
        else:
            continue

        if MAX_COUNT and len(result["exports"]) >= MAX_COUNT:
            result["has_more"] = True
            break

        result["exports"].append({{
            "name": name,
            "address": hex(ea),
            "ordinal": ordinal if ordinal else None
        }})
    
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_callgraph(shm_path: str, address: int) -> str:
    """
    Generate IDA script to get call graph (callers + callees).
    
    Args:
        shm_path: Path to shared memory file for results
        address: Target function address
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idautils
import idc
import ida_xref
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
TARGET_EA = {address}

idaapi.auto_wait()

result = {{"success": True, "callers": [], "callees": []}}

try:
    func = idaapi.get_func(TARGET_EA)
    if not func:
        result["success"] = False
        result["error"] = f"No function found at {{hex(TARGET_EA)}}"
    else:
        result["function"] = hex(func.start_ea)
        
        # Get callers
        for xref in idautils.XrefsTo(func.start_ea, 0):
            if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                caller_func = idaapi.get_func(xref.frm)
                if caller_func:
                    call_type = "direct" if xref.type == ida_xref.fl_CN else "indirect"
                    result["callers"].append({{
                        "address": hex(caller_func.start_ea),
                        "name": idc.get_func_name(caller_func.start_ea),
                        "call_from": hex(xref.frm),
                        "call_type": call_type
                    }})
        
        # Get callees
        for item_ea in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    callee_func = idaapi.get_func(xref.to)
                    if callee_func:
                        call_type = "direct" if xref.type == ida_xref.fl_CN else "indirect"
                        callee_entry = {{
                            "address": hex(callee_func.start_ea),
                            "name": idc.get_func_name(callee_func.start_ea),
                            "call_type": call_type
                        }}
                        if callee_entry not in result["callees"]:
                            result["callees"].append(callee_entry)
        
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_find_regex(shm_path: str, pattern: str, max_results: int) -> str:
    """
    Generate IDA script to search strings with regex.
    
    Args:
        shm_path: Path to shared memory file for results
        pattern: Regex pattern to search for
        max_results: Maximum number of matches to return
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idautils
import idc
import re
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
PATTERN = r"{pattern}"
MAX_RESULTS = {max_results}

idaapi.auto_wait()

result = {{"success": True, "matches": [], "pattern": PATTERN}}

try:
    regex = re.compile(PATTERN, re.IGNORECASE)
    
    for s in idautils.Strings():
        string_val = str(s)
        if regex.search(string_val):
            result["matches"].append({{
                "address": hex(s.ea),
                "value": string_val,
                "length": len(string_val)
            }})
            
            if len(result["matches"]) >= MAX_RESULTS:
                result["truncated"] = True
                break
                
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_lookup_funcs(shm_path: str, queries: list) -> str:
    """
    Generate IDA script for batch function lookup.
    
    Args:
        shm_path: Path to shared memory file for results
        queries: List of function names or addresses to look up
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    queries_json = json_module.dumps(queries)
    
    return f"""
import idaapi
import idautils
import idc
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
QUERIES = {queries_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

try:
    for query in QUERIES:
        query_result = {{"query": query, "function": None, "error": None}}
        
        try:
            # Extract query value based on type
            if isinstance(query, dict):
                query_type = query.get("type", "address")
                query_value = query.get("value", "")
            else:
                # Legacy: treat as string
                query_value = str(query)
                query_type = "auto"
            
            # Determine address from query
            if query_type == "address" or query_value.startswith("0x") or query_value.startswith("0X"):
                ea = int(query_value, 16) if isinstance(query_value, str) else query_value
            elif query_type == "name" or not query_value.startswith("0x"):
                ea = idc.get_name_ea_simple(query_value)
            elif query_value.startswith("sub_"):
                ea = int(query_value[4:], 16)
            else:
                ea = idc.get_name_ea_simple(query_value)
            
            if ea == idaapi.BADADDR:
                query_result["error"] = "Not found"
            else:
                func = idaapi.get_func(ea)
                if not func:
                    query_result["error"] = "Not a function"
                else:
                    query_result["function"] = {{
                        "name": idc.get_func_name(func.start_ea),
                        "address": hex(func.start_ea),
                        "end_address": hex(func.end_ea),
                        "size": func.end_ea - func.start_ea
                    }}
        except Exception as e:
            query_result["error"] = str(e)
        
        result["results"].append(query_result)
        
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
