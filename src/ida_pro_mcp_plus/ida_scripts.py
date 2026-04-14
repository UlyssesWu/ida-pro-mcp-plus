"""
IDA Script Generation Module

This module contains all IDA Python script generators for MCP tools.
Each function generates a complete IDA Python script that:
1. Waits for IDA auto-analysis to complete
2. Performs the requested operation using IDA API
3. Writes results to shared memory as JSON
4. Exits IDA cleanly

Script Generator Naming Convention:
- Function name: script_<tool_name>
- Parameters: shm_path (shared memory file path) + tool-specific params
- Returns: Complete IDA Python script as string

Adding New Tools:
1. Create script_<new_tool>() function in this file
2. Import the function in ida-pro-mcp-server.py
3. Call it from the MCP tool function via _run_ida_script()


Project: ida-pro-mcp-plus
Author: oxygen
Email: 304914289@qq.com
"""


def script_list_strings(shm_path: str, count: int) -> str:
    """
    Generate IDA script to list strings from the binary.
    
    Args:
        shm_path: Path to shared memory file for results
        count: Maximum number of strings to return (0 = unlimited)
    
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

result = {{"success": True, "strings": []}}

try:
    strings = idautils.Strings()
    try:
        strings.setup()
    except Exception:
        # Older/newer IDA builds may not require setup()
        pass

    for index, s in enumerate(strings):
        if MAX_COUNT and index >= MAX_COUNT:
            break
        value = str(s)
        result["strings"].append({{
            "ea": hex(s.ea),
            "string": value,
            "length": len(value)
        }})
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_disassemble_function(shm_path: str, address: int) -> str:
    """
    Generate IDA script to disassemble a function.
    
    Args:
        shm_path: Path to shared memory file for results
        address: Target function address
    
    Returns:
        Complete IDA Python script as string
    """
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


def script_decompile_function(shm_path: str, address: int) -> str:
    """
    Generate IDA script to decompile a function to pseudocode.
    
    Args:
        shm_path: Path to shared memory file for results
        address: Target function address
    
    Returns:
        Complete IDA Python script as string
    """
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


def script_batch_decompile_functions(
    shm_path: str,
    targets: list[str],
    deduplicate: bool = True,
) -> str:
    """
    Generate IDA script to decompile multiple functions in one IDA run.

    Args:
        shm_path: Path to shared memory file for results
        targets: List of hex/decimal addresses or function names
        deduplicate: If true, decompile each resolved function start once

    Returns:
        Complete IDA Python script as string
    """
    script_template = r"""
import idaapi
import idc
import json
import mmap

SHARED_MEM_PATH = __SHM_PATH__
TARGETS = __TARGETS__
DEDUPLICATE = __DEDUP__

idaapi.auto_wait()

result = {"success": True, "functions": [], "requested_count": len(TARGETS)}
seen_funcs = set()

def _resolve_target(raw):
    text = str(raw).strip()
    if not text:
        return idaapi.BADADDR, "Empty target"
    try:
        return int(text, 0), None
    except Exception:
        pass
    ea = idc.get_name_ea_simple(text)
    if ea == idaapi.BADADDR:
        return idaapi.BADADDR, "Target not found: " + text
    return ea, None

for raw_target in TARGETS:
    item = {"query": str(raw_target)}
    ea, resolve_error = _resolve_target(raw_target)
    if resolve_error:
        item["success"] = False
        item["error"] = resolve_error
        result["functions"].append(item)
        continue

    item["resolved_ea"] = hex(ea)
    func = idaapi.get_func(ea)
    if not func:
        item["success"] = False
        item["error"] = "No function found for target " + str(raw_target)
        result["functions"].append(item)
        continue

    func_start = func.start_ea
    item["function_start"] = hex(func_start)
    item["function_name"] = idc.get_func_name(func_start)
    item["function_size"] = hex(func.end_ea - func.start_ea)

    if DEDUPLICATE and func_start in seen_funcs:
        item["success"] = True
        item["skipped"] = True
        item["reason"] = "Duplicate function start"
        result["functions"].append(item)
        continue

    seen_funcs.add(func_start)

    try:
        cfunc = idaapi.decompile(func_start)
        if cfunc:
            item["success"] = True
            item["pseudocode"] = str(cfunc)
        else:
            item["success"] = False
            item["error"] = "Decompilation failed for function " + item["function_name"]
    except Exception as e:
        item["success"] = False
        item["error"] = "Decompilation error: " + str(e)

    result["functions"].append(item)

result["returned_count"] = len(result["functions"])
result["decompiled_count"] = len(
    [f for f in result["functions"] if f.get("success") and not f.get("skipped")]
)
result["failed_count"] = len([f for f in result["functions"] if not f.get("success")])

if result["requested_count"] == 0:
    result["success"] = False
    result["error"] = "No targets provided"
elif result["decompiled_count"] == 0 and result["failed_count"] > 0:
    result["success"] = False

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
    return (
        script_template
        .replace("__SHM_PATH__", repr(shm_path))
        .replace("__TARGETS__", repr([str(t) for t in targets]))
        .replace("__DEDUP__", "True" if deduplicate else "False")
    )


def script_list_functions(shm_path: str, offset: int, count: int, filter_pattern: str) -> str:
    """
    Generate IDA script to list functions with pagination and filtering.
    
    Args:
        shm_path: Path to shared memory file for results
        offset: Starting offset for pagination
        count: Maximum number of functions to return (0 = unlimited)
        filter_pattern: Case-insensitive substring filter for function names
    
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
OFFSET = {offset}
MAX_COUNT = {count}
FILTER = r"{filter_pattern}"

idaapi.auto_wait()

result = {{"success": True, "functions": [], "total_count": 0, "has_more": False}}

# Collect all functions
all_funcs = []
for ea in idautils.Functions():
    func_name = idc.get_func_name(ea)
    
    # Apply filter if specified
    if FILTER and FILTER.lower() not in func_name.lower():
        continue
    
    func = idaapi.get_func(ea)
    if func:
        all_funcs.append({{
            "name": func_name,
            "address": hex(ea),
            "size": hex(func.end_ea - func.start_ea)
        }})

result["total_count"] = len(all_funcs)

# Apply pagination
if MAX_COUNT == 0:
    # Return all
    result["functions"] = all_funcs[OFFSET:]
else:
    end_idx = OFFSET + MAX_COUNT
    result["functions"] = all_funcs[OFFSET:end_idx]
    result["has_more"] = end_idx < len(all_funcs)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

import idc
idc.qexit(0)
"""


def script_get_function_info(shm_path: str, address: int) -> str:
    """
    Generate IDA script to get detailed function information.
    
    Args:
        shm_path: Path to shared memory file for results
        address: Target function address
    
    Returns:
        Complete IDA Python script as string
    """
    script_template = r"""
import idaapi
import idc
import ida_name
import idautils
import json
import mmap

SHARED_MEM_PATH = r"%(shm_path)s"
TARGET_EA = %(address)d

idaapi.auto_wait()

result = {"success": True}

func = idaapi.get_func(TARGET_EA)
if not func:
    result["success"] = False
    result["error"] = "No function found for address " + hex(TARGET_EA)
else:
    func_name = idc.get_func_name(func.start_ea)
    
    # Get demangled name if available
    demangled = ida_name.get_ea_name(func.start_ea, ida_name.GN_VISIBLE)
    
    # Get function flags
    flags = func.flags
    is_lib = bool(flags & idaapi.FUNC_LIB)
    is_thunk = bool(flags & idaapi.FUNC_THUNK)
    
    # Count xrefs to this function (callers)
    xref_count = 0
    for xref in idautils.XrefsTo(func.start_ea):
        xref_count += 1
    
    result["function"] = {
        "name": func_name,
        "demangled": demangled if demangled != func_name else None,
        "start_address": hex(func.start_ea),
        "end_address": hex(func.end_ea),
        "size": hex(func.end_ea - func.start_ea),
        "frame_size": hex(func.frsize) if hasattr(func, 'frsize') else "0x0",
        "is_library": is_lib,
        "is_thunk": is_thunk,
        "xref_count": xref_count
    }

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
    return script_template % {"shm_path": shm_path, "address": address}


def script_list_imports(shm_path: str, offset: int, count: int) -> str:
    """
    Generate IDA script to list imported functions.
    
    Args:
        shm_path: Path to shared memory file for results
        offset: Starting offset for pagination
        count: Maximum number of imports to return (0 = unlimited)
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idc
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
OFFSET = {offset}
MAX_COUNT = {count}

idaapi.auto_wait()

result = {{"success": True, "imports": [], "total_count": 0, "has_more": False}}

# Collect all imports
all_imports = []

nimps = idaapi.get_import_module_qty()
for i in range(nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        continue
    
    def imp_cb(ea, imp_name, ordinal):
        if not imp_name:
            imp_name = f"ord_{{ordinal}}"
        
        all_imports.append({{
            "module": name,
            "name": imp_name,
            "address": hex(ea),
            "ordinal": ordinal if ordinal != 0 else None
        }})
        return True
    
    idaapi.enum_import_names(i, imp_cb)

result["total_count"] = len(all_imports)

# Apply pagination
if MAX_COUNT == 0:
    result["imports"] = all_imports[OFFSET:]
else:
    end_idx = OFFSET + MAX_COUNT
    result["imports"] = all_imports[OFFSET:end_idx]
    result["has_more"] = end_idx < len(all_imports)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

import idc
idc.qexit(0)
"""


def script_xrefs_to(shm_path: str, addresses: list) -> str:
    """
    Generate IDA script to find cross-references to addresses.
    
    Args:
        shm_path: Path to shared memory file for results
        addresses: List of target addresses to find xrefs to
    
    Returns:
        Complete IDA Python script as string
    """
    addresses_str = ", ".join([f"0x{addr:x}" if isinstance(addr, int) else f"{addr}" for addr in addresses])
    
    return f"""
import idaapi
import idautils
import idc
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
TARGET_ADDRS = [{addresses_str}]
MAX_XREFS_PER_ADDR = 1000

idaapi.auto_wait()

result = {{"success": True, "xrefs": {{}}}}

for addr_str in TARGET_ADDRS:
    if isinstance(addr_str, str):
        target_ea = int(addr_str, 0)
    else:
        target_ea = addr_str
    
    xrefs = []
    count = 0
    
    for xref in idautils.XrefsTo(target_ea):
        if count >= MAX_XREFS_PER_ADDR:
            break
        
        # Get xref type
        xref_type = "unknown"
        if xref.type == idaapi.fl_CN:
            xref_type = "call_near"
        elif xref.type == idaapi.fl_CF:
            xref_type = "call_far"
        elif xref.type == idaapi.fl_JN:
            xref_type = "jump_near"
        elif xref.type == idaapi.fl_JF:
            xref_type = "jump_far"
        elif xref.type in [idaapi.dr_R, idaapi.dr_O]:
            xref_type = "data_read"
        elif xref.type == idaapi.dr_W:
            xref_type = "data_write"
        
        # Get instruction at xref location
        insn_text = idc.GetDisasm(xref.frm)
        
        xrefs.append({{
            "from_address": hex(xref.frm),
            "to_address": hex(target_ea),
            "type": xref_type,
            "instruction": insn_text
        }})
        count += 1
    
    result["xrefs"][hex(target_ea)] = {{
        "items": xrefs,
        "total": count,
        "truncated": count >= MAX_XREFS_PER_ADDR
    }}

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

import idc
idc.qexit(0)
"""


def script_get_callees(shm_path: str, address: int) -> str:
    """
    Generate IDA script to get functions called by a function.
    
    Args:
        shm_path: Path to shared memory file for results
        address: Target function address
    
    Returns:
        Complete IDA Python script as string
    """
    script_template = r"""
import idaapi
import idautils
import idc
import json
import mmap

SHARED_MEM_PATH = r"%(shm_path)s"
TARGET_EA = %(address)d

idaapi.auto_wait()

result = {"success": True, "callees": []}

func = idaapi.get_func(TARGET_EA)
if not func:
    result["success"] = False
    result["error"] = "No function found for address " + hex(TARGET_EA)
else:
    seen_callees = set()
    
    # Iterate through all instructions in the function
    for ea in idautils.FuncItems(func.start_ea):
        # Get xrefs from this instruction
        for xref in idautils.XrefsFrom(ea, 0):
            # Check if it's a call
            if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                target_ea = xref.to
                
                if target_ea in seen_callees:
                    continue
                seen_callees.add(target_ea)
                
                target_name = idc.get_func_name(target_ea)
                if not target_name:
                    target_name = idc.get_name(target_ea) or f"sub_{target_ea:x}"
                
                call_type = "direct"
                target_func = idaapi.get_func(target_ea)
                
                result["callees"].append({
                    "address": hex(target_ea),
                    "name": target_name,
                    "call_type": call_type,
                    "is_function": target_func is not None
                })

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
    return script_template % {"shm_path": shm_path, "address": address}


def script_read_bytes(shm_path: str, address: int, size: int) -> str:
    """
    Generate IDA script to read raw bytes from memory.
    
    Args:
        shm_path: Path to shared memory file for results
        address: Starting address to read from
        size: Number of bytes to read
    
    Returns:
        Complete IDA Python script as string
    """
    script_template = r"""
import idaapi
import ida_bytes
import idc
import json
import mmap

SHARED_MEM_PATH = r"%(shm_path)s"
TARGET_EA = %(address)d
READ_SIZE = %(size)d

idaapi.auto_wait()

result = {"success": True}

# Check if address is valid
if not idaapi.is_loaded(TARGET_EA):
    result["success"] = False
    result["error"] = f"Address {hex(TARGET_EA)} is not mapped in the binary"
else:
    # Try to read bytes
    data = ida_bytes.get_bytes(TARGET_EA, READ_SIZE)
    
    if data is None:
        # Try to read what's available
        available = 0
        test_ea = TARGET_EA
        while idaapi.is_loaded(test_ea) and available < READ_SIZE:
            available += 1
            test_ea += 1
        
        if available > 0:
            data = ida_bytes.get_bytes(TARGET_EA, available)
            result["bytes"] = data.hex() if data else ""
            result["address"] = hex(TARGET_EA)
            result["requested_size"] = READ_SIZE
            result["actual_size"] = available
            result["warning"] = f"Only {available} bytes available, truncated from {READ_SIZE}"
        else:
            result["success"] = False
            result["error"] = "Unable to read any bytes from address"
    else:
        result["bytes"] = data.hex()
        result["address"] = hex(TARGET_EA)
        result["requested_size"] = READ_SIZE
        result["actual_size"] = len(data)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
    return script_template % {
        "shm_path": shm_path,
        "address": address,
        "size": size,
    }


# ============================================================================
# Category 1: Advanced Analysis Tools
# ============================================================================
