"""
IDA Script Generation Module - Type System Tools

This module contains script generators for type system operations:
- Type declaration
- Struct reading
- Struct searching
- Type application


Project: ida-pro-mcp-plus
Author: oxygen
Email: 304914289@qq.com
"""


def script_declare_type(shm_path: str, decls: list) -> str:
    """
    Generate IDA script to declare types in local types.
    
    Args:
        shm_path: Path to shared memory file for results
        decls: List of C type declarations
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    decls_json = json_module.dumps(decls)
    
    return f"""
import idaapi
import ida_typeinf
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
DECLS = {decls_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

try:
    til = ida_typeinf.get_idati()
    
    for decl in DECLS:
        decl_result = {{"decl": decl, "ok": False, "error": None}}
        
        try:
            # Parse declaration
            tif = ida_typeinf.tinfo_t()
            til_result = ida_typeinf.parse_decl(tif, til, decl + ";", ida_typeinf.PT_SIL)
            
            if til_result is None:
                decl_result["error"] = "Failed to parse declaration"
            else:
                # Import into local types
                if tif.is_well_defined():
                    decl_result["ok"] = True
                    decl_result["type_name"] = str(tif)
                else:
                    decl_result["error"] = "Type is not well-defined"
        except Exception as e:
            decl_result["error"] = str(e)
        
        result["results"].append(decl_result)
        
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_read_struct(shm_path: str, queries: list) -> str:
    """
    Generate IDA script to read struct instances from memory.
    
    Args:
        shm_path: Path to shared memory file for results
        queries: List with 'addr' and 'type' fields
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    queries_json = json_module.dumps(queries)
    
    return f"""
import idaapi
import idc
import ida_bytes
import ida_typeinf
import ida_struct
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
QUERIES = {queries_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

try:
    for query in QUERIES:
        query_result = {{"addr": query.get("addr", ""), "type": query.get("type", ""), "fields": {{}}, "error": None}}
        
        try:
            addr_str = query.get("addr", "")
            if addr_str.startswith("0x"):
                ea = int(addr_str, 16)
            else:
                ea = int(addr_str, 0)
            
            type_name = query.get("type", "")
            
            # Get type info
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, f"{{type_name}} x;", ida_typeinf.PT_SIL):
                # Try to get from local types
                if not tif.get_named_type(ida_typeinf.get_idati(), type_name):
                    query_result["error"] = f"Type '{{type_name}}' not found"
                    result["results"].append(query_result)
                    continue
            
            # Read struct data
            if tif.is_struct():
                struct_size = tif.get_size()
                data = ida_bytes.get_bytes(ea, struct_size)
                
                if data:
                    query_result["size"] = struct_size
                    query_result["raw_bytes"] = data.hex()
                    
                    # Try to parse fields (simplified - just show raw data)
                    query_result["ok"] = True
                else:
                    query_result["error"] = "Failed to read memory"
            else:
                query_result["error"] = "Type is not a struct"
                
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


def script_search_structs(shm_path: str, pattern: str) -> str:
    """
    Generate IDA script to search struct types.
    
    Args:
        shm_path: Path to shared memory file for results
        pattern: Regex pattern to match struct names
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import ida_typeinf
import ida_struct
import re
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
PATTERN = r"{pattern}"

idaapi.auto_wait()

result = {{"success": True, "structs": [], "pattern": PATTERN}}

try:
    pattern_re = re.compile(PATTERN, re.IGNORECASE)
    
    # Search in local types
    til = ida_typeinf.get_idati()
    
    # Enumerate all structs
    for idx in range(ida_struct.get_struc_qty()):
        struc_id = ida_struct.get_struc_by_idx(idx)
        if struc_id != idaapi.BADADDR:
            struc = ida_struct.get_struc(struc_id)
            if struc:
                name = ida_struct.get_struc_name(struc_id)
                if pattern_re.search(name):
                    struct_info = {{
                        "name": name,
                        "size": ida_struct.get_struc_size(struc_id),
                        "member_count": struc.memqty
                    }}
                    result["structs"].append(struct_info)
        
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_set_type(shm_path: str, items: list) -> str:
    """
    Generate IDA script to set types at addresses.
    
    Args:
        shm_path: Path to shared memory file for results
        items: List with 'addr' and 'type' fields
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    items_json = json_module.dumps(items)
    
    return f"""
import idaapi
import idc
import ida_typeinf
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
ITEMS = {items_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

try:
    for item in ITEMS:
        item_result = {{"addr": item.get("addr", ""), "type": item.get("type", ""), "ok": False, "error": None}}
        
        try:
            addr_str = item.get("addr", "")
            if addr_str.startswith("0x"):
                ea = int(addr_str, 16)
            else:
                ea = int(addr_str, 0)
            
            type_str = item.get("type", "")
            
            # Try multiple parsing methods
            tif = ida_typeinf.tinfo_t()
            parsed = False
            
            # Method 1: Direct parse with semicolon
            if ida_typeinf.parse_decl(tif, None, type_str + ";", ida_typeinf.PT_SIL):
                parsed = True
            # Method 2: Try without modifying
            elif ida_typeinf.parse_decl(tif, None, type_str, ida_typeinf.PT_SIL):
                parsed = True
            # Method 3: Use idc.parse_decl (simpler parser)
            else:
                try:
                    decl_result = idc.parse_decl(type_str, 0)
                    if decl_result:
                        parsed = True
                        # Recreate tif from parsed declaration
                        ida_typeinf.parse_decl(tif, None, decl_result, ida_typeinf.PT_SIL)
                except:
                    pass
            
            if not parsed:
                item_result["error"] = f"Failed to parse type: {{type_str}}"
            else:
                # Apply type - try multiple methods
                applied = False
                
                # Method 1: Use idc.apply_type
                try:
                    if idc.apply_type(ea, idc.parse_decl(type_str, 0)):
                        applied = True
                        item_result["ok"] = True
                except:
                    pass
                
                # Method 2: Use SetType
                if not applied:
                    try:
                        if idc.SetType(ea, type_str):
                            applied = True
                            item_result["ok"] = True
                    except:
                        pass
                
                # Method 3: Use apply_tinfo
                if not applied:
                    try:
                        if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                            applied = True
                            item_result["ok"] = True
                    except:
                        pass
                
                if not applied:
                    item_result["error"] = "Failed to apply type (all methods failed)"
                        
        except Exception as e:
            item_result["error"] = str(e)
        
        result["results"].append(item_result)
        
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_infer_types(shm_path: str, address: int) -> str:
    """
    Generate IDA script to run type inference.
    
    Note: This is optional and complex - placeholder implementation
    """
    return f"""
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"

result = {{"success": False, "error": "infer_types not yet implemented (optional feature)"}}

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))
"""
