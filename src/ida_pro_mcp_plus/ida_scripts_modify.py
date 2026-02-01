"""
IDA Script Generation Module - Modification Tools

This module contains script generators for code/data modification operations:
- Setting comments
- Patching assembly
- Renaming symbols

TODO: These are placeholder implementations. Full implementations require:
- ida_hexrays for decompiler comments
- idautils.Assemble for assembly patching
- Complex rename logic for functions/globals/locals/stack vars


Project: ida-pro-mcp-plus
Author: oxygen
Email: 304914289@qq.com
"""


def script_set_comments(shm_path: str, items: list) -> str:
    """
    Generate IDA script to set comments.
    
    TODO: Implement with ida_hexrays for decompiler comments
    """
    import json as json_module
    items_json = json_module.dumps(items)
    
    return f"""
import idaapi
import idc
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
ITEMS = {items_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

try:
    for item in ITEMS:
        addr_str = item.get('addr', '')
        comment = item.get('comment', '')
        
        try:
            ea = int(addr_str, 0)
            # Set regular comment
            idc.set_cmt(ea, comment, 0)
            
            result["results"].append({{"addr": addr_str, "ok": True}})
        except Exception as e:
            result["results"].append({{"addr": addr_str, "error": str(e)}})
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_patch_asm(shm_path: str, items: list) -> str:
    """
    Generate IDA script to patch assembly.
    
    Implemented with idautils.Assemble
    """
    import json as json_module
    items_json = json_module.dumps(items)
    
    return f"""
import idaapi
import idautils
import idc
import ida_bytes
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
ITEMS = {items_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

try:
    for item in ITEMS:
        patch_result = {{"addr": item.get("addr", ""), "ok": False, "error": None}}
        
        try:
            addr_str = item.get("addr", "")
            if isinstance(addr_str, str):
                if addr_str.startswith("0x") or addr_str.startswith("0X"):
                    ea = int(addr_str, 16)
                else:
                    ea = int(addr_str, 0)
            else:
                ea = addr_str
            
            asm_code = item.get("asm", "")
            
            # Assemble the instruction
            asm_bytes = idautils.Assemble(ea, asm_code)
            
            if asm_bytes is None:
                patch_result["error"] = f"Failed to assemble: {{asm_code}}"
            else:
                # Patch the bytes
                for i, byte in enumerate(asm_bytes):
                    ida_bytes.patch_byte(ea + i, byte)
                
                patch_result["ok"] = True
                patch_result["bytes_written"] = len(asm_bytes)
                patch_result["asm"] = asm_code
        except Exception as e:
            patch_result["error"] = str(e)
        
        result["results"].append(patch_result)
        
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_rename(shm_path: str, batch: dict) -> str:
    """
    Generate IDA script for unified renaming.
    
    Implemented with idaapi.set_name, ida_hexrays.rename_lvar
    """
    import json as json_module
    batch_json = json_module.dumps(batch)
    
    return f"""
import idaapi
import idc
import ida_name
import ida_hexrays
import ida_frame
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
BATCH = {batch_json}

idaapi.auto_wait()

result = {{"success": True, "functions": [], "globals": [], "locals": [], "stack_vars": []}}

try:
    # Rename functions
    for item in BATCH.get("funcs", []):
        func_result = {{"old": item.get("old", ""), "new": item.get("new", ""), "ok": False, "error": None}}
        
        try:
            old_name = item.get("old", "")
            new_name = item.get("new", "")
            
            # Find function by name or address
            if old_name.startswith("0x"):
                ea = int(old_name, 16)
            else:
                ea = idc.get_name_ea_simple(old_name)
            
            if ea == idaapi.BADADDR:
                func_result["error"] = "Function not found"
            else:
                if idaapi.set_name(ea, new_name, ida_name.SN_CHECK):
                    func_result["ok"] = True
                    func_result["address"] = hex(ea)
                else:
                    func_result["error"] = "Failed to set name (may already exist)"
        except Exception as e:
            func_result["error"] = str(e)
        
        result["functions"].append(func_result)
    
    # Rename globals
    for item in BATCH.get("globals", []):
        global_result = {{"old": item.get("old", ""), "new": item.get("new", ""), "ok": False, "error": None}}
        
        try:
            old_name = item.get("old", "")
            new_name = item.get("new", "")
            
            # Find global by name or address
            if old_name.startswith("0x"):
                ea = int(old_name, 16)
            else:
                ea = idc.get_name_ea_simple(old_name)
            
            if ea == idaapi.BADADDR:
                global_result["error"] = "Global not found"
            else:
                if idaapi.set_name(ea, new_name, ida_name.SN_CHECK):
                    global_result["ok"] = True
                    global_result["address"] = hex(ea)
                else:
                    global_result["error"] = "Failed to set name"
        except Exception as e:
            global_result["error"] = str(e)
        
        result["globals"].append(global_result)
    
    # Rename local variables (requires decompiler)
    for item in BATCH.get("locals", []):
        local_result = {{"func": item.get("func", ""), "old": item.get("old", ""), "new": item.get("new", ""), "ok": False, "error": None}}
        
        try:
            func_addr_str = item.get("func", "")
            old_name = item.get("old", "")
            new_name = item.get("new", "")
            
            if func_addr_str.startswith("0x"):
                func_ea = int(func_addr_str, 16)
            else:
                func_ea = idc.get_name_ea_simple(func_addr_str)
            
            if func_ea == idaapi.BADADDR:
                local_result["error"] = "Function not found"
            else:
                # Decompile function
                cfunc = idaapi.decompile(func_ea)
                if not cfunc:
                    local_result["error"] = "Decompilation failed"
                else:
                    # Find and rename local variable
                    renamed = False
                    for lvar in cfunc.lvars:
                        if lvar.name == old_name:
                            if ida_hexrays.rename_lvar(func_ea, old_name, new_name):
                                local_result["ok"] = True
                                renamed = True
                                break
                    
                    if not renamed and not local_result["ok"]:
                        local_result["error"] = f"Local variable '{{old_name}}' not found"
        except Exception as e:
            local_result["error"] = str(e)
        
        result["locals"].append(local_result)
    
    # Rename stack variables
    for item in BATCH.get("stack_vars", []):
        stack_result = {{"func": item.get("func", ""), "old": item.get("old", ""), "new": item.get("new", ""), "ok": False, "error": None}}
        
        try:
            func_addr_str = item.get("func", "")
            old_name = item.get("old", "")
            new_name = item.get("new", "")
            
            if func_addr_str.startswith("0x"):
                func_ea = int(func_addr_str, 16)
            else:
                func_ea = idc.get_name_ea_simple(func_addr_str)
            
            if func_ea == idaapi.BADADDR:
                stack_result["error"] = "Function not found"
            else:
                func = idaapi.get_func(func_ea)
                if not func:
                    stack_result["error"] = "Not a function"
                else:
                    frame = ida_frame.get_frame(func)
                    if not frame:
                        stack_result["error"] = "No stack frame"
                    else:
                        # Find stack member by name
                        member = ida_frame.get_member_by_name(frame, old_name)
                        if not member:
                            stack_result["error"] = f"Stack variable '{{old_name}}' not found"
                        else:
                            if ida_frame.set_member_name(frame, member.soff, new_name):
                                stack_result["ok"] = True
                            else:
                                stack_result["error"] = "Failed to rename"
        except Exception as e:
            stack_result["error"] = str(e)
        
        result["stack_vars"].append(stack_result)
        
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
