"""
IDA Script Generation Module - Stack Frame Operations

This module contains script generators for stack frame manipulation:
- Retrieving stack frame variables
- Declaring typed stack variables
- Deleting stack variables


Project: ida-pro-mcp-plus
Author: oxygen
Email: 304914289@qq.com
"""


def script_stack_frame(shm_path: str, address: int) -> str:
    """
    Generate IDA script to get stack frame variables.
    
    Args:
        shm_path: Path to shared memory file for results
        address: Function address
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idc
import ida_frame
import ida_struct
import ida_typeinf
import ida_bytes
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
FUNC_ADDR = {address}

idaapi.auto_wait()

result = {{"success": True, "variables": [], "function": hex(FUNC_ADDR)}}

try:
    func = idaapi.get_func(FUNC_ADDR)
    if not func:
        result["success"] = False
        result["error"] = "Not a function"
    else:
        frame = ida_frame.get_frame(func)
        if not frame:
            result["success"] = False
            result["error"] = "No stack frame"
        else:
            result["frame_size"] = ida_struct.get_struc_size(frame)
            
            # Iterate through stack members
            idx = 0
            while idx < ida_struct.get_struc_size(frame):
                member = ida_struct.get_member(frame, idx)
                if member:
                    var_info = {{
                        "name": ida_struct.get_member_name(member.id),
                        "offset": member.soff,
                        "size": ida_struct.get_member_size(member),
                        "type": idc.get_type(member.id) or "unknown"
                    }}
                    result["variables"].append(var_info)
                    idx += ida_struct.get_member_size(member)
                else:
                    idx += 1
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_declare_stack(shm_path: str, func_addr: int, name: str, offset: int, type_str: str) -> str:
    """
    Generate IDA script to declare typed stack variable.
    
    Args:
        shm_path: Path to shared memory file for results
        func_addr: Function address
        name: Variable name
        offset: Stack offset
        type_str: Type string (e.g., "int", "char*")
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idc
import ida_frame
import ida_struct
import ida_typeinf
import ida_bytes
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
FUNC_ADDR = {func_addr}
VAR_NAME = "{name}"
OFFSET = {offset}
TYPE_STR = r"{type_str}"

idaapi.auto_wait()

result = {{"success": True, "name": VAR_NAME, "offset": OFFSET, "type": TYPE_STR}}

try:
    func = idaapi.get_func(FUNC_ADDR)
    if not func:
        result["success"] = False
        result["error"] = "Not a function"
    else:
        frame = ida_frame.get_frame(func)
        if not frame:
            result["success"] = False
            result["error"] = "No stack frame"
        else:
            # Parse type
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, TYPE_STR + ";", ida_typeinf.PT_SIL):
                result["success"] = False
                result["error"] = f"Failed to parse type: {{TYPE_STR}}"
            else:
                type_size = tif.get_size()
                
                # Add stack member
                ret = ida_struct.add_struc_member(frame, VAR_NAME, OFFSET, ida_bytes.FF_DATA, None, type_size)
                if ret == 0:
                    # Set type
                    member = ida_struct.get_member(frame, OFFSET)
                    if member:
                        ida_typeinf.set_member_tinfo(frame, member, 0, tif, 0)
                        result["ok"] = True
                    else:
                        result["success"] = False
                        result["error"] = "Failed to get member after creation"
                else:
                    result["success"] = False
                    result["error"] = f"Failed to add stack member (error code: {{ret}})"
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_delete_stack(shm_path: str, func_addr: int, name: str) -> str:
    """
    Generate IDA script to delete stack variable.
    
    Args:
        shm_path: Path to shared memory file for results
        func_addr: Function address
        name: Variable name to delete
    
    Returns:
        Complete IDA Python script as string
    """
    return f"""
import idaapi
import idc
import ida_frame
import ida_struct
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
FUNC_ADDR = {func_addr}
VAR_NAME = "{name}"

idaapi.auto_wait()

result = {{"success": True, "name": VAR_NAME}}

try:
    func = idaapi.get_func(FUNC_ADDR)
    if not func:
        result["success"] = False
        result["error"] = "Not a function"
    else:
        frame = ida_frame.get_frame(func)
        if not frame:
            result["success"] = False
            result["error"] = "No stack frame"
        else:
            # Find member by name
            member = ida_frame.get_member_by_name(frame, VAR_NAME)
            if not member:
                result["success"] = False
                result["error"] = f"Stack variable '{{VAR_NAME}}' not found"
            else:
                # Delete member
                if ida_struct.del_struc_member(frame, member.soff):
                    result["ok"] = True
                else:
                    result["success"] = False
                    result["error"] = "Failed to delete stack member"
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""
