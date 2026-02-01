"""
IDA Script Generation Module - Memory Operations

This module contains script generators for memory read/write operations:
- Typed integer reading/writing
- String reading
- Global variable value reading  
- Memory patching


Project: ida-pro-mcp-plus
Author: oxygen
Email: 304914289@qq.com
"""


def script_get_int(shm_path: str, queries: list) -> str:
    """
    Generate IDA script to read typed integers.
    
    Args:
        shm_path: Path to shared memory file for results
        queries: List of dicts with 'addr' and 'ty' (type like "i32le", "u64be")
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    queries_json = json_module.dumps(queries)
    
    return f"""
import idaapi
import ida_bytes
import struct
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
QUERIES = {queries_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

def parse_type(ty_str):
    import re
    match = re.match(r'([iu])(\\d+)(le|be)?', ty_str.lower())
    if not match:
        raise ValueError(f"Invalid type: {{ty_str}}")
    signed = match.group(1) == 'i'
    bits = int(match.group(2))
    endian = match.group(3) or 'le'
    return signed, bits, endian

try:
    for query in QUERIES:
        addr_str = query.get('addr', '')
        ty_str = query.get('ty', 'u32le')
        
        try:
            ea = int(addr_str, 0)
            signed, bits, endian = parse_type(ty_str)
            byte_count = bits // 8
            
            data = ida_bytes.get_bytes(ea, byte_count)
            if not data:
                raise ValueError(f"Cannot read {{byte_count}} bytes at {{hex(ea)}}")
            
            fmt_map = {{
                (8, True, 'le'): '<b', (8, False, 'le'): '<B',
                (16, True, 'le'): '<h', (16, False, 'le'): '<H',
                (32, True, 'le'): '<i', (32, False, 'le'): '<I',
                (64, True, 'le'): '<q', (64, False, 'le'): '<Q',
                (8, True, 'be'): '>b', (8, False, 'be'): '>B',
                (16, True, 'be'): '>h', (16, False, 'be'): '>H',
                (32, True, 'be'): '>i', (32, False, 'be'): '>I',
                (64, True, 'be'): '>q', (64, False, 'be'): '>Q',
            }}
            
            fmt = fmt_map.get((bits, signed, endian))
            value = struct.unpack(fmt, data)[0]
            
            result["results"].append({{
                "addr": addr_str,
                "value_dec": value,
                "value_hex": hex(value if value >= 0 else (1 << bits) + value)
            }})
        except Exception as e:
            result["results"].append({{"addr": addr_str, "error": str(e)}})
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

import idc
idc.qexit(0)
"""


def script_get_string(shm_path: str, addresses: list) -> str:
    """
    Generate IDA script to read strings.
    
    Args:
        shm_path: Path to shared memory file for results
        addresses: List of addresses (strings)
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    addresses_json = json_module.dumps(addresses)
    
    return f"""
import idaapi
import idc
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
ADDRESSES = {addresses_json}

idaapi.auto_wait()

result = {{"success": True, "strings": []}}

try:
    for addr_str in ADDRESSES:
        try:
            ea = int(addr_str, 0)
            str_val = idc.get_strlit_contents(ea)
            if str_val is None:
                raise ValueError("No string at address")
            
            try:
                decoded = str_val.decode('utf-8')
                encoding = 'utf-8'
            except:
                try:
                    decoded = str_val.decode('ascii')
                    encoding = 'ascii'
                except:
                    decoded = str_val.decode('latin1')
                    encoding = 'latin1'
            
            result["strings"].append({{
                "address": addr_str,
                "value": decoded,
                "length": len(decoded),
                "encoding": encoding
            }})
        except Exception as e:
            result["strings"].append({{"address": addr_str, "error": str(e)}})
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_get_global_value(shm_path: str, names: list) -> str:
    """
    Generate IDA script to read global variable values.
    
    Args:
        shm_path: Path to shared memory file for results
        names: List of global variable names
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    names_json = json_module.dumps(names)
    
    return f"""
import idaapi
import idc
import ida_bytes
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
NAMES = {names_json}

idaapi.auto_wait()

result = {{"success": True, "values": []}}

try:
    for name in NAMES:
        try:
            ea = idc.get_name_ea_simple(name)
            if ea == idaapi.BADADDR:
                raise ValueError(f"Global '{{name}}' not found")
            
            size = idc.get_item_size(ea)
            if size <= 0:
                size = 64
            
            data = ida_bytes.get_bytes(ea, min(size, 64))
            
            result["values"].append({{
                "name": name,
                "address": hex(ea),
                "value": data.hex() if data else None,
                "size": size
            }})
        except Exception as e:
            result["values"].append({{"name": name, "error": str(e)}})
            
except Exception as e:
    result["success"] = False
    result["error"] = str(e)

with open(SHARED_MEM_PATH, "r+b") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
        mm.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

idc.qexit(0)
"""


def script_patch(shm_path: str, patches: list) -> str:
    """
    Generate IDA script to patch memory.
    
    Args:
        shm_path: Path to shared memory file for results
        patches: List of dicts with 'addr' and 'bytes' (hex string)
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    patches_json = json_module.dumps(patches)
    
    return f"""
import idaapi
import ida_bytes
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
PATCHES = {patches_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

try:
    for patch in PATCHES:
        addr_str = patch.get('addr', '')
        bytes_str = patch.get('bytes', '')
        
        try:
            ea = int(addr_str, 0)
            bytes_parts = bytes_str.split()
            byte_data = bytes([int(b, 16) for b in bytes_parts])
            ida_bytes.patch_bytes(ea, byte_data)
            
            result["results"].append({{
                "addr": addr_str,
                "bytes_written": len(byte_data),
                "ok": True
            }})
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


def script_put_int(shm_path: str, writes: list) -> str:
    """
    Generate IDA script to write typed integers.
    
    Args:
        shm_path: Path to shared memory file for results
        writes: List of dicts with 'addr', 'ty', and 'value'
    
    Returns:
        Complete IDA Python script as string
    """
    import json as json_module
    writes_json = json_module.dumps(writes)
    
    return f"""
import idaapi
import ida_bytes
import struct
import json
import mmap

SHARED_MEM_PATH = r"{shm_path}"
WRITES = {writes_json}

idaapi.auto_wait()

result = {{"success": True, "results": []}}

def parse_type(ty_str):
    import re
    match = re.match(r'([iu])(\\d+)(le|be)?', ty_str.lower())
    if not match:
        raise ValueError(f"Invalid type: {{ty_str}}")
    signed = match.group(1) == 'i'
    bits = int(match.group(2))
    endian = match.group(3) or 'le'
    return signed, bits, endian

try:
    for write in WRITES:
        addr_str = write.get('addr', '')
        ty_str = write.get('ty', 'u32le')
        value = write.get('value', 0)
        
        try:
            ea = int(addr_str, 0)
            if isinstance(value, str):
                value = int(value, 0)
            
            signed, bits, endian = parse_type(ty_str)
            
            fmt_map = {{
                (8, True, 'le'): '<b', (8, False, 'le'): '<B',
                (16, True, 'le'): '<h', (16, False, 'le'): '<H',
                (32, True, 'le'): '<i', (32, False, 'le'): '<I',
                (64, True, 'le'): '<q', (64, False, 'le'): '<Q',
                (8, True, 'be'): '>b', (8, False, 'be'): '>B',
                (16, True, 'be'): '>h', (16, False, 'be'): '>H',
                (32, True, 'be'): '>i', (32, False, 'be'): '>I',
                (64, True, 'be'): '>q', (64, False, 'be'): '>Q',
            }}
            
            fmt = fmt_map.get((bits, signed, endian))
            byte_data = struct.pack(fmt, value)
            ida_bytes.patch_bytes(ea, byte_data)
            
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
