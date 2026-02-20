import sys
import idc
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_ua
import ida_lines
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP
mcp = FastMCP("IDA Pro")

@mcp.tool()
def get_functions() -> list[dict]:
    """Returns a list of functions in the current database."""
    funcs = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        name = idc.get_func_name(ea)
        funcs.append({
            "name": name,
            "start": ea,
            "end": f.end_ea if f else ea
        })
    return funcs

@mcp.tool()
def disassemble(address: int) -> str:
    """Returns disassembly of the instruction at address."""
    return idc.GetDisasm(address)

@mcp.tool()
def decompile(address: int) -> str:
    """Returns pseudo-code for the function at address (requires Hex-Rays)."""
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return "Hex-Rays decompiler not available or failed to init"

        cfunc = ida_hexrays.decompile(address)
        if cfunc:
            # Extract pseudo-code lines
            sv = cfunc.get_pseudocode()
            lines = []
            for sline in sv:
                # Remove color tags from the line content
                lines.append(ida_lines.tag_remove(sline.line))
            return "\n".join(lines)
    except ImportError:
        return "Hex-Rays decompiler module not found"
    except Exception as e:
        return f"Error decompiling: {e}"
    return "Failed to decompile"

@mcp.tool()
def read_bytes(address: int, length: int) -> str:
    """Reads raw bytes from memory."""
    data = ida_bytes.get_bytes(address, length)
    if data:
        return data.hex()
    return ""

@mcp.tool()
def get_segments() -> list[dict]:
    """Returns a list of segments in the database."""
    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        name = idc.get_segm_name(seg_ea)
        segments.append({
            "name": name,
            "start": seg.start_ea,
            "end": seg.end_ea
        })
    return segments

if __name__ == "__main__":
    # Use SSE transport to avoid stdout issues in IDA
    # This runs a uvicorn server. Ensure uvicorn is installed in IDA's python environment.
    print("Starting IDA Pro MCP Server on SSE transport...")
    try:
        mcp.run(transport="sse")
    except Exception as e:
        print(f"Error running server: {e}")
