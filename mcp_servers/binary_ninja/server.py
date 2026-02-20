import sys
import binaryninja
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP
mcp = FastMCP("Binary Ninja")

# Global state
current_bv = None

@mcp.tool()
def load_file(filepath: str, address: int = 0, arch: str = None) -> str:
    """Loads a binary file for analysis.

    Args:
        filepath: Path to the binary file.
        address: Base address for loading the binary (default: 0).
        arch: Architecture string (e.g., 'x86', 'armv7', 'mipsel32'). If None, auto-detect.
    """
    global current_bv

    if arch:
        try:
            # Check if architecture is valid
            if arch not in binaryninja.Architecture:
                return f"Architecture {arch} not found. Available architectures: {list(binaryninja.Architecture.keys())}"

            # Load as Raw binary with specific architecture
            current_bv = binaryninja.BinaryViewType['Raw'].open(filepath)
            if not current_bv:
                 return f"Failed to open {filepath} as Raw binary"

            current_bv.platform = binaryninja.Architecture[arch].standalone_platform

            # Map the file content to the specified address
            current_bv.add_auto_segment(address, len(current_bv), 0, len(current_bv),
                                      binaryninja.SegmentFlag.SegmentReadable |
                                      binaryninja.SegmentFlag.SegmentExecutable)

            current_bv.update_analysis_and_wait()
            return f"Loaded {filepath} as {arch} at 0x{address:x}"

        except KeyError:
            return f"Architecture {arch} not found"
        except Exception as e:
            return f"Error loading file: {e}"
    else:
        # Auto-detect format (ELF, PE, etc.)
        current_bv = binaryninja.BinaryViewType.get_view_of_file(filepath)
        if current_bv:
            current_bv.update_analysis_and_wait()
            return f"Loaded {filepath} (auto-detected)"

    return "Failed to load file"

@mcp.tool()
def get_functions() -> list[dict]:
    """Returns a list of functions in the current binary."""
    if not current_bv:
        return []
    # Return basic info to keep payload small
    return [{"name": f.name, "start": f.start, "len": f.total_bytes} for f in current_bv.functions]

@mcp.tool()
def disassemble(address: int, count: int = 10) -> list[str]:
    """Disassembles instructions at the given address."""
    if not current_bv:
        return ["No file loaded"]

    instructions = []
    curr_addr = address
    for _ in range(count):
        length = current_bv.get_instruction_length(curr_addr)
        if length == 0:
            break
        text = current_bv.get_disassembly(curr_addr)
        instructions.append(f"0x{curr_addr:x}: {text}")
        curr_addr += length
    return instructions

@mcp.tool()
def read_bytes(address: int, length: int) -> str:
    """Reads raw bytes from memory."""
    if not current_bv:
        return "No file loaded"
    data = current_bv.read(address, length)
    return data.hex()

@mcp.tool()
def get_strings() -> list[dict]:
    """Returns a list of strings found in the binary."""
    if not current_bv:
        return []
    # Filter for reasonable length strings (> 4 chars)
    return [{"value": s.value, "start": s.start, "length": s.length} for s in current_bv.strings if s.length > 4]

@mcp.tool()
def get_pseudo_code(address: int) -> str:
    """Returns High Level IL (HLIL) pseudo-code for the function at address."""
    if not current_bv:
        return "No file loaded"

    funcs = current_bv.get_functions_containing(address)
    if not funcs:
        return "No function found at address"

    func = funcs[0]
    try:
        # Check if HLIL is available
        if func.hlil:
            # Flatten the HLIL to string lines
            return str(func.hlil)
    except Exception as e:
        return f"Error generating HLIL: {e}"
    return "No HLIL available"

if __name__ == "__main__":
    # Run the server using stdio transport (default)
    mcp.run()
