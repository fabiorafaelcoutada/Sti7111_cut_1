# MCP Servers for Binary Analysis

This directory contains Model Context Protocol (MCP) servers for integrating Binary Ninja and IDA Pro with AI assistants.

## Prerequisites

1.  **Python 3.10+**: Ensure you have a compatible Python version.
2.  **MCP Python SDK**: Install the `mcp` library.
3.  **Tool APIs**:
    *   For Binary Ninja: `binaryninja` python module (usually installed with Binary Ninja).
    *   For IDA Pro: IDA Pro installed with Python support.

## Installation

Install the required Python packages:

```bash
pip install -r requirements.txt
```

If you are using IDA Pro, you need to install these packages in the Python environment used by IDA.

## Binary Ninja Server

This server uses the `binaryninja` API to analyze files. It supports loading binary files (including raw binaries with specified architecture) and querying functions, disassembly, and pseudo-code.

### Usage

Run the server directly:

```bash
python mcp_servers/binary_ninja/server.py
```

This will start the server using standard input/output (stdio) transport, which is suitable for connecting to local MCP clients like Claude Desktop.

### Features

*   `load_file(filepath, address, arch)`: Load a binary. `arch` is optional (e.g., 'x86', 'armv7').
*   `get_functions()`: List all functions.
*   `disassemble(address, count)`: Get assembly instructions.
*   `read_bytes(address, length)`: Read raw memory.
*   `get_strings()`: List strings in the binary.
*   `get_pseudo_code(address)`: Get HLIL pseudo-code.

## IDA Pro Server

This server runs inside IDA Pro to expose the current database for analysis. It uses the Server-Sent Events (SSE) transport over HTTP to avoid conflicts with IDA's console output.

### Usage

1.  Open your target file in IDA Pro.
2.  Run the server script within IDA. You can do this via:
    *   **GUI**: File -> Script File... -> select `mcp_servers/ida_pro/server.py`.
        *   **Warning**: Running the server in the GUI thread will freeze the IDA interface while the server is active.
    *   **Command Line (Headless)**:
        ```bash
        ida64 -A -S"path/to/mcp_servers/ida_pro/server.py" target_file.idb
        ```

    **Note**: The server uses `transport='sse'`, which starts an HTTP server (typically on http://localhost:8000/sse).

3.  Connect your MCP client to the SSE endpoint.

### Features

*   `get_functions()`: List all functions.
*   `disassemble(address)`: Get assembly instruction.
*   `decompile(address)`: Get Hex-Rays pseudo-code (if available).
*   `read_bytes(address, length)`: Read raw memory.
*   `get_segments()`: List memory segments.

## Notes

*   **Raw Binaries**: When analyzing raw NAND/NOR dumps, ensure you specify the correct loading address and architecture in Binary Ninja, or set up the memory map correctly in IDA before starting the server.
*   **Performance**: Large binaries may take time to analyze. The servers are designed to be responsive but initial analysis might block.
