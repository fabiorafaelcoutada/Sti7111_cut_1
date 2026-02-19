from fastmcp import FastMCP
import os
import sys

# Ensure src is in path if running directly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from extractor import extract_nagra3_data
from serial_exploit import send_exploit

mcp = FastMCP("Nagra3 Tools")

@mcp.tool()
def extract_nagra3_keys(file_path: str) -> dict:
    """
    Extracts Nagra 3 keys and data from a binary file.

    Args:
        file_path: Path to the binary file to analyze.

    Returns:
        A dictionary containing the extracted keys and blocks.
    """
    return extract_nagra3_data(file_path)

@mcp.tool()
def send_serial_exploit(port: str, baudrate: int = 115200, exploit_file: str = None) -> dict:
    """
    Sends a serial exploit payload to a device.

    Args:
        port: The serial port to use (e.g., /dev/ttyUSB0). Use 'mock' for testing.
        baudrate: The baud rate for the serial connection (default: 115200).
        exploit_file: Optional path to a custom exploit file. If not provided, the default payload is used.

    Returns:
        A dictionary with status and message.
    """
    return send_exploit(port, baudrate, exploit_file)

if __name__ == "__main__":
    mcp.run()
