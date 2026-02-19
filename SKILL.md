# Nagra 3 Tools Skills

This repository provides an MCP server with tools for analyzing Nagra 3 binary dumps and executing serial exploits.

## Tools

### `extract_nagra3_keys`
- **Description**: Extracts Nagra 3 keys and data from a binary file.
- **Parameters**:
  - `file_path` (string): Path to the binary file to analyze.
- **Returns**: A JSON object containing keys (eCKs), block payloads, and metadata.

### `send_serial_exploit`
- **Description**: Sends a serial exploit payload to a device.
- **Parameters**:
  - `port` (string): The serial port (e.g., `/dev/ttyUSB0`) or `mock` for testing.
  - `baudrate` (integer): Baud rate, default 115200.
  - `exploit_file` (string, optional): Path to a custom exploit file.
- **Returns**: A status dictionary (`{"status": "success", "message": "..."}`).
