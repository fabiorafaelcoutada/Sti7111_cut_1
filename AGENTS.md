# Agent Instructions

This repository contains tools for Nagra 3 analysis and exploitation.

## Setup
1. Install dependencies: `pip install -r requirements.txt`.
2. Run the MCP server: `python3 src/mcp_server.py`.

## Usage
- Use `src/extractor.py` for standalone file analysis.
- Use `src/serial_exploit.py` for sending payloads.
- Use the MCP server to integrate with LLM workflows.

## Development
- Add new exploits to `src/exploits/`.
- Run tests with `python3 -m unittest discover tests`.
