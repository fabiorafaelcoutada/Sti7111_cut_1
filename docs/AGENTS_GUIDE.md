# Developer Guide: Nagra 3 Exploit & Key Extraction

This guide is intended for AI coding agents and developers working on the `Nagra 3 Extrator` project. It synthesizes the information available in the repository, including inferred details about the hardware and the exploit methodology.

## Project Overview

The goal of this project is to extract cryptographic keys (specifically CWPK - Control Word Protection Key) from a specific set-top box or development board. The device uses the Nagra 3 conditional access system. The exploit relies on a vulnerability accessible via the UART serial console.

## Hardware & Environment

### Target Device
- **Type**: Set-Top Box / Development Board (referenced as "Pace maxtv" in README).
- **Processor**: MIPS-based or similar embedded architecture (inferred from `peek`/`poke` commands and memory addresses).
- **Memory Map**:
  - `0xFE......`: Likely Memory Mapped I/O or a specific memory region used by the bootloader/kernel.
  - `0xFE00D05C`: A specific register or memory location checked to determine vulnerability.
  - `0xFE24C150`: Location of the "final key" after payload execution.
  - `0xFE24xxxx`: Address range used for payload injection.

### Interface
- **Connection**: UART Serial.
- **Port**: `/dev/ttyUSB1` (default in scripts).
- **Baud Rate**: 115200.
- **Protocol**: Raw serial commands (`peek`, `poke`, `display`).

## Exploit Methodology

The exploit involves the following steps:

1.  **Vulnerability Check**:
    - Connect to the device via UART.
    - Send command: `peek fe00d05c`
    - Check response:
        - `0x01100110`: Vulnerable. Proceed.
        - `0x00000000`: Not vulnerable. Stop.

2.  **Payload Injection**:
    - Use `poke` commands to write a sequence of values (instructions/data) into memory starting at `0xFE24xxxx`.
    - This is automated in `Ferro_fixo.py`.

3.  **Execution & Extraction**:
    - The payload presumably executes or modifies system state to expose the keys.
    - The final step in `Ferro_fixo.py` displays the key at `FE24C130`.
    - The keys are then extracted and processed.

## Codebase Analysis

### `Extrator_00886_BXXXXXXX.py`
- **Purpose**: Parses a binary dump (likely a memory dump or firmware image) to extract keys.
- **Key Logic**:
    - Reads a binary file.
    - Extracts specific blocks (eCK, subkeys) based on offsets.
    - Prints the keys in a readable format.
- **Usage**: `python Extrator_00886_BXXXXXXX.py` (prompts for directory and filename).

### `Ferro_fixo.py`
- **Purpose**: Automates the exploit process over serial.
- **Key Logic**:
    - Opens serial port `/dev/ttyUSB1`.
    - Sends a long sequence of `poke` commands to inject data/code.
    - Validates the process by checking specific memory locations (implied).
    - Displays the final key.
- **Payload**: The script contains hardcoded values written to `0xFE24xxxx`. These values likely correspond to MIPS instructions or configuration data for the SoC.

### `Crypto Calculator` (C# Project)
- **Status**: Incomplete in this repo (missing `.cs` source files).
- **Purpose**: Likely a GUI tool to perform cryptographic operations on the extracted keys.
- **Artifacts**: `.csproj` file present, but source code is missing.

## Next Steps for Development

1.  **Analyze the Payload**: Disassemble the values in `Ferro_fixo.py` to understand exactly what code is being injected.
2.  **Port Tools**:
    - Convert `Extrator_00886_BXXXXXXX.py` to a more robust CLI tool or integrate it into a larger framework.
    - Re-implement the missing C# `Crypto Calculator` logic if the algorithm can be reverse-engineered from the Python script.
3.  **Automate Exploit**:
    - Enhance `Ferro_fixo.py` to automatically detect the serial port and handle errors.
    - Implement the "Vulnerability Check" (`peek fe00d05c`) programmatically before attempting injection.
4.  **Documentation**:
    - Locate the missing datasheets (PDFs) referenced in the initial request.
    - Document the specific SoC model once identified.

## Missing Information
- **Datasheets**: The datasheets and reference manuals for the microprocessor were expected but not found in the repository.
- **C# Source**: The source code for the Crypto Calculator is missing.
