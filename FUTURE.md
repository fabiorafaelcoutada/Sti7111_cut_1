# Future Roadmap

## Critical Updates
1. **C# Port**: Re-implement the missing C# `Crypto Calculator` logic based on `Extrator` logic, likely for a Windows GUI.
2. **Flash Analyzer**: Integrate `Flash_Analyzer.py` functionality into the MCP server.
3. **Testing**: Add integration tests with a simulated serial device (e.g., using `socat`).
4. **Hardware Support**: Add support for other STi7111-based devices.
5. **UI**: Create a web or desktop UI for the tools.

## Known Issues
- `Extrator.py` parsing logic relies on fixed offsets which might vary between firmware versions. Need heuristic detection.
