#!/usr/bin/env python3
# Compatibility wrapper for legacy Python 2 script
from Extrator_Py3 import main
from nagra_parser import extract_header, extract_nagra3_data # Keep for test compatibility

if __name__ == "__main__":
    main()
