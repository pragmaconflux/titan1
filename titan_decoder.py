#!/usr/bin/env python3
"""
Legacy entry point for backward compatibility.
Use 'titan-decoder' command after installation.
"""

import sys
from pathlib import Path

# Add the package to path
sys.path.insert(0, str(Path(__file__).parent))

from titan_decoder.cli import main

if __name__ == "__main__":
    main()
