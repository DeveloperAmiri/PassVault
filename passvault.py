#!/usr/bin/env python3
"""PassVault entry point — run any command through this file.

Examples
--------
    python passvault.py init
    python passvault.py add github -u octocat --generate
    python passvault.py list
    python passvault.py get github
    python passvault.py generate -n 24 --copy
"""

from passvault.cli import main

if __name__ == "__main__":
    main()
