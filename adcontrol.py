#!/usr/bin/env python3
"""Convenience launcher so the tool runs straight from a clone without install:

    python3 adcontrol.py --dc dc01.corp.local -u user -p pass -d corp.local

Equivalent to `python3 -m adcontrol` / the installed `adcontrol` console script.
All logic lives in the adcontrol package (adcontrol/cli.py).
"""
import os
import sys

# Ensure the package next to this file is importable when run as a script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from adcontrol.cli import main

if __name__ == "__main__":
    main()
