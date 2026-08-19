#!/usr/bin/env python3
"""Repository-root shim: run ``python wallet2hash.py ...`` without installing."""

import sys

from wallet2hash.cli import main

if __name__ == "__main__":
    sys.exit(main())
