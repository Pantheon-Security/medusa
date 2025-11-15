#!/usr/bin/env python3
"""
MEDUSA Entry Point
Allows running MEDUSA as a module: python -m medusa
"""

import sys
from medusa.cli import main

if __name__ == '__main__':
    sys.exit(main())
