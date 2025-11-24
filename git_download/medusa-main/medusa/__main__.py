#!/usr/bin/env python3
"""
MEDUSA module entry point
Allows running: python3 -m medusa
"""

import sys

if __name__ == '__main__':
    # Check if setup_path submodule is being called
    if len(sys.argv) > 1 and sys.argv[1] == 'setup_path':
        from medusa.setup_path import main
        sys.argv.pop(1)  # Remove 'setup_path' from args
        main()
    else:
        # Default: run CLI
        from medusa.cli import main
        main()
