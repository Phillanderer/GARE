"""
PyGhidra wrapper for running Ghidra scripts
This initializes PyGhidra and uses its run_script function for proper Python support
"""

import sys
import os
import pyghidra

if __name__ == "__main__":
    # Initialize PyGhidra
    ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")

    # Start PyGhidra with the Ghidra installation
    # This initializes the JVM and enables Python scripting
    pyghidra.start(install_dir=ghidra_install, verbose=True)

    # Import and run the Ghidra analyzer
    from ghidra.app.util.headless import AnalyzeHeadless

    # Run analyzeHeadless with all arguments
    try:
        AnalyzeHeadless.main(sys.argv[1:])
    except SystemExit as e:
        sys.exit(e.code if hasattr(e, 'code') else 0)
