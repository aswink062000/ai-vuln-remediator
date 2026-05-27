import sys
import os
from pathlib import Path

# Mocking the environment to simulate the issue
# We want to see if _find_semgrep_binary prioritizes shutil.which
try:
    from app.scanners.semgrep_scan import _find_semgrep_binary
    print("Successfully imported _find_semgrep_binary")
    
    path = _find_semgrep_binary()
    print(f"Detected semgrep path: {path}")
    
    if path:
        print("SUCCESS: Semgrep binary found.")
    else:
        print("FAILURE: Semgrep binary not found.")
except Exception as e:
    print(f"Error during test: {e}")
