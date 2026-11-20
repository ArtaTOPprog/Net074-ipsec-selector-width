#!/usr/bin/env python3
"""Compatibility entry point; the original generator lives in experiment/gen.py."""
from pathlib import Path
import runpy
if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).resolve().parents[1]/'experiment/gen.py'), run_name='__main__')
