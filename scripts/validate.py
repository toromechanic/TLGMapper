#!/usr/bin/env python3
"""Repository validation helper for TLGMapper."""

import os
import py_compile
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

PYTHON_SOURCES = [
    os.path.join(REPO_ROOT, "TLGMapper.py"),
    os.path.join(REPO_ROOT, "scripts", "validate.py"),
]


def compile_file(path):
    try:
        py_compile.compile(path, doraise=True)
        print(f"[+] Python syntax valid: {path}")
        return True
    except py_compile.PyCompileError as exc:
        print(f"[!] Syntax error in {path}: {exc.msg}")
        return False
    except Exception as exc:
        print(f"[!] Failed to compile {path}: {exc}")
        return False


def main():
    all_good = True
    for source in PYTHON_SOURCES:
        if not compile_file(source):
            all_good = False
    return 0 if all_good else 1


if __name__ == "__main__":
    sys.exit(main())
