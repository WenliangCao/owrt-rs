#!/usr/bin/env python3
"""Compatibility entry point for the R85 HTTPD result analyzer."""
from analyze_candidate import derive, main, parallel, read, serial  # noqa: F401


if __name__ == "__main__":
    main()
