#!/usr/bin/env python3
"""Generate strong API keys for PHISHGUARD_SCAN_KEYS / PHISHGUARD_ADMIN_KEYS."""
import secrets
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
for label in ("scan", "admin"):
    keys = [secrets.token_urlsafe(32) for _ in range(n)]
    print(f"PHISHGUARD_{label.upper()}_KEYS={','.join(keys)}")
