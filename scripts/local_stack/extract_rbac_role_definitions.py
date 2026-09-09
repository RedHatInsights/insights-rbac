#!/usr/bin/env python3
"""Extract RBAC role definition JSON files from a Kubernetes configmap YAML."""

from __future__ import annotations

import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <rbac-config.yml> <output-dir>", file=sys.stderr)
        return 1

    try:
        import yaml
    except ImportError:
        print("PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        return 1

    config_path = pathlib.Path(sys.argv[1])
    out_dir = pathlib.Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    for old in out_dir.glob("*.json"):
        old.unlink()

    data = yaml.safe_load(config_path.read_text())
    entries = data["objects"][0]["data"]
    for key, value in entries.items():
        if not isinstance(value, str):
            value = yaml.dump(value)
        (out_dir / key).write_text(value)

    print(f"Extracted {len(entries)} RBAC role definition files to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
