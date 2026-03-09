#!/usr/bin/env python3

import yaml
import os

# Resolve path relative to this file so the EDR works regardless of
# what directory it is launched from
_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "config",
    "rules.yaml"
)

def load_config(path: str = _CONFIG_PATH) -> dict:
    """Read and parse rules.yaml, returning the full config dict"""
    with open(os.path.abspath(path), "r") as f:
        return yaml.safe_load(f)
    
CONFIG = load_config()