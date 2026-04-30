"""Pytest config — adds project root to sys.path so `engine.*`, `api.*`, etc.
import without needing an editable install."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
