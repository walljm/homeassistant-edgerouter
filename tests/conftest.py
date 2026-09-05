"""Pytest configuration — makes edgerouter_api importable without HA installed."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "custom_components" / "edgerouter"))
