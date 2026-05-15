from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
STATE_FILE_PATH = DATA_DIR / "event_state.json"


def save_last_processed_record_number(last_record_number: int) -> None:
    """
    Save the last processed Windows Event Log record number to disk.

    Args:
        last_record_number: The event log record number to persist.
    """
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Unable to create data directory: {DATA_DIR}") from exc

    payload: Dict[str, Any] = {"last_record_number": int(last_record_number)}

    try:
        STATE_FILE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Unable to write state file: {STATE_FILE_PATH}") from exc


def load_last_processed_record_number() -> int:
    
    if not STATE_FILE_PATH.exists():
        return 0

    try:
        raw = STATE_FILE_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        
        return 0

    
    if not isinstance(data, dict):
        return 0

    value = data.get("last_record_number", 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# Simple manual test (runs only when this file is executed directly).
# TODO: remove this manual test block later.
if __name__ == "__main__":
    print("Testing state_tracker...")
    try:
        before = load_last_processed_record_number()
        print(f"Loaded before save: {before}")

        save_last_processed_record_number(123)
        after = load_last_processed_record_number()
        print(f"Loaded after save: {after}")
    except RuntimeError as exc:
        print(f"State tracker test failed: {exc}")
