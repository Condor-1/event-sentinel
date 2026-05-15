from __future__ import annotations

import sys
from typing import Any, Dict, List
from pathlib import Path

import pywintypes
import win32evtlog

# Allow importing `config.py` from the project root when running this file directly.
PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import MAX_EVENTS
from state_tracker import load_last_processed_record_number, save_last_processed_record_number


def fetch_events(channel: str, event_ids: List[int]) -> List[Dict[str, Any]]:
    """
    Fetch Windows Event Log entries from the given `channel` and filter by `event_ids`.

    Args:
        channel: Event log channel name, like "Security" or "System".
        event_ids: List of numeric Windows Event IDs to include (e.g., [4624, 4625]).

    Returns:
        A list of dictionaries. Each dictionary has:
          - event_id: int
          - record_number: int
          - timestamp: datetime (from the log entry)
          - message: str (basic message built from StringInserts when available)
          - string_inserts: list | None (raw StringInserts when available)

    Notes:
        - Uses `MAX_EVENTS` from `config.py` to limit the number of results returned.
        - Uses `win32evtlog` (pywin32) to access the Windows Event Log.
    """

    if not event_ids:
        return []

    last_record_number = load_last_processed_record_number()
    max_record_number_seen = last_record_number

    try:
        allowed_ids = {int(eid) for eid in event_ids}
    except (TypeError, ValueError) as exc:
        raise ValueError("event_ids must be a list of integers") from exc

    if not isinstance(channel, str) or not channel.strip():
        raise ValueError("channel must be a non-empty string (e.g., 'Security')")

    handle = None
    results: List[Dict[str, Any]] = []

    try:
        
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
        except pywintypes.error as exc:
            
            raise RuntimeError(
                f"Unable to open event log '{channel}'. "
                f"Check the channel name and your permissions."
            ) from exc

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        record_offset = 0

        while len(results) < MAX_EVENTS:
            events = win32evtlog.ReadEventLog(handle, flags, record_offset)
            if not events:
                break

            stop_reading = False
            for ev in events:
                if len(results) >= MAX_EVENTS:
                    break

        
                record_no = getattr(ev, "RecordNumber", None)
                if record_no is None:
                    # If we can't determine the record number, skip this event.
                    continue
                try:
                    record_no_int = int(record_no)
                except (TypeError, ValueError):
                    continue

                if record_no_int > max_record_number_seen:
                    max_record_number_seen = record_no_int

                if record_no_int <= last_record_number:
                    stop_reading = True
                    break

                # Filter by EventID.
                try:
                    this_event_id = int(ev.EventID)
                except (TypeError, ValueError):
                    continue

                if this_event_id not in allowed_ids:
                    continue

                timestamp = getattr(ev, "TimeGenerated", None)

                message = ""
                inserts = getattr(ev, "StringInserts", None)
                if inserts:
                    message = " ".join(str(x) for x in inserts if x is not None)

                results.append(
                    {
                        "event_id": this_event_id,
                        "record_number": record_no_int,
                        "timestamp": timestamp,
                        "message": message,
                        "string_inserts": list(inserts) if inserts else None,
                    }
                )

            if stop_reading:
                break

            record_offset += len(events)

    except pywintypes.error as exc:
        # Permission issues and other Win32 errors often show up as pywintypes.error.
        raise RuntimeError(
            "Failed to fetch Windows Event Logs. "
            "Make sure you have the required permissions."
        ) from exc
    finally:
        if handle is not None:
            win32evtlog.CloseEventLog(handle)

    if max_record_number_seen > last_record_number:
        save_last_processed_record_number(max_record_number_seen)

    return results


# Simple manual test (runs only when this file is executed directly).
# TODO: remove this manual test block later.
if __name__ == "__main__":
    events = fetch_events("System", [6005, 6006, 41])
    print(f"Fetched {len(events)} events")

    print("First 5 events:")
    for ev in events[:5]:
        print(
            f"- event_id={ev.get('event_id')}, "
            f"timestamp={ev.get('timestamp')}, "
            f"message={ev.get('message')}"
        )

