from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable


_RECENT_SHUTDOWN_TIMES: deque[datetime] = deque()


def detect_unexpected_shutdown(events: Iterable[Dict[str, Any]]) -> None:
    """
    Simple detection rule for testing.

    Detects Windows System Event ID 41: unexpected shutdown/restart.
    """

    window = timedelta(seconds=60)
    threshold = 3

    for ev in events:
        try:
            event_id = int(ev.get("event_id"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue

        if event_id != 41:
            continue

        timestamp = ev.get("timestamp")
        record_number = ev.get("record_number")

        print("[ALERT] Unexpected shutdown detected")
        print(f"EventID: {event_id}")
        print(f"Timestamp: {timestamp}")
        print(f"Record: {record_number}")

        # Burst detection: if we see >3 EventID 41 within a short time window,
        # emit an additional alert.
        ts_dt: datetime | None = timestamp if isinstance(timestamp, datetime) else None
        if ts_dt is None:
            continue

        _RECENT_SHUTDOWN_TIMES.append(ts_dt)
        cutoff = ts_dt - window
        while _RECENT_SHUTDOWN_TIMES and _RECENT_SHUTDOWN_TIMES[0] < cutoff:
            _RECENT_SHUTDOWN_TIMES.popleft()

        if len(_RECENT_SHUTDOWN_TIMES) > threshold:
            print("[ALERT] Multiple unexpected shutdowns detected in a short period")
            print(f"Count: {len(_RECENT_SHUTDOWN_TIMES)}")
            print(f"WindowSeconds: {int(window.total_seconds())}")
