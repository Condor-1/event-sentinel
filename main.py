# CLI entry point for the mini SIEM application.
# Start the event collection, parsing, storage, and rule-processing loop here.

from __future__ import annotations

import sys
import time
from pathlib import Path

from config import POLL_INTERVAL, SECURITY_EVENT_IDS, SYSTEM_EVENT_IDS

# The collector uses `from state_tracker import ...` (non-package import).
# Ensure `mini_siem/collector` is on `sys.path` so that module resolves.
COLLECTOR_DIR = Path(__file__).resolve().parent / "mini_siem" / "collector"
if str(COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(COLLECTOR_DIR))

from mini_siem.collector.event_collector import fetch_events
from mini_siem.rules.rule_engine import run_rule_engine


def main() -> None:
    system_channel = "System"
    security_channel = "Security"

    all_events: list[dict] = []

    try:
        while True:
            system_events = fetch_events(system_channel, SYSTEM_EVENT_IDS)
            security_events: list[dict] = []
            try:
                security_events = fetch_events(security_channel, SECURITY_EVENT_IDS)
            except RuntimeError as exc:
                # Security log often requires elevated permissions; keep the loop running.
                print(f"[{security_channel}] unable to read events: {exc}")

            new_events = system_events + security_events

            if new_events:
                all_events.extend(new_events)

                # Run all detection rules through the central rule engine.
                alerts = run_rule_engine(new_events)
                for alert_line in alerts:
                    print(alert_line)

                # TESTING OUTPUT ONLY — remove this block later.
                print(f"[all] new events: {len(new_events)} (total seen: {len(all_events)})")
                for ev in new_events[:5]:
                    print(
                        f"- record_number={ev.get('record_number')} "
                        f"event_id={ev.get('event_id')} "
                        f"timestamp={ev.get('timestamp')} "
                        f"message={ev.get('message')}"
                    )
            else:
                print(f"[{system_channel}] no new events")
                if not security_events:
                    print(f"[{security_channel}] no new events")

            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
