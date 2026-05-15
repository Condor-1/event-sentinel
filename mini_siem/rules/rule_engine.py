from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from typing import Any, Dict, Iterable, List

from mini_siem.rules.auth_rules import detect_failed_login
from mini_siem.rules.process_creation import detect_suspicious_process_creation
from mini_siem.rules.privilege_rules import detect_privilege_assignment
from mini_siem.rules.shutdown_rules import detect_unexpected_shutdown


def run_rule_engine(events: Iterable[Dict[str, Any]]) -> List[str]:
    """
    Run all enabled detection rules and return alert lines.

    Current detection rules print alert details to stdout. To keep their
    existing behavior untouched while centralizing execution, we capture their
    printed output and pass it back to main for display.
    """

    event_list = list(events)
    if not event_list:
        return []

    alert_buffer = StringIO()
    with redirect_stdout(alert_buffer):
        detect_unexpected_shutdown(event_list)
        detect_failed_login(event_list)
        detect_privilege_assignment(event_list)
        detect_suspicious_process_creation(event_list)

    return [line for line in alert_buffer.getvalue().splitlines() if line.strip()]
