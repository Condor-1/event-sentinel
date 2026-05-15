from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Tuple


_ALERT_COOLDOWN = timedelta(seconds=45)
last_alert_time_per_user: Dict[str, datetime] = {}
_IGNORED_EXACT_USERS = {
    "SYSTEM",
    "NT AUTHORITY\\SYSTEM",
    "LOCAL SERVICE",
    "NT AUTHORITY\\LOCAL SERVICE",
    "NETWORK SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE",
}


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_user(value: Any) -> str:
    user = _normalize_text(value)
    if not user or user in {"-", "NULL", "null"}:
        return "Unknown"
    return user


def _normalize_logon_id(value: Any) -> str:
    v = _normalize_text(value).lower()
    if not v or v in {"-", "0", "0x0"}:
        return "unknown"
    return v


def _extract_from_string_inserts(inserts: Any) -> Tuple[str, str]:
    if not isinstance(inserts, list):
        return "Unknown", "unknown"

    # Typical 4672 ordering:
    # [0] SubjectUserSid, [1] SubjectUserName, [2] SubjectDomainName, [3] SubjectLogonId
    username = _normalize_user(inserts[1] if len(inserts) > 1 else None)
    logon_id = _normalize_logon_id(inserts[3] if len(inserts) > 3 else None)
    return username, logon_id


def _is_noise_account(username: str) -> bool:
    normalized_upper = _normalize_user(username).upper()
    if normalized_upper in _IGNORED_EXACT_USERS:
        return True
    return normalized_upper.endswith("$")


def _prune_cooldown(reference_time: datetime) -> None:
    cutoff = reference_time - _ALERT_COOLDOWN
    expired_users: List[str] = []
    for user, ts in last_alert_time_per_user.items():
        if ts < cutoff:
            expired_users.append(user)
    for user in expired_users:
        last_alert_time_per_user.pop(user, None)


def detect_privilege_assignment(events: Iterable[Dict[str, Any]]) -> None:
    """
    Detect Windows Security Event ID 4672 and emit a low-medium alert.

    This rule intentionally stays conservative and filters noisy built-in
    service/machine identities to avoid over-alerting.
    """
    for ev in events:
        try:
            event_id = int(ev.get("event_id"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue

        if event_id != 4672:
            continue

        timestamp = ev.get("timestamp")
        if not isinstance(timestamp, datetime):
            continue

        record_number = ev.get("record_number")
        username, logon_id = _extract_from_string_inserts(ev.get("string_inserts"))

        if _is_noise_account(username):
            continue

        _prune_cooldown(timestamp)
        user_key = username.upper()
        last_alert_at = last_alert_time_per_user.get(user_key)
        if isinstance(last_alert_at, datetime) and (timestamp - last_alert_at) < _ALERT_COOLDOWN:
            continue

        severity = "MEDIUM"
        source_ip = _normalize_text(ev.get("source_ip"))
        logon_type = _normalize_text(ev.get("logon_type"))

        is_valid_ip = bool(source_ip) and source_ip not in {"-"}
        is_remote_ip = is_valid_ip and source_ip not in {"127.0.0.1", "::1"}
        if is_remote_ip:
            severity = "HIGH"

        # Keep current severity for interactive logons (no downgrade).
        if logon_type in {"2", "10"}:
            severity = severity

        if severity == "HIGH":
            print("[ALERT][HIGH] Elevated privileges granted from remote source")
        else:
            print("[ALERT][MEDIUM] Elevated privileges granted to user")
        print(f"EventID: {event_id}")
        print(f"User: {username}")
        print(f"Logon ID: {logon_id}")
        print(f"Timestamp: {timestamp}")
        print(f"Record: {record_number}")

        last_alert_time_per_user[user_key] = timestamp
