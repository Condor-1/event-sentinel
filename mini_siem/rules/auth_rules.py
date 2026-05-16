from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Tuple

from config import DEBUG


def _normalize_user(value: Any) -> str:
    s = "" if value is None else str(value).strip()
    if not s or s in {"-", "NULL", "null"}:
        return "Unknown"
    return s


def _extract_4625_fields_from_inserts(inserts: Any) -> Tuple[str, str | None, str | None]:
   
    # Extract fields from Security 4625 StringInserts by index.

    if not isinstance(inserts, list):
        return "Unknown", None, None

    def _at(idx: int) -> Any:
        return inserts[idx] if 0 <= idx < len(inserts) else None

    username = "Unknown"
    # Try multiple candidates for TargetUserName / Account Name (0-based indices).
    for idx in (5, 1, 0, 6, 2, 3, 4, 7, 8, 9, 11, 12, 13):
        candidate = _at(idx)
        normalized = _normalize_user(candidate)
        if normalized != "Unknown":
            username = normalized
            break

    logon_type_raw = _at(10)
    source_ip_raw = _at(19)

    logon_type = None if logon_type_raw is None else str(logon_type_raw).strip() or None
    source_ip = None if source_ip_raw is None else str(source_ip_raw).strip() or None

    return username, logon_type, source_ip


def _extract_username_from_inserts(inserts: Any, candidate_indices: Tuple[int, ...]) -> str:
    if not isinstance(inserts, list):
        return "Unknown"

    for idx in candidate_indices:
        if 0 <= idx < len(inserts):
            normalized = _normalize_user(inserts[idx])
            if normalized != "Unknown":
                return normalized
    return "Unknown"


def _extract_4624_username(inserts: Any) -> str:
    # Common 4624 mapping: TargetUserName is often index 5.
    return _extract_username_from_inserts(
        inserts, (5, 1, 0, 6, 2, 3, 4, 7, 8, 9, 11, 12, 13)
    )


def _extract_4672_username(inserts: Any) -> str:
    return _extract_username_from_inserts(inserts, (1, 0, 2, 3, 4, 5))


_FAILED_THRESHOLD = 3
_FAILURE_WINDOW = timedelta(seconds=90)
_SESSION_TIMEOUT = timedelta(minutes=5)
_ALERT_COOLDOWN = timedelta(seconds=30)
_FALLBACK_SESSION_MATCH_WINDOW = timedelta(seconds=5)
_DEBUG = True
_EVENT_PRIORITY = {4625: 0, 4624: 1, 4672: 2}

_recent_failures: List[Dict[str, Any]] = []
_sessions: Dict[str, Dict[str, Any]] = {}
_last_alert_by_logon_id: Dict[str, datetime] = {}
_last_alert_time_per_user: Dict[str, datetime] = {}


def debug(msg: str) -> None:
    if DEBUG:
        print(msg)


def _debug_log(message: str) -> None:
    if _DEBUG:
        debug(f"[DEBUG][AUTH] {message}")


def _extract_indexed(inserts: Any, idx: int) -> str | None:
    if not isinstance(inserts, list) or idx < 0 or idx >= len(inserts):
        return None
    raw = inserts[idx]
    if raw is None:
        return None
    value = str(raw).strip()
    return value or None


def _normalize_logon_id(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().lower()
    if not v or v in {"-", "0x0", "0"}:
        return None
    return v


def _extract_4624_fields(inserts: Any) -> Tuple[str, str | None, str | None]:
    user = _extract_4624_username(inserts)
    # Typical 4624 TargetLogonId and IpAddress positions.
    logon_id = _normalize_logon_id(_extract_indexed(inserts, 7))
    source_ip = _extract_indexed(inserts, 18)
    return user, logon_id, source_ip


def _extract_4672_fields(inserts: Any) -> Tuple[str, str | None]:
    user = _extract_4672_username(inserts)
    # Typical 4672 SubjectLogonId position.
    logon_id = _normalize_logon_id(_extract_indexed(inserts, 3))
    return user, logon_id


def _is_ignored_user(username: str) -> bool:
    normalized = _normalize_user(username).upper()
    return normalized in {"UNKNOWN", "SYSTEM", "NT AUTHORITY\\SYSTEM"}


def _normalized_user_key(username: str) -> str:
    key = _normalize_user(username).strip().upper()
    if key.endswith("$"):
        key = key[:-1]
    return key


def _prune_recent_failures(reference_time: datetime) -> None:
    cutoff = reference_time - _FAILURE_WINDOW
    before = len(_recent_failures)
    _recent_failures[:] = [f for f in _recent_failures if f["timestamp"] >= cutoff]
    removed = before - len(_recent_failures)
    if removed > 0:
        _debug_log(f"Removed {removed} old failures outside time window")


def _prune_sessions(reference_time: datetime) -> None:
    expired = []
    for logon_id, session in _sessions.items():
        success_time = session.get("success_time")
        if isinstance(success_time, datetime) and (reference_time - success_time) > _SESSION_TIMEOUT:
            expired.append(logon_id)
    for logon_id in expired:
        _sessions.pop(logon_id, None)
    if expired:
        _debug_log(f"Removed {len(expired)} expired sessions")


def _emit_high_alert(logon_id: str, session: Dict[str, Any], privilege_ts: Any, privilege_record: Any) -> None:
    print("[ALERT][HIGH] Possible brute force detected with privilege escalation")
    print(f"Logon ID: {logon_id}")
    print(f"User: {session.get('user')}")
    print(f"Failed Attempts: {len(session.get('failures', []))}")
    print("Sequence: 4625 -> 4624 -> 4672")
    print(f"4624 Timestamp: {session.get('success_timestamp')}")
    print(f"4624 Record number: {session.get('success_record')}")
    print(f"4672 Timestamp: {privilege_ts}")
    print(f"4672 Record number: {privilege_record}")


def _find_session_for_privilege_event(
    privilege_user: str, privilege_logon_id: str | None, privilege_time: datetime
) -> Tuple[str | None, Dict[str, Any] | None, bool]:
    # Primary: exact logon_id match.
    if privilege_logon_id is not None:
        exact = _sessions.get(privilege_logon_id)
        if exact is not None:
            return privilege_logon_id, exact, False

    # Fallback: same user + near success timestamp.
    user_key = _normalized_user_key(privilege_user)
    for session_logon_id, session in _sessions.items():
        session_user = session.get("user")
        success_time = session.get("success_time")
        if not isinstance(session_user, str) or not isinstance(success_time, datetime):
            continue
        if _normalized_user_key(session_user) != user_key:
            continue
        if abs(privilege_time - success_time) <= _FALLBACK_SESSION_MATCH_WINDOW:
            return session_logon_id, session, True

    # Secondary fallback: nearest-by-time session regardless of user mismatch.
    for session_logon_id, session in _sessions.items():
        success_time = session.get("success_time")
        if not isinstance(success_time, datetime):
            continue
        if abs(privilege_time - success_time) <= _FALLBACK_SESSION_MATCH_WINDOW:
            return session_logon_id, session, True

    return None, None, False


def detect_failed_login(events: Iterable[Dict[str, Any]]) -> None:
    """
    Simple detection rule for testing.

    Detects Windows Security Event ID 4625 (failed logon).
    """

    normalized_events: List[Dict[str, Any]] = []
    _debug_log(
        f"Starting correlation pass. failures={len(_recent_failures)} sessions={len(_sessions)}"
    )

    for ev in events:
        timestamp = ev.get("timestamp")
        if not isinstance(timestamp, datetime):
            continue
        try:
            event_id = int(ev.get("event_id"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue

        username = "Unknown"
        logon_id: str | None = None
        source_ip: str | None = None
        inserts = ev.get("string_inserts")
        if event_id == 4625:
            username, _, source_ip = _extract_4625_fields_from_inserts(inserts)
        elif event_id == 4624:
            username, logon_id, source_ip = _extract_4624_fields(inserts)
        elif event_id == 4672:
            username, logon_id = _extract_4672_fields(inserts)
        else:
            continue

        if _is_ignored_user(username):
            _debug_log(f"Ignoring event_id={event_id} for system/unknown user={username}")
            continue

        normalized_events.append(
            {
                "event_id": event_id,
                "ts": timestamp,
                "timestamp": ev.get("timestamp"),
                "record_number": ev.get("record_number"),
                "string_inserts": inserts,
                "username": username,
                "logon_id": logon_id,
                "source_ip": source_ip,
            }
        )

    # For identical timestamps, keep auth flow order: 4625 -> 4624 -> 4672.
    normalized_events.sort(
        key=lambda item: (item["ts"], _EVENT_PRIORITY.get(item["event_id"], 99))
    )

    latest_event_time: datetime | None = None
    for item in normalized_events:
        event_id = item["event_id"]
        ts_dt = item["ts"]
        timestamp = item["timestamp"]
        record_number = item["record_number"]
        username = item["username"]
        logon_id = item["logon_id"]
        source_ip = item["source_ip"]

        _prune_recent_failures(ts_dt)
        _prune_sessions(ts_dt)
        latest_event_time = ts_dt

        if event_id == 4625:
            _recent_failures.append(
                {
                    "timestamp": ts_dt,
                    "record_number": record_number,
                    "user": username,
                    "source_ip": source_ip,
                }
            )
            _debug_log(
                f"Added 4625 failure user={username} ip={source_ip} ts={timestamp} "
                f"recent_failures={len(_recent_failures)}"
            )
            _prune_recent_failures(ts_dt)
            _debug_log(f"Stored failure timestamps: {[x['timestamp'].isoformat() for x in _recent_failures]}")
            continue

        if event_id == 4624:
            _debug_log(
                f"success detected: user={username} logon_id={logon_id} ip={source_ip} "
                f"ts={timestamp} record={record_number}"
            )
            if logon_id is None:
                _debug_log("ALERT NOT TRIGGERED: success missing logon_id")
                continue

            window_start = ts_dt - _FAILURE_WINDOW
            matched_failures = [
                f
                for f in _recent_failures
                if window_start <= f["timestamp"] <= ts_dt
                and (
                    source_ip is None
                    or f.get("source_ip") is None
                    or f.get("source_ip") == source_ip
                )
            ]
            _debug_log(
                f"Recent failures for success(logon_id={logon_id}): {len(matched_failures)} "
                f"(threshold={_FAILED_THRESHOLD})"
            )
            if len(matched_failures) >= _FAILED_THRESHOLD:
                _debug_log("failures detected: threshold met before success")
                _sessions[logon_id] = {
                    "user": username,
                    "success_time": ts_dt,
                    "success_timestamp": timestamp,
                    "success_record": record_number,
                    "source_ip": source_ip,
                    "has_privilege": False,
                    "failures": matched_failures,
                }
                _debug_log(
                    f"Session linked for logon_id={logon_id} with {len(matched_failures)} failures"
                )
            else:
                _debug_log(
                    "ALERT NOT TRIGGERED: success seen but failure threshold not met in time window"
                )
            continue

        if event_id == 4672:
            _debug_log(
                f"privilege detected: user={username} logon_id={logon_id} ts={timestamp} record={record_number}"
            )
            matched_logon_id, session, used_fallback = _find_session_for_privilege_event(
                username, logon_id, ts_dt
            )
            if matched_logon_id is None or session is None:
                _debug_log(
                    "ALERT NOT TRIGGERED: no matching session for privilege event "
                    "(exact logon_id and fallback user+time both failed)"
                )
                continue

            if used_fallback:
                _debug_log(
                    f"Fallback session match used: 4672(logon_id={logon_id}) -> "
                    f"session(logon_id={matched_logon_id})"
                )
                if _normalized_user_key(username) != _normalized_user_key(str(session.get("user", ""))):
                    _debug_log("Fallback used despite user mismatch (time-proximity correlation)")

            session["has_privilege"] = True
            _debug_log(f"Session privilege linked for logon_id={matched_logon_id}")

            failure_count = len(session.get("failures", []))
            if failure_count < _FAILED_THRESHOLD:
                _debug_log("ALERT NOT TRIGGERED: session does not have enough failures")
                continue

            last_alert_at = _last_alert_by_logon_id.get(matched_logon_id)
            in_cooldown = (
                isinstance(last_alert_at, datetime)
                and (ts_dt - last_alert_at) < _ALERT_COOLDOWN
            )
            if in_cooldown:
                _debug_log(
                    f"ALERT NOT TRIGGERED: cooldown active for logon_id={matched_logon_id} "
                    f"({int((ts_dt - last_alert_at).total_seconds())}s elapsed)"
                )
            else:
                alert_user = str(session.get("user", username))
                last_user_alert_at = _last_alert_time_per_user.get(alert_user)
                user_in_cooldown = (
                    isinstance(last_user_alert_at, datetime)
                    and (ts_dt - last_user_alert_at) < _ALERT_COOLDOWN
                )
                if user_in_cooldown:
                    _debug_log("ALERT SUPPRESSED due to cooldown")
                else:
                    _emit_high_alert(matched_logon_id, session, timestamp, record_number)
                    _last_alert_by_logon_id[matched_logon_id] = ts_dt
                    _last_alert_time_per_user[alert_user] = ts_dt
                    _debug_log("ALERT TRIGGERED")
            # Consume this session after evaluation to avoid duplicate linking.
            _sessions.pop(matched_logon_id, None)

            # Already handled 4672 correlation path.
            continue

    if latest_event_time is not None:
        _prune_recent_failures(latest_event_time)
        _prune_sessions(latest_event_time)
        _debug_log(
            f"End correlation pass. failures={len(_recent_failures)} sessions={len(_sessions)}"
        )
