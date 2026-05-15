from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from config import DEBUG


suspicious_processes = [
    "powershell.exe",
    "pwsh.exe",
    "wmic.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "schtasks.exe",
]

_IGNORED_EXACT_USERS = {
    "SYSTEM",
    "NT AUTHORITY\\SYSTEM",
    "LOCAL SERVICE",
    "NT AUTHORITY\\LOCAL SERVICE",
    "NETWORK SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE",
}


def debug(msg: str) -> None:
    if DEBUG:
        print(msg)


def _debug_log(message: str) -> None:
    if DEBUG:
        debug(f"[DEBUG][PROC4688] {message}")


def _norm_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _norm_user(value: Any) -> str:
    user = _norm_text(value)
    if not user or user in {"-", "NULL", "null"}:
        return "Unknown"
    return user


def _extract_process_names(raw_value: str) -> List[str]:
    value = raw_value.strip()
    if not value:
        return []

    process_names: List[str] = []
    for token in value.split():
        lower_token = token.lower()
        if ".exe" not in lower_token:
            continue
        if "\\" not in token and "/" not in token:
            continue

        cleaned = token.replace('"', "")
        if "%%" in cleaned:
            cleaned = cleaned.split("%%", 1)[0]

        lower_cleaned = cleaned.lower()
        exe_pos = lower_cleaned.find(".exe")
        if exe_pos == -1:
            continue
        cleaned = cleaned[: exe_pos + 4]

        process_name = cleaned.split("\\")[-1].split("/")[-1].lower().strip()
        print("DEBUG CLEAN PROCESS:", repr(process_name))
        if process_name:
            process_names.append(process_name)

    return process_names


def _extract_4688_fields(ev: Dict[str, Any]) -> Tuple[str, str, str, str]:
    user = _norm_user(ev.get("user"))
    process_name = _norm_text(ev.get("process_name"))
    parent_process_name = _norm_text(ev.get("parent_process_name"))
    command_line = _norm_text(ev.get("command_line"))

    inserts = ev.get("string_inserts")
    if isinstance(inserts, list):
        # Common 4688 mapping (varies by Windows build/audit policy):
        # [1] SubjectUserName, [5] NewProcessName, [9] ProcessCommandLine,
        # [13] ParentProcessName.
        if user == "Unknown" and len(inserts) > 1:
            user = _norm_user(inserts[1])
        if not process_name and len(inserts) > 5:
            process_name = _norm_text(inserts[5])
        if not command_line and len(inserts) > 9:
            command_line = _norm_text(inserts[9])
        if not parent_process_name and len(inserts) > 13:
            parent_process_name = _norm_text(inserts[13])

    if process_name:
        raw = process_name
        exe_pos = raw.lower().find(".exe")
        if exe_pos != -1:
            start = raw.rfind('"', 0, exe_pos + 4)
            if start == -1:
                c_pos = raw.lower().rfind("c:", 0, exe_pos + 4)
                start = c_pos if c_pos != -1 else 0

            sid_pos = raw.find(" S-1-", exe_pos + 4)
            end = sid_pos if sid_pos != -1 else len(raw)

            command_line = raw[start:end].strip()
        else:
            command_line = ""
        print("DEBUG CMD:", repr(command_line))

    if parent_process_name:
        parent_process_name = parent_process_name.replace("\\", "/").split("/")[-1]

    return user, process_name, parent_process_name, command_line


def _is_ignored_user(user: str) -> bool:
    normalized = _norm_user(user).upper()
    if normalized in _IGNORED_EXACT_USERS:
        return True
    return normalized.endswith("$")


def detect_suspicious_process_creation(events: Iterable[Dict[str, Any]]) -> None:
    for ev in events:
        try:
            event_id = int(ev.get("event_id"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue

        if event_id != 4688:
            continue

        timestamp = ev.get("timestamp")
        if not isinstance(timestamp, datetime):
            _debug_log("Skipping 4688 without valid datetime timestamp")
            continue

        user, process_name, parent_process_name, command_line = _extract_4688_fields(ev)
        process_names = _extract_process_names(process_name)
        matched_process = next((p for p in process_names if p in suspicious_processes), "")
        process_name_lc = matched_process
        print("DEBUG PROCESS:", process_name_lc)
        print("DEBUG MATCH:", process_name_lc in suspicious_processes)
        print("DEBUG ALL PROCESSES:", process_names)
        print("DEBUG MATCH FOUND:", matched_process)

        _debug_log(
            f"4688 user={user} process={process_name_lc or 'unknown'} parent={parent_process_name or 'unknown'}"
        )

        if _is_ignored_user(user):
            _debug_log(f"Ignoring service/system/machine account user={user}")
            continue

        if not any(p in suspicious_processes for p in process_names):
            continue

        print("DEBUG ALERT TRIGGERED")
        print("[ALERT][MEDIUM] Suspicious process execution detected")
        print(f"User: {user}")
        print(f"Process: {matched_process}")
        print(f"Parent: {parent_process_name or 'Unknown'}")
        print(f"Timestamp: {timestamp}")
        if command_line:
            print(f"CommandLine: {command_line}")
