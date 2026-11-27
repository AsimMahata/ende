"""
History logging and audit trail for ende operations.
Stores history in ~/.ende/history.json with configurable fallback.
Author: asim
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional


def get_history_dir() -> Path:
    """Gets history directory, respecting ENDE_HOME or falling back gracefully."""
    env_dir = os.environ.get("ENDE_HOME")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p
    try:
        home_dir = Path.home() / ".ende"
        home_dir.mkdir(parents=True, exist_ok=True)
        return home_dir
    except (PermissionError, OSError):
        local_dir = Path.cwd() / ".ende"
        try:
            local_dir.mkdir(parents=True, exist_ok=True)
            return local_dir
        except Exception:
            import tempfile
            tmp = Path(tempfile.gettempdir()) / ".ende"
            tmp.mkdir(parents=True, exist_ok=True)
            return tmp


def get_history_file() -> Path:
    return get_history_dir() / "history.json"


def load_history() -> List[Dict[str, Any]]:
    """Loads existing history records."""
    h_file = get_history_file()
    if not h_file.exists():
        return []
    try:
        with open(h_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []


def save_history(records: List[Dict[str, Any]]) -> None:
    """Saves history records atomically."""
    h_dir = get_history_dir()
    h_file = get_history_file()
    temp_file = h_dir / f"history_{os.getpid()}.tmp"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)
        temp_file.replace(h_file)
    except Exception:
        # Fallback to direct write if replace fails
        try:
            with open(h_file, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, ensure_ascii=False)
        except Exception:
            pass


def add_history_entry(
    action: str,
    source_file: str,
    target_file: str,
    file_size_bytes: int,
    sha256: str,
    layers: int = 1,
    compressed: bool = True,
    status: str = "SUCCESS",
    details: Optional[str] = None,
) -> Dict[str, Any]:
    """Adds a new operation record to history without throwing on I/O errors."""
    entry = {
        "id": 1,
        "timestamp": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "author": "asim",
        "action": action.upper(),
        "source": str(source_file),
        "target": str(target_file),
        "size_bytes": file_size_bytes,
        "sha256": sha256,
        "layers": layers,
        "compressed": compressed,
        "status": status.upper(),
        "details": details or "",
    }
    try:
        records = load_history()
        entry["id"] = len(records) + 1
        records.append(entry)
        save_history(records)
    except Exception:
        pass
    return entry


def clear_history() -> int:
    """Clears history records. Returns count of deleted records."""
    records = load_history()
    count = len(records)
    h_file = get_history_file()
    if h_file.exists():
        try:
            h_file.unlink()
        except Exception:
            save_history([])
    return count


def format_history_table(records: Optional[List[Dict[str, Any]]] = None) -> str:
    """Renders a readable formatted table of history records."""
    if records is None:
        records = load_history()
    
    if not records:
        return f"No history records found in {get_history_file()}."

    headers = ["ID", "Timestamp", "Action", "Source", "Target", "Layers", "Status"]
    
    rows = []
    for r in records[-30:]:
        source_name = Path(r.get("source", "")).name
        target_name = Path(r.get("target", "")).name
        rows.append([
            str(r.get("id", "")),
            r.get("timestamp", "")[:19],
            r.get("action", ""),
            source_name if len(source_name) <= 22 else source_name[:19] + "...",
            target_name if len(target_name) <= 22 else target_name[:19] + "...",
            str(r.get("layers", 1)),
            r.get("status", "SUCCESS"),
        ])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(cell))

    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_line = "| " + " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers)) + " |"

    lines = [
        "",
        "============================== ENDE HISTORY LOG ==============================",
        f"Total records: {len(records)}  |  Log: {get_history_file()}",
        sep,
        header_line,
        sep,
    ]
    for row in rows:
        row_line = "| " + " | ".join(f"{cell:<{col_widths[i]}}" for i, cell in enumerate(row)) + " |"
        lines.append(row_line)
    lines.append(sep)
    lines.append("")
    return "\n".join(lines)
