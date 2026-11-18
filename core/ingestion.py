import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

def compute_file_hash(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def load_and_normalize(filepath: str) -> list[dict]:
    path = Path(filepath)
    file_hash = compute_file_hash(filepath)
    ingested_at = datetime.now(timezone.utc).isoformat()
    with open(filepath, "r", encoding="utf-8") as f:
        raw_events = json.load(f)
    normalized = []
    for ev in raw_events:
        normalized.append({
            "event_id": ev["event_id"],
            "timestamp": datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00")),
            "device": ev["device"],
            "event_type": ev["event_type"],
            "details": ev["details"],
            "actor": ev.get("actor", "unknown"),
            "provenance": {
                "source_file": path.name,
                "sha256": file_hash,
                "ingested_at": ingested_at,
                "raw_record": ev
            }
        })
    return normalized
