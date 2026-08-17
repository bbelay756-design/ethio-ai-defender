"""
Analysis Records and Metadata Store for ETHIO-AI Defender.
Maintains in-memory and persistent JSON indices of analyzed files.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict, field

from app.core.config import settings
from app.core.logger import logger


@dataclass
class FileRecord:
    """Represents the saved metadata for an analyzed sample."""
    analysis_id: str
    filename: str
    original_filename: str
    size: int
    sha256: str
    md5: str
    sha1: str
    status: str
    uploaded_at: str
    file_type: str
    quarantined_path: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_api_response(self) -> Dict[str, Any]:
        """Returns the standard API format required by ETHIO-AI Defender."""
        return {
            "analysis_id": self.analysis_id,
            "filename": self.filename,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "status": self.status,
        }


class AnalysisStore:
    """Thread-safe storage manager for file intake records and hash deduplication."""

    def __init__(self, records_dir: Optional[Path] = None):
        self.records_dir = records_dir or (settings.STORAGE_BASE_DIR / "records")
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._counter = 1
        self._cache: Dict[str, FileRecord] = {}
        self._sha256_index: Dict[str, str] = {}  # Map: sha256.lower() -> analysis_id
        self._initialize_from_disk()

    def _initialize_from_disk(self) -> None:
        """Initializes counter and SHA-256 lookup index from existing records on disk."""
        with self._lock:
            existing_files = list(self.records_dir.glob("ANL-*.json"))
            highest = 0
            for f in existing_files:
                try:
                    num_part = f.stem.replace("ANL-", "")
                    val = int(num_part)
                    if val > highest:
                        highest = val

                    # Load and index record
                    with open(f, "r", encoding="utf-8") as rf:
                        data = json.load(rf)
                    rec = FileRecord(**data)
                    self._cache[rec.analysis_id] = rec
                    if rec.sha256:
                        self._sha256_index[rec.sha256.lower()] = rec.analysis_id
                except Exception as err:
                    logger.warning(f"Could not load historical record from {f.name}: {err}")
                    continue

            self._counter = highest + 1

    def generate_analysis_id(self) -> str:
        """Generates a sequential, formatted analysis identifier (e.g., 'ANL-000001')."""
        with self._lock:
            current_id = f"ANL-{self._counter:06d}"
            self._counter += 1
            return current_id

    def save_record(self, record: FileRecord) -> None:
        """Saves a record to cache, updates hash index, and writes a persistent JSON copy."""
        with self._lock:
            self._cache[record.analysis_id] = record
            if record.sha256:
                self._sha256_index[record.sha256.lower()] = record.analysis_id

            record_file = self.records_dir / f"{record.analysis_id}.json"
            try:
                with open(record_file, "w", encoding="utf-8") as f:
                    json.dump(asdict(record), f, indent=2)
                logger.info(f"Saved analysis record for {record.analysis_id} ({record.filename})")
            except Exception as e:
                logger.error(f"Failed to persist record {record.analysis_id}: {e}")

    def get_record(self, analysis_id: str) -> Optional[FileRecord]:
        """Retrieves a record by analysis ID from memory cache or persistent storage."""
        with self._lock:
            if analysis_id in self._cache:
                return self._cache[analysis_id]

            record_file = self.records_dir / f"{analysis_id}.json"
            if record_file.is_file():
                try:
                    with open(record_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    rec = FileRecord(**data)
                    self._cache[analysis_id] = rec
                    if rec.sha256:
                        self._sha256_index[rec.sha256.lower()] = rec.analysis_id
                    return rec
                except Exception as e:
                    logger.error(f"Error loading record {analysis_id}: {e}")
                    return None
            return None

    def get_record_by_sha256(self, sha256: str) -> Optional[FileRecord]:
        """Looks up an analyzed record by its SHA-256 hash."""
        if not sha256:
            return None
        clean_hash = sha256.strip().lower()
        with self._lock:
            if clean_hash in self._sha256_index:
                analysis_id = self._sha256_index[clean_hash]
                return self.get_record(analysis_id)
            return None

    def has_sha256(self, sha256: str) -> bool:
        """Determines whether a sample with the given SHA-256 hash has already been analyzed."""
        if not sha256:
            return False
        clean_hash = sha256.strip().lower()
        with self._lock:
            return clean_hash in self._sha256_index


# Global singleton store instance
analysis_store = AnalysisStore()
