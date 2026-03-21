"""
Disk and file system forensics.

Capabilities:
  - File system timeline generation (MAC times)
  - Deleted file carving (signature-based)
  - Metadata extraction
  - Suspicious file detection (double extensions, hidden files, executables in unusual paths)
  - MFT/USN journal analysis helpers
"""

import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from src.utils.hash_utils import compute_hashes


# Suspicious file patterns
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com", ".pif"}
DOUBLE_EXT_RE = re.compile(r"\.[a-zA-Z]{2,4}\.(exe|dll|bat|ps1|vbs|js|hta|scr|com)$", re.I)
SCRIPT_IN_TEMP_RE = re.compile(r"(temp|tmp|appdata|downloads)", re.I)

# Common file magic bytes (hex signatures)
FILE_SIGNATURES = {
    b"\x4d\x5a": "PE Executable (EXE/DLL)",
    b"\x7fELF": "ELF Executable (Linux)",
    b"\x50\x4b\x03\x04": "ZIP Archive",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\xd0\xcf\x11\xe0": "OLE2 Compound File (Office)",
    b"\x89PNG": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"\x1f\x8b": "GZIP Archive",
    b"\x37\x7a\xbc\xaf": "7-Zip Archive",
    b"\x52\x61\x72\x21": "RAR Archive",
    b"MZ": "DOS/PE Executable",
}


@dataclass
class FileMetadata:
    path: str
    name: str
    size_bytes: int
    created: Optional[str]
    modified: Optional[str]
    accessed: Optional[str]
    md5: str
    sha256: str
    extension: str
    magic_type: Optional[str]
    is_suspicious: bool
    suspicious_reasons: List[str]
    is_hidden: bool
    permissions: str


@dataclass
class TimelineEntry:
    timestamp: datetime
    event_type: str    # created | modified | accessed | changed
    path: str
    size_bytes: int


class DiskForensics:
    """Perform file system forensic analysis on a directory or mounted image."""

    def __init__(self, root_path: str, compute_file_hashes: bool = True):
        self.root = Path(root_path)
        self.compute_hashes = compute_file_hashes

    # ------------------------------------------------------------------
    # File Metadata
    # ------------------------------------------------------------------

    def get_file_metadata(self, file_path: str) -> FileMetadata:
        """Extract full metadata for a single file."""
        path = Path(file_path)
        st = path.stat()
        ext = path.suffix.lower()
        magic = self._detect_magic(path)
        suspicious, reasons = self._check_suspicious(path, ext, magic)

        hashes = {"md5": "N/A", "sha256": "N/A"}
        if self.compute_hashes and path.is_file() and st.st_size < 500 * 1024 * 1024:
            try:
                hashes = compute_hashes(str(path), ("md5", "sha256"))
            except (PermissionError, OSError):
                pass

        return FileMetadata(
            path=str(path),
            name=path.name,
            size_bytes=st.st_size,
            created=self._ts(st.st_ctime),
            modified=self._ts(st.st_mtime),
            accessed=self._ts(st.st_atime),
            md5=hashes["md5"],
            sha256=hashes["sha256"],
            extension=ext,
            magic_type=magic,
            is_suspicious=suspicious,
            suspicious_reasons=reasons,
            is_hidden=path.name.startswith(".") or bool(st.st_file_attributes & 2) if hasattr(st, "st_file_attributes") else path.name.startswith("."),
            permissions=oct(stat.S_IMODE(st.st_mode)),
        )

    def scan_directory(self, path: Optional[str] = None) -> Generator[FileMetadata, None, None]:
        """Recursively scan a directory, yielding FileMetadata for each file."""
        root = Path(path) if path else self.root
        for item in root.rglob("*"):
            if item.is_file():
                try:
                    yield self.get_file_metadata(str(item))
                except (PermissionError, OSError):
                    continue

    def find_suspicious_files(self, path: Optional[str] = None) -> List[FileMetadata]:
        """Return only files flagged as suspicious."""
        return [f for f in self.scan_directory(path) if f.is_suspicious]

    # ------------------------------------------------------------------
    # Timeline Analysis
    # ------------------------------------------------------------------

    def build_timeline(self, path: Optional[str] = None) -> List[TimelineEntry]:
        """Build a MAC-time filesystem timeline sorted by timestamp."""
        entries: List[TimelineEntry] = []
        root = Path(path) if path else self.root

        for item in root.rglob("*"):
            if not item.is_file():
                continue
            try:
                st = item.stat()
                size = st.st_size
                entries += [
                    TimelineEntry(datetime.fromtimestamp(st.st_mtime, tz=timezone.utc), "modified", str(item), size),
                    TimelineEntry(datetime.fromtimestamp(st.st_atime, tz=timezone.utc), "accessed", str(item), size),
                    TimelineEntry(datetime.fromtimestamp(st.st_ctime, tz=timezone.utc), "changed/created", str(item), size),
                ]
            except (PermissionError, OSError):
                continue

        entries.sort(key=lambda e: e.timestamp)
        return entries

    def timeline_to_csv(self, output_path: str, path: Optional[str] = None) -> str:
        """Export timeline to CSV for analysis in Excel/timeline tools."""
        import csv
        entries = self.build_timeline(path)
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Timestamp (UTC)", "Event Type", "File Path", "Size (bytes)"])
            for e in entries:
                writer.writerow([e.timestamp.isoformat(), e.event_type, e.path, e.size_bytes])
        return output_path

    # ------------------------------------------------------------------
    # File Carving (signature-based)
    # ------------------------------------------------------------------

    def carve_files(self, source_path: str, output_dir: str, target_sigs: Optional[list] = None) -> List[str]:
        """
        Basic signature-based file carving from raw binary data.
        Searches for magic bytes and extracts chunks around them.
        Returns list of carved file paths.
        """
        sigs = target_sigs or list(FILE_SIGNATURES.keys())
        carved = []
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        with open(source_path, "rb") as fh:
            data = fh.read()

        for sig in sigs:
            offset = 0
            count = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                # Carve 10 MB after signature (adjust for production use)
                chunk = data[pos:pos + 10 * 1024 * 1024]
                label = FILE_SIGNATURES.get(sig, "unknown").split()[0].lower().replace("/", "_")
                carved_path = out / f"carved_{label}_{pos:010d}_{count}.bin"
                with open(carved_path, "wb") as cf:
                    cf.write(chunk)
                carved.append(str(carved_path))
                offset = pos + len(sig)
                count += 1

        return carved

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_magic(path: Path) -> Optional[str]:
        """Read first 8 bytes and match against known file signatures."""
        try:
            with open(path, "rb") as fh:
                header = fh.read(8)
            for sig, name in FILE_SIGNATURES.items():
                if header.startswith(sig):
                    return name
        except (PermissionError, OSError):
            pass
        return None

    @staticmethod
    def _check_suspicious(path: Path, ext: str, magic: Optional[str]) -> tuple:
        reasons = []
        # Mismatch between extension and magic type
        if magic and "Executable" in magic and ext not in (".exe", ".dll", ".com", ".scr"):
            reasons.append(f"Executable magic but extension is '{ext}'")
        # Double extension
        if DOUBLE_EXT_RE.search(path.name):
            reasons.append("Double extension detected")
        # Executable in suspicious directory
        if ext in SUSPICIOUS_EXTENSIONS and SCRIPT_IN_TEMP_RE.search(str(path)):
            reasons.append(f"Executable/script in suspicious directory ({path.parent})")
        # Very long filename (often used to hide extension)
        if len(path.name) > 100:
            reasons.append(f"Unusually long filename ({len(path.name)} chars)")
        return bool(reasons), reasons

    @staticmethod
    def _ts(epoch: float) -> str:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
