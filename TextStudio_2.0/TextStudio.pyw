#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TextStudio 2.0
Large-text/log viewer with annotations, bookmarks, regex search, tabs and lazy line index.
Standard library only: tkinter, mmap, sqlite3, threading, re, json, csv.
"""

from __future__ import annotations

import bisect
import csv
import hashlib
import json
import mmap
import os
import queue
import re
import sqlite3
import sys
import threading
import time
import posixpath
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    from remote_support import (
        HAS_PARAMIKO, RemoteSession, RemoteTextFile, RemoteLineIndex, remote_identity
    )
except Exception:
    HAS_PARAMIKO = False
    RemoteSession = RemoteTextFile = RemoteLineIndex = None
    def remote_identity(user, host, port, path):
        return f"ssh://{user}@{host}:{port}{path}"

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_NATIVE_DND = True
except Exception:
    DND_FILES = None
    TkinterDnD = None
    HAS_NATIVE_DND = False

APP_NAME = "TextMark"
VERSION = "2.0"

PAGE_LINES = 240
PAGE_MAX_BYTES = 8 * 1024 * 1024
INDEX_CHUNK = 4 * 1024 * 1024
REGEX_CHUNK = 512 * 1024

MARK_COLORS = {
    "yellow": "#FFF2A8",
    "red": "#FFD1D1",
    "green": "#D5F5D5",
    "blue": "#D7E8FF",
}
MARK_LABELS = {
    "yellow": "黄色",
    "red": "红色",
    "green": "绿色",
    "blue": "蓝色",
}
LABEL_TO_MARK = {v: k for k, v in MARK_LABELS.items()}

ENCODING_CHOICES = ["自动", "UTF-8", "GB18030", "Latin-1", "UTF-16 LE", "UTF-16 BE"]
ENCODING_MAP = {
    "UTF-8": "utf-8",
    "GB18030": "gb18030",
    "Latin-1": "latin-1",
    "UTF-16 LE": "utf-16-le",
    "UTF-16 BE": "utf-16-be",
}

# Precompile hot-path patterns once.  They are evaluated for every visible log
# line on each viewport refresh.
SEVERITY_ERROR_RE = re.compile(
    r"(^|[\s\[\(<])(?:ERROR|FATAL|CRITICAL|SEVERE)(?=$|[\s\]\)>:])", re.IGNORECASE
)
SEVERITY_WARN_RE = re.compile(
    r"(^|[\s\[\(<])(?:WARN|WARNING)(?=$|[\s\]\)>:])", re.IGNORECASE
)

REMOTE_HISTORY_PATH = Path.home() / ".textmark" / "remote_connections.json"
REMOTE_HISTORY_LIMIT = 20
LOCAL_DOWNLOAD_FOLDER = "textmark"


def local_textmark_download_dir():
    """Return the visible local download folder beside the portable app."""
    try:
        if getattr(sys, "frozen", False):
            base = Path(sys.executable).resolve().parent
        else:
            raw = sys.argv[0] if sys.argv and sys.argv[0] and not str(sys.argv[0]).startswith("-") else __file__
            candidate = Path(raw).expanduser().resolve()
            if candidate.is_file() or candidate.suffix.lower() in (".py", ".pyw", ".pyz", ".exe"):
                base = candidate.parent
            else:
                base = Path(__file__).resolve().parent
    except Exception:
        base = Path.cwd()
    return base / LOCAL_DOWNLOAD_FOLDER


def _remote_record_key(record):
    use_jump = bool(record.get("use_jump", False))
    return (
        str(record.get("host", "")).strip().lower(),
        int(record.get("port", 22) or 22),
        str(record.get("user", "")).strip(),
        use_jump,
        str(record.get("jump_host", "")).strip().lower() if use_jump else "",
        int(record.get("jump_port", 22) or 22) if use_jump else 22,
        str(record.get("jump_user", "")).strip() if use_jump else "",
    )


def load_remote_history():
    try:
        data = json.loads(REMOTE_HISTORY_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return []
        rows = []
        for x in data:
            if not isinstance(x, dict) or not x.get("host") or not x.get("user"):
                continue
            try:
                _remote_record_key(x)
                float(x.get("updated_at", 0) or 0)
            except (TypeError, ValueError):
                continue
            rows.append(x)
        rows.sort(key=lambda x: float(x.get("updated_at", 0) or 0), reverse=True)
        return rows[:REMOTE_HISTORY_LIMIT]
    except Exception:
        return []


def save_remote_history(records):
    REMOTE_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = REMOTE_HISTORY_PATH.with_suffix(".tmp")
    payload = json.dumps(records[:REMOTE_HISTORY_LIMIT], ensure_ascii=False, indent=2) + "\n"
    tmp.write_text(payload, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, REMOTE_HISTORY_PATH)
    try:
        os.chmod(REMOTE_HISTORY_PATH, 0o600)
    except OSError:
        pass



def document_key(path: str) -> str:
    """Stable key for local paths and ssh:// remote identities."""
    value = str(path)
    if value.startswith("ssh://"):
        return value
    return os.path.abspath(value)

def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for unit in units:
        if x < 1024 or unit == units[-1]:
            return f"{x:.0f} {unit}" if unit == "B" else f"{x:.2f} {unit}"
        x /= 1024
    return f"{n} B"


def safe_basename(path: str, max_len: int = 24) -> str:
    name = os.path.basename(path)
    if len(name) <= max_len:
        return name
    return name[: max_len - 1] + "…"


@dataclass
class PageLine:
    byte_start: int
    byte_end: int
    text: str


class MappedTextFile:
    """Read-only mmap backend. Only the current viewport is decoded."""
    is_remote = False

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.identity = self.path
        self.fp = None
        self.mm = None
        self.size = 0
        self.mtime_ns = 0
        self.encoding = "utf-8"
        self.detected_encoding = "utf-8"
        self.encoding_confidence = "高"
        self.bom = 0
        self.newline = b"\n"
        self._open()

    def _open(self):
        st = os.stat(self.path)
        self.size = st.st_size
        self.mtime_ns = st.st_mtime_ns
        self.fp = open(self.path, "rb", buffering=0)
        self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ) if self.size else None
        self._detect_encoding()

    def close(self):
        try:
            if self.mm is not None:
                self.mm.close()
        finally:
            self.mm = None
            if self.fp is not None:
                self.fp.close()
                self.fp = None

    def _detect_encoding(self):
        if not self.size or self.mm is None:
            self.encoding = self.detected_encoding = "utf-8"
            self.encoding_confidence = "高"
            self.bom, self.newline = 0, b"\n"
            return

        sample = bytes(self.mm[: min(self.size, 256 * 1024)])
        if sample.startswith(b"\xef\xbb\xbf"):
            self.encoding = self.detected_encoding = "utf-8"
            self.encoding_confidence = "高(BOM)"
            self.bom, self.newline = 3, b"\n"
            return
        if sample.startswith(b"\xff\xfe"):
            self.encoding = self.detected_encoding = "utf-16-le"
            self.encoding_confidence = "高(BOM)"
            self.bom, self.newline = 2, b"\n\x00"
            return
        if sample.startswith(b"\xfe\xff"):
            self.encoding = self.detected_encoding = "utf-16-be"
            self.encoding_confidence = "高(BOM)"
            self.bom, self.newline = 2, b"\x00\n"
            return

        # Detect BOM-less UTF-16. Newline byte order is a strong signal for text/log files,
        # while NUL distribution helps when the sample contains mostly ASCII.
        if len(sample) >= 16:
            le_nl = sample.count(b"\n\x00")
            be_nl = sample.count(b"\x00\n")
            even = sample[0::2]
            odd = sample[1::2]
            even_nul = even.count(0) / max(1, len(even))
            odd_nul = odd.count(0) / max(1, len(odd))

            if (
                (le_nl >= 2 and le_nl >= be_nl * 3)
                or (odd_nul > 0.10 and odd_nul > even_nul * 3.0)
            ):
                self.encoding = self.detected_encoding = "utf-16-le"
                self.encoding_confidence = "中"
                self.bom, self.newline = 0, b"\n\x00"
                return
            if (
                (be_nl >= 2 and be_nl >= le_nl * 3)
                or (even_nul > 0.10 and even_nul > odd_nul * 3.0)
            ):
                self.encoding = self.detected_encoding = "utf-16-be"
                self.encoding_confidence = "中"
                self.bom, self.newline = 0, b"\x00\n"
                return

        try:
            sample.decode("utf-8")
            self.encoding = self.detected_encoding = "utf-8"
            self.encoding_confidence = "高"
            self.bom, self.newline = 0, b"\n"
            return
        except UnicodeDecodeError:
            pass

        try:
            sample.decode("gb18030")
            self.encoding = self.detected_encoding = "gb18030"
            self.encoding_confidence = "中"
            self.bom, self.newline = 0, b"\n"
            return
        except UnicodeDecodeError:
            self.encoding = self.detected_encoding = "latin-1"
            self.encoding_confidence = "低"
            self.bom, self.newline = 0, b"\n"

    def set_encoding(self, encoding: str):
        self.encoding = encoding
        self.bom = 0
        if self.size and self.mm is not None:
            head = bytes(self.mm[:3])
            if encoding == "utf-8" and head.startswith(b"\xef\xbb\xbf"):
                self.bom = 3
            elif encoding == "utf-16-le" and head.startswith(b"\xff\xfe"):
                self.bom = 2
            elif encoding == "utf-16-be" and head.startswith(b"\xfe\xff"):
                self.bom = 2

        if encoding == "utf-16-le":
            self.newline = b"\n\x00"
        elif encoding == "utf-16-be":
            self.newline = b"\x00\n"
        else:
            self.newline = b"\n"

    def _floor(self) -> int:
        return self.bom if self.size >= self.bom else 0

    def read_bytes(self, start: int, end: int) -> bytes:
        if not self.size or self.mm is None:
            return b""
        start = max(0, min(int(start), self.size))
        end = max(start, min(int(end), self.size))
        return bytes(self.mm[start:end])

    def align_line_start(self, offset: int) -> int:
        if not self.size or self.mm is None:
            return 0
        floor = self._floor()
        offset = max(floor, min(int(offset), self.size))
        if offset <= floor:
            return floor
        if len(self.newline) == 2 and (offset - floor) % 2:
            offset -= 1
        p = self.mm.rfind(self.newline, floor, offset)
        return floor if p < 0 else min(self.size, p + len(self.newline))

    def line_end_after(self, offset: int) -> int:
        if not self.size or self.mm is None:
            return 0
        p = self.mm.find(self.newline, max(self._floor(), int(offset)), self.size)
        return self.size if p < 0 else p + len(self.newline)

    def move_lines_count(self, start: int, delta: int):
        if not self.size or self.mm is None or delta == 0:
            return self.align_line_start(start), 0

        floor = self._floor()
        pos = self.align_line_start(start)
        nl = self.newline
        nllen = len(nl)
        moved = 0

        if delta > 0:
            for _ in range(delta):
                p = self.mm.find(nl, pos, self.size)
                if p < 0:
                    return self.align_line_start(self.size), moved
                pos = p + nllen
                moved += 1
                if pos >= self.size:
                    return self.size, moved
            return pos, moved

        for _ in range(-delta):
            if pos <= floor:
                return floor, moved
            preceding_nl = pos - nllen
            p = self.mm.rfind(nl, floor, max(floor, preceding_nl))
            if p < 0:
                pos = floor
            else:
                pos = p + nllen
            moved -= 1
        return pos, moved

    def read_page(self, start: int, max_lines: int = PAGE_LINES, max_bytes: int = PAGE_MAX_BYTES):
        if not self.size or self.mm is None:
            return [PageLine(0, 0, "")], 0, 0, False

        start = self.align_line_start(start)
        start = max(self._floor(), start)
        pos = start
        lines = []
        truncated = False
        nl = self.newline
        nllen = len(nl)
        byte_limit = min(self.size, start + max_bytes)

        for _ in range(max_lines):
            if pos > self.size:
                break
            p = self.mm.find(nl, pos, self.size)
            if p < 0:
                p = self.size
                next_pos = self.size
            else:
                next_pos = p + nllen

            if p > byte_limit:
                p = byte_limit
                next_pos = byte_limit
                truncated = True

            content_start = pos
            if pos == 0 and self.bom:
                content_start = self.bom

            raw = bytes(self.mm[content_start:p])
            content_end = p
            if self.encoding in ("utf-8", "gb18030", "latin-1") and raw.endswith(b"\r"):
                raw, content_end = raw[:-1], p - 1
            elif self.encoding == "utf-16-le" and raw.endswith(b"\r\x00"):
                raw, content_end = raw[:-2], p - 2
            elif self.encoding == "utf-16-be" and raw.endswith(b"\x00\r"):
                raw, content_end = raw[:-2], p - 2

            text = raw.decode(self.encoding, errors="replace")
            lines.append(PageLine(content_start, content_end, text))

            if truncated or p >= self.size:
                pos = next_pos
                break
            pos = next_pos
            if pos >= self.size:
                break

        return lines, start, min(pos, self.size), truncated

    def search_literal(self, text: str, start: int, backwards: bool = False):
        if not text or not self.size or self.mm is None:
            return None
        needle = text.encode(self.encoding, errors="replace")
        if not needle:
            return None
        floor = self._floor()
        start = max(floor, min(int(start), self.size))
        p = self.mm.rfind(needle, floor, start) if backwards else self.mm.find(needle, start, self.size)
        return None if p < 0 else (p, p + len(needle))

    def ends_with_newline(self):
        if not self.size or self.mm is None:
            return False
        n = len(self.newline)
        if self.size < n:
            return False
        return bytes(self.mm[self.size - n:self.size]) == self.newline

    def has_changed(self):
        try:
            st = os.stat(self.path)
            return st.st_size != self.size or st.st_mtime_ns != self.mtime_ns
        except OSError:
            return False


class LazyLineIndex:
    """
    Background line index.
    It records a checkpoint near every 4 MB chunk, not every line.
    Opening a file never waits for index construction.
    """

    def __init__(self, path: str, size: int, mtime_ns: int, newline: bytes, bom: int = 0):
        self.path = os.path.abspath(path)
        self.size = int(size)
        self.mtime_ns = int(mtime_ns)
        self.newline = bytes(newline)
        self.bom = int(bom)

        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = None

        self.offsets = [self.bom]
        self.lines = [1]
        self.indexed_bytes = self.bom
        self.newline_total = 0
        self.complete = self.size <= self.bom
        self.error = None
        self.generation = 0

        self.cache_dir = Path.home() / ".textmark" / "indexes"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / (hashlib.sha256(self.path.encode("utf-8")).hexdigest() + ".json")

        if not self._load_cache():
            self.start()

    def _cache_payload(self):
        with self.lock:
            return {
                "path": self.path,
                "size": self.size,
                "mtime_ns": self.mtime_ns,
                "newline": self.newline.hex(),
                "bom": self.bom,
                "chunk": INDEX_CHUNK,
                "offsets": self.offsets,
                "lines": self.lines,
                "indexed_bytes": self.indexed_bytes,
                "newline_total": self.newline_total,
                "complete": self.complete,
            }

    def _load_cache(self):
        try:
            if not self.cache_path.exists():
                return False
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if (
                data.get("path") != self.path
                or int(data.get("size", -1)) != self.size
                or int(data.get("mtime_ns", -1)) != self.mtime_ns
                or data.get("newline") != self.newline.hex()
                or int(data.get("bom", -1)) != self.bom
                or int(data.get("chunk", -1)) != INDEX_CHUNK
                or not data.get("complete")
            ):
                return False
            offsets = [int(x) for x in data["offsets"]]
            lines = [int(x) for x in data["lines"]]
            if not offsets or len(offsets) != len(lines):
                return False
            with self.lock:
                self.offsets = offsets
                self.lines = lines
                self.indexed_bytes = self.size
                self.newline_total = int(data.get("newline_total", max(0, lines[-1] - 1)))
                self.complete = True
            return True
        except Exception:
            return False

    def _save_cache(self):
        try:
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache_payload(), separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, self.cache_path)
        except Exception:
            pass

    def start(self):
        with self.lock:
            if self.thread and self.thread.is_alive():
                return
            self.stop_event.clear()
            self.generation += 1
            gen = self.generation
            self.thread = threading.Thread(target=self._worker, args=(gen,), daemon=True, name="TextMarkLineIndex")
            self.thread.start()

    def stop(self):
        self.stop_event.set()

    def reset(self, size: int, mtime_ns: int, newline: bytes, bom: int):
        self.stop()
        with self.lock:
            self.size = int(size)
            self.mtime_ns = int(mtime_ns)
            self.newline = bytes(newline)
            self.bom = int(bom)
            self.offsets = [self.bom]
            self.lines = [1]
            self.indexed_bytes = self.bom
            self.newline_total = 0
            self.complete = self.size <= self.bom
            self.error = None
        if not self.complete:
            self.start()

    def extend_if_append(self, new_size: int, new_mtime_ns: int):
        new_size = int(new_size)
        with self.lock:
            old_size = self.size
            if new_size < old_size:
                return False
            self.size = new_size
            self.mtime_ns = int(new_mtime_ns)
            if new_size > self.indexed_bytes:
                self.complete = False
        if new_size > old_size:
            self.start()
        return True

    def _worker(self, gen: int):
        try:
            with self.lock:
                pos = self.indexed_bytes
                total = self.newline_total
                target = self.size

            if pos < self.bom:
                pos = self.bom

            with open(self.path, "rb", buffering=0) as f:
                f.seek(pos)
                while not self.stop_event.is_set():
                    with self.lock:
                        if gen != self.generation:
                            return
                        target = self.size
                    if pos >= target:
                        break

                    to_read = min(INDEX_CHUNK, target - pos)
                    data = f.read(to_read)
                    if not data:
                        break
                    count = data.count(self.newline)
                    if count:
                        last = data.rfind(self.newline)
                        cp_offset = pos + last + len(self.newline)
                        cp_line = total + count + 1
                        with self.lock:
                            if cp_offset > self.offsets[-1]:
                                self.offsets.append(cp_offset)
                                self.lines.append(cp_line)
                    total += count
                    pos += len(data)

                    with self.lock:
                        self.indexed_bytes = pos
                        self.newline_total = total

                with self.lock:
                    if gen != self.generation:
                        return
                    self.indexed_bytes = pos
                    self.newline_total = total
                    self.complete = pos >= self.size and not self.stop_event.is_set()
                    done = self.complete
                if done:
                    self._save_cache()
        except Exception as e:
            with self.lock:
                self.error = str(e)

    def progress(self):
        with self.lock:
            if self.size <= 0:
                return 1.0
            return min(1.0, self.indexed_bytes / self.size)

    def snapshot(self):
        with self.lock:
            return self.indexed_bytes, self.complete, self.newline_total, self.error

    def line_number_at(self, byte_offset: int, mm_obj):
        byte_offset = max(self.bom, min(int(byte_offset), self.size))
        with self.lock:
            if byte_offset > self.indexed_bytes:
                return None
            idx = bisect.bisect_right(self.offsets, byte_offset) - 1
            idx = max(0, idx)
            cp_off = self.offsets[idx]
            cp_line = self.lines[idx]
        if byte_offset <= cp_off:
            return cp_line
        return cp_line + bytes(mm_obj[cp_off:byte_offset]).count(self.newline)

    def approximate_line_number(self, byte_offset: int):
        with self.lock:
            if self.newline_total > 0 and self.indexed_bytes > self.bom:
                avg = (self.indexed_bytes - self.bom) / self.newline_total
                return max(1, int((byte_offset - self.bom) / max(1.0, avg)) + 1)
        return 1

    def offset_for_line(self, target_line: int, mm_obj):
        target_line = max(1, int(target_line))
        with self.lock:
            max_known_line = self.newline_total + 1
            if target_line > max_known_line and not self.complete:
                return None
            if target_line > max_known_line and self.complete:
                return None
            idx = bisect.bisect_right(self.lines, target_line) - 1
            idx = max(0, idx)
            pos = self.offsets[idx]
            line = self.lines[idx]

        if target_line == line:
            return pos

        nl = self.newline
        for _ in range(target_line - line):
            p = mm_obj.find(nl, pos, self.size)
            if p < 0:
                return None
            pos = p + len(nl)
        return pos


class AnnotationStore:
    def __init__(self):
        base = Path.home() / ".textmark"
        base.mkdir(parents=True, exist_ok=True)
        self.db_path = base / "annotations.sqlite3"
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS annotations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                start_byte INTEGER NOT NULL,
                end_byte INTEGER NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT 'yellow',
                excerpt TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS bookmarks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                byte_pos INTEGER NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                excerpt TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        self._migrate_legacy_schema()
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_annotations_path ON annotations(path)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_path ON bookmarks(path)")
        self.db.commit()

    def _table_columns(self, table: str):
        return {row[1] for row in self.db.execute(f"PRAGMA table_info({table})")}

    def _ensure_column(self, table: str, name: str, ddl: str):
        cols = self._table_columns(table)
        if name not in cols:
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
            return True
        return False

    def _migrate_legacy_schema(self):
        """Add missing additive fields used by older TextMark databases."""
        ann_before = self._table_columns("annotations")
        added_excerpt = self._ensure_column("annotations", "excerpt", "TEXT NOT NULL DEFAULT ''")
        added_color = self._ensure_column("annotations", "color", "TEXT NOT NULL DEFAULT 'yellow'")
        self._ensure_column("annotations", "note", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("annotations", "created_at", "TEXT NOT NULL DEFAULT ''")

        if added_excerpt and "snippet" in ann_before:
            self.db.execute("UPDATE annotations SET excerpt=COALESCE(snippet,'') WHERE excerpt='' ")
        if added_color and "highlight_color" in ann_before:
            self.db.execute("UPDATE annotations SET color=COALESCE(highlight_color,'yellow') WHERE color='yellow'")

        bm_before = self._table_columns("bookmarks")
        added_bm_excerpt = self._ensure_column("bookmarks", "excerpt", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("bookmarks", "label", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("bookmarks", "created_at", "TEXT NOT NULL DEFAULT ''")
        if added_bm_excerpt and "snippet" in bm_before:
            self.db.execute("UPDATE bookmarks SET excerpt=COALESCE(snippet,'') WHERE excerpt='' ")

    def list_annotations(self, path: str):
        cur = self.db.execute("""
            SELECT id,start_byte,end_byte,note,color,excerpt,created_at
            FROM annotations WHERE path=? ORDER BY start_byte,id
        """, (document_key(path),))
        keys = ["id", "start_byte", "end_byte", "note", "color", "excerpt", "created_at"]
        return [dict(zip(keys, row)) for row in cur.fetchall()]

    def list_bookmarks(self, path: str):
        cur = self.db.execute("""
            SELECT id,byte_pos,label,excerpt,created_at
            FROM bookmarks WHERE path=? ORDER BY byte_pos,id
        """, (document_key(path),))
        keys = ["id", "byte_pos", "label", "excerpt", "created_at"]
        return [dict(zip(keys, row)) for row in cur.fetchall()]

    def add_annotation(self, path: str, start: int, end: int, note: str, color: str, excerpt: str):
        created = time.strftime("%Y-%m-%d %H:%M:%S")
        cur = self.db.execute("""
            INSERT INTO annotations(path,start_byte,end_byte,note,color,excerpt,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (document_key(path), int(start), int(end), note, color, excerpt, created))
        self.db.commit()
        return cur.lastrowid

    def delete_annotation(self, annotation_id: int):
        self.db.execute("DELETE FROM annotations WHERE id=?", (int(annotation_id),))
        self.db.commit()

    def add_bookmark(self, path: str, byte_pos: int, label: str, excerpt: str):
        created = time.strftime("%Y-%m-%d %H:%M:%S")
        cur = self.db.execute("""
            INSERT INTO bookmarks(path,byte_pos,label,excerpt,created_at)
            VALUES(?,?,?,?,?)
        """, (document_key(path), int(byte_pos), label, excerpt, created))
        self.db.commit()
        return cur.lastrowid

    def delete_bookmark(self, bookmark_id: int):
        self.db.execute("DELETE FROM bookmarks WHERE id=?", (int(bookmark_id),))
        self.db.commit()

    def close(self):
        self.db.close()


def _align_start_map(mm_obj, size: int, newline: bytes, bom: int, offset: int):
    if not size:
        return 0
    offset = max(bom, min(int(offset), size))
    if offset <= bom:
        return bom
    if len(newline) == 2 and (offset - bom) % 2:
        offset -= 1
    p = mm_obj.rfind(newline, bom, offset)
    return bom if p < 0 else p + len(newline)


def regex_search_file(path: str, encoding: str, newline: bytes, bom: int,
                      pattern: str, start_byte: int, backwards: bool, case_sensitive: bool,
                      cancel_check=None):
    """
    Unicode-aware chunked regex search. Chunks begin at line boundaries.
    This avoids loading the whole file. Cross-chunk multi-line matches are not guaranteed.
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    rx = re.compile(pattern, flags)
    size = os.path.getsize(path)
    if size <= 0:
        return None

    with open(path, "rb", buffering=0) as fp:
        mm_obj = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            start_byte = max(bom, min(int(start_byte), size))

            if not backwards:
                chunk_start = _align_start_map(mm_obj, size, newline, bom, start_byte)
                first = True
                while chunk_start < size:
                    if cancel_check and cancel_check():
                        return None
                    nominal = min(size, chunk_start + REGEX_CHUNK)
                    if nominal < size:
                        p = mm_obj.find(newline, nominal, size)
                        chunk_end = size if p < 0 else p + len(newline)
                    else:
                        chunk_end = size

                    raw = bytes(mm_obj[chunk_start:chunk_end])
                    text = raw.decode(encoding, errors="replace")

                    char_from = 0
                    if first and start_byte > chunk_start:
                        prefix = bytes(mm_obj[chunk_start:start_byte]).decode(encoding, errors="replace")
                        char_from = len(prefix)
                    m = rx.search(text, char_from)
                    if m:
                        pre = text[:m.start()].encode(encoding, errors="replace")
                        hit = text[m.start():m.end()].encode(encoding, errors="replace")
                        a = chunk_start + len(pre)
                        return (a, a + len(hit))
                    if chunk_end >= size:
                        return None
                    chunk_start = chunk_end
                    first = False
                return None

            # backwards
            search_limit = start_byte
            chunk_end = start_byte
            # Include rest of the current line, then filter results to start before search_limit.
            p = mm_obj.find(newline, start_byte, size)
            if p >= 0:
                chunk_end = p + len(newline)
            else:
                chunk_end = size

            while chunk_end > bom:
                if cancel_check and cancel_check():
                    return None
                nominal = max(bom, chunk_end - REGEX_CHUNK)
                chunk_start = _align_start_map(mm_obj, size, newline, bom, nominal)
                raw = bytes(mm_obj[chunk_start:chunk_end])
                text = raw.decode(encoding, errors="replace")
                if search_limit <= chunk_start:
                    limit_char = 0
                elif search_limit >= chunk_end:
                    limit_char = len(text)
                else:
                    prefix_raw = bytes(mm_obj[chunk_start:search_limit])
                    limit_char = len(prefix_raw.decode(encoding, errors="replace"))

                last_span = None
                for m in rx.finditer(text):
                    if cancel_check and cancel_check():
                        return None
                    if m.start() < limit_char:
                        last_span = m.span()
                    else:
                        break
                if last_span:
                    a_char, b_char = last_span
                    pre = text[:a_char].encode(encoding, errors="replace")
                    hit = text[a_char:b_char].encode(encoding, errors="replace")
                    a = chunk_start + len(pre)
                    return (a, a + len(hit))
                if chunk_start <= bom:
                    return None
                chunk_end = chunk_start
            return None
        finally:
            mm_obj.close()


class DocumentView(ttk.Frame):
    def __init__(self, app, parent, path: str, backend=None):
        super().__init__(parent)
        self.app = app
        if backend is None:
            self.path = os.path.abspath(path)
            self.backend = MappedTextFile(self.path)
        else:
            self.backend = backend
            self.path = getattr(backend, "identity", str(path))

        if getattr(self.backend, "is_remote", False):
            self.index = RemoteLineIndex(self.backend)
        else:
            self.index = LazyLineIndex(
                self.path, self.backend.size, self.backend.mtime_ns,
                self.backend.newline, self.backend.bom
            )

        self.annotations = self.app.store.list_annotations(self.path)
        self.bookmarks = self.app.store.list_bookmarks(self.path)
        self.page_lines = []
        self.page_byte_starts = []
        self.page_start = 0
        self.page_end = 0
        self.page_start_line = 1
        self.page_line_exact = True
        self.gutter_was_approx = False
        self.current_match = None
        self.search_text = ""
        self.regex_mode = False
        self.case_sensitive = False
        self.follow_tail = False
        self.encoding_choice = "自动"
        self.pending_jump_line = None
        self.search_generation = 0
        self.searching = False
        self.search_results = queue.Queue()
        self.search_poll_scheduled = False
        self.visible_search_signature = None
        self.visible_search_spans = []
        self.visible_search_line_starts = [0]
        self.closed = False
        self.context_index = "1.0"
        self.click_byte = None
        self.click_text_index = None
        self.click_line = None
        self.click_col = None
        self.search_anchor_pending = False
        self._rendering = False
        self._gutter_after = None
        self._scroll_sync_after = None
        self._scroll_drag_after = None
        self._pending_scroll_fraction = None
        self._scroll_dragging = False
        self._remote_jump_generation = 0
        self._remote_jump_results = queue.Queue()
        self._remote_jump_poll_scheduled = False
        self.remote_new_bytes = 0
        self._remote_live_results = queue.Queue()
        self._remote_live_inflight = False
        self._remote_live_last_request = 0.0
        self._remote_live_error = ""

        self._build()
        self.render_at(0, line_hint=1, exact_hint=True, view_byte=0)

    def _build(self):
        main = ttk.Panedwindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=6, pady=(4, 4))

        viewer = ttk.Frame(main)
        side = ttk.Frame(main, width=340)
        main.add(viewer, weight=5)
        main.add(side, weight=1)

        text_frame = ttk.Frame(viewer)
        text_frame.pack(fill="both", expand=True)

        # A Canvas gutter avoids Tk Text.count(..., "displaylines") for every
        # buffered line.  That call forces expensive wrapped-layout work and was
        # the main reason a large file could take seconds to open.  We now draw
        # only the logical line numbers whose first display row is actually visible.
        self._gutter_font = tkfont.Font(font=("TkFixedFont", 11))
        self.gutter = tk.Canvas(
            text_frame, width=88, highlightthickness=0, bd=0,
            takefocus=False, cursor="arrow", background="#ececec"
        )
        self.gutter.pack(side="left", fill="y")

        self.text = tk.Text(
            text_frame, wrap="char", undo=False, state="disabled",
            font=("TkFixedFont", 11), padx=7, pady=7,
            selectbackground="#7aa7ff", selectforeground="black"
        )
        self.text.pack(side="left", fill="both", expand=True)

        self.vscroll = ttk.Scrollbar(text_frame, orient="vertical", command=self._on_vscroll)
        self.vscroll.pack(side="right", fill="y")
        self.text.configure(yscrollcommand=self._on_text_yview)
        self.vscroll.bind("<ButtonPress-1>", self._vscroll_press, add="+")
        self.vscroll.bind("<ButtonRelease-1>", self._vscroll_release, add="+")

        self.side_nb = ttk.Notebook(side)
        self.side_nb.pack(fill="both", expand=True)

        ann_frame = ttk.Frame(self.side_nb)
        bm_frame = ttk.Frame(self.side_nb)
        self.side_nb.add(ann_frame, text="标注")
        self.side_nb.add(bm_frame, text="书签")

        ann_bar = ttk.Frame(ann_frame)
        ann_bar.pack(fill="x", pady=(2, 4))
        ttk.Label(ann_bar, text="双击标注可跳转", foreground="#777777").pack(side="left", padx=(2, 6))
        ttk.Button(ann_bar, text="删除", command=self.delete_selected_annotation, style="Compact.TButton").pack(side="right")

        self.ann_tree = ttk.Treeview(
            ann_frame, columns=("color", "excerpt", "note"), show="headings", selectmode="browse"
        )
        self.ann_tree.heading("color", text="颜色")
        self.ann_tree.heading("excerpt", text="内容")
        self.ann_tree.heading("note", text="备注")
        self.ann_tree.column("color", width=48, stretch=False)
        self.ann_tree.column("excerpt", width=145, stretch=True)
        self.ann_tree.column("note", width=120, stretch=True)
        self.ann_tree.pack(fill="both", expand=True)
        self.ann_tree.bind("<Double-1>", self._jump_annotation)

        bm_bar = ttk.Frame(bm_frame)
        bm_bar.pack(fill="x", pady=(2, 4))
        ttk.Button(bm_bar, text="删除", command=self.delete_selected_bookmark).pack(side="right")

        self.bm_tree = ttk.Treeview(
            bm_frame, columns=("label", "excerpt"), show="headings", selectmode="browse"
        )
        self.bm_tree.heading("label", text="名称")
        self.bm_tree.heading("excerpt", text="位置内容")
        self.bm_tree.column("label", width=120, stretch=True)
        self.bm_tree.column("excerpt", width=180, stretch=True)
        self.bm_tree.pack(fill="both", expand=True)
        self.bm_tree.bind("<Double-1>", self._jump_bookmark)

        self.status = ttk.Label(self, text="", relief="sunken", anchor="w", padding=(6, 3))
        self.status.pack(fill="x", side="bottom")

        for key, color in MARK_COLORS.items():
            self.text.tag_configure(f"ann_{key}", background=color)

        self.text.tag_configure("severity_error", background="#ffe0e0", foreground="#8b0000")
        self.text.tag_configure("severity_warn", background="#fff3c4", foreground="#6b4c00")
        self.text.tag_configure("search_all", background="#fff2a8", foreground="black")
        self.text.tag_configure("search_hit", background="#ffb347", foreground="black")
        self.click_caret = tk.Frame(self.text, width=2, background="#202020", takefocus=False)
        self.click_caret.place_forget()

        self._reload_annotation_tree()
        self._reload_bookmark_tree()

        self.text.bind("<MouseWheel>", self._mousewheel)
        self.text.bind("<Button-4>", lambda e: self._native_scroll_units(-1))
        self.text.bind("<Button-5>", lambda e: self._native_scroll_units(1))
        # Scrolling over the line-number gutter should behave exactly like
        # scrolling over the log body.
        self.gutter.bind("<MouseWheel>", self._mousewheel)
        self.gutter.bind("<Button-4>", lambda e: self._native_scroll_units(-1))
        self.gutter.bind("<Button-5>", lambda e: self._native_scroll_units(1))
        self.text.bind("<Prior>", lambda e: self.quick_flip_pages(-1, 1))
        self.text.bind("<Next>", lambda e: self.quick_flip_pages(1, 1))
        self.text.bind("<Control-End>", lambda e: self.jump_tail())
        self.text.bind("<Control-Home>", lambda e: self.render_at(0, line_hint=1, exact_hint=True))
        self.text.bind("<Button-3>", self._show_context_menu)
        self.text.bind("<Button-1>", self._on_text_click, add="+")
        self.text.bind("<Double-Button-1>", self._select_word_at_click)
        self.text.bind("<Control-f>", self._ctrl_f_search)
        self.text.bind("<Configure>", self._on_text_configure, add="+")
        self.gutter.bind("<Configure>", lambda _e: self._schedule_gutter_render(), add="+")

        self.context_menu = tk.Menu(self.text, tearoff=0)
        color_menu = tk.Menu(self.context_menu, tearoff=0)
        for key, label in MARK_LABELS.items():
            color_menu.add_command(label=label, command=lambda k=key: self.add_annotation(k))
        self.context_menu.add_cascade(label="标注选中文本", menu=color_menu)
        self.context_menu.add_command(label="使用当前颜色标注", command=lambda: self.add_annotation())
        self.context_menu.add_separator()
        self.context_menu.add_command(label="在此添加书签", command=self.add_bookmark_at_context)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="复制", command=self.copy_selection)

        # Native file drag/drop targets (when tkinterdnd2/tkDnD is available).
        for widget in (self, self.text, self.gutter, self.side_nb, self.ann_tree, self.bm_tree):
            self.app.register_drop_target(widget)

    def close(self):
        self.closed = True
        self.search_generation += 1
        try:
            self.index.stop()
        except Exception:
            pass
        try:
            self.backend.close()
        except Exception:
            pass

    def _show_context_menu(self, event):
        self.context_index = self.text.index(f"@{event.x},{event.y}")
        try:
            self.text.mark_set("insert", self.context_index)
        except tk.TclError:
            pass

        has_sel = len(self.text.tag_ranges("sel")) == 2
        state = "normal" if has_sel else "disabled"
        self.context_menu.entryconfigure("标注选中文本", state=state)
        self.context_menu.entryconfigure("使用当前颜色标注", state=state)
        self.context_menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def copy_selection(self):
        ranges = self.text.tag_ranges("sel")
        if len(ranges) == 2:
            value = self.text.get(ranges[0], ranges[1])
            self.clipboard_clear()
            self.clipboard_append(value)

    def _ctrl_f_search(self, _event=None):
        # Capture the Text selection while this widget still owns the focus.
        # Returning "break" prevents class/toplevel bindings from processing Ctrl+F again.
        self.app.focus_search(source_view=self)
        return "break"

    def _on_text_click(self, event):
        """Remember the exact logical/byte position of the latest left click."""
        try:
            idx = self.text.index(f"@{event.x},{event.y}")
            line_s, col_s = idx.split(".")
            logical_line = max(1, int(line_s))
            col = max(0, int(col_s))
            byte_pos = self._text_index_to_byte(idx)

            self.click_text_index = idx
            self.click_byte = max(0, min(int(byte_pos), self.backend.size))
            self.click_line = self.page_start_line + logical_line - 1
            self.click_line_exact = self.page_line_exact
            self.click_col = col + 1
            self.search_anchor_pending = True

            # A deliberate click establishes a new search origin. Keep the old
            # query text, but do not let an older match override this anchor.
            self.current_match = None
            try:
                self.text.tag_remove("search_hit", "1.0", "end")
                self.text.mark_set("insert", idx)
                self.text.focus_set()
                self._position_click_caret(idx)
            except tk.TclError:
                pass
            self._update_status()
        except Exception:
            pass
        # Do not return "break": normal click/drag selection must keep working.

    def _position_click_caret(self, idx=None):
        if self.click_byte is None or not hasattr(self, "click_caret"):
            return
        if idx is None:
            idx = self._byte_to_text_index(self.click_byte)
        if not idx:
            try:
                self.click_caret.place_forget()
            except tk.TclError:
                pass
            return
        try:
            box = self.text.bbox(idx)
            if not box:
                self.click_caret.place_forget()
                return
            x, y, _w, h = box

            # Text.bbox() returns coordinates in the Text widget's outer
            # coordinate system, while a child managed by place() is positioned
            # relative to the widget's inner content area.  With border/highlight
            # thickness and padx/pady this otherwise shifts the custom caret down
            # and to the right (especially visible on HiDPI/Windows themes).
            def opt_pixels(name):
                value = self.text.cget(name)
                try:
                    return int(self.text.winfo_pixels(value))
                except (tk.TclError, TypeError, ValueError):
                    try:
                        return int(float(value))
                    except (TypeError, ValueError):
                        return 0

            inset_x = (
                opt_pixels("borderwidth")
                + opt_pixels("highlightthickness")
                + opt_pixels("padx")
            )
            inset_y = (
                opt_pixels("borderwidth")
                + opt_pixels("highlightthickness")
                + opt_pixels("pady")
            )
            self.click_caret.place(
                x=x - inset_x, y=y - inset_y, width=2, height=max(2, h)
            )
            self.click_caret.lift()
        except tk.TclError:
            pass

    def _refresh_click_caret(self):
        if self.closed:
            return
        self._position_click_caret()

    def _on_text_configure(self, _event=None):
        if self.closed:
            return
        self.after_idle(self._refresh_click_caret)
        self._schedule_gutter_render()

    def _schedule_gutter_render(self):
        if self.closed or self._gutter_after is not None:
            return
        self._gutter_after = self.after_idle(self._run_gutter_render)

    def _run_gutter_render(self):
        self._gutter_after = None
        if not self.closed:
            self._render_gutter()

    def _raise_selection_tag(self):
        # Search/annotation backgrounds must never visually cover the native
        # selection.  Keeping ``sel`` at the highest priority also makes
        # double-click selection obvious on yellow search matches.
        try:
            self.text.tag_raise("sel")
        except tk.TclError:
            pass

    def _tag_add_ranges(self, tag, flat_ranges, pairs_per_call=1024):
        """Add many Text tag ranges with bounded Tcl calls instead of one call per hit."""
        if not flat_ranges:
            return
        step = max(2, int(pairs_per_call) * 2)
        try:
            for pos in range(0, len(flat_ranges), step):
                chunk = flat_ranges[pos:pos + step]
                if len(chunk) >= 2:
                    self.text.tag_add(tag, chunk[0], *chunk[1:])
        except tk.TclError:
            pass

    @staticmethod
    def _is_word_char(ch):
        return bool(ch) and (ch == "_" or ch.isalnum())

    def _select_word_at_click(self, event):
        """Double-click selects a Unicode word/token without scanning the whole line."""
        try:
            idx = self.text.index(f"@{event.x},{event.y}")
            line_s, col_s = idx.split(".")
            line_no = int(line_s)
            col = int(col_s)
            line_text = self.text.get(f"{line_no}.0", f"{line_no}.end")
            if not line_text:
                return "break"

            probe = min(max(0, col), len(line_text) - 1)
            if not self._is_word_char(line_text[probe]) and probe > 0:
                if self._is_word_char(line_text[probe - 1]):
                    probe -= 1
            if not self._is_word_char(line_text[probe]):
                return "break"

            # Expand only through the token under the pointer.  The previous
            # re.finditer() scanned an entire logical line, which was noticeable
            # on multi-megabyte JSON/log lines.
            left = probe
            while left > 0 and self._is_word_char(line_text[left - 1]):
                left -= 1
            right = probe + 1
            n = len(line_text)
            while right < n and self._is_word_char(line_text[right]):
                right += 1

            start = f"{line_no}.{left}"
            end = f"{line_no}.{right}"
            self.text.tag_remove("sel", "1.0", "end")
            self.text.tag_add("sel", start, end)
            self._raise_selection_tag()
            self.text.mark_set("insert", end)
            self.text.see(start)
            try:
                self.click_caret.place_forget()
            except tk.TclError:
                pass
            return "break"
        except (tk.TclError, ValueError, IndexError):
            return "break"

    def render_at(self, start: int, line_hint=None, exact_hint=False, view_byte=None):
        if self.closed or not self.backend:
            return
        try:
            lines, page_start, page_end, truncated = self.backend.read_page(start)
        except Exception as e:
            self.status.config(text=f"读取失败：{e}")
            return

        self.page_lines = lines
        self.page_byte_starts = [int(pl.byte_start) for pl in lines]
        self.page_start = page_start
        self.page_end = page_end

        if line_hint is not None:
            self.page_start_line = max(1, int(line_hint))
            self.page_line_exact = bool(exact_hint)
        else:
            exact_line = self.index.line_number_at(page_start, getattr(self.backend, "mm", None))
            if exact_line is not None:
                self.page_start_line = exact_line
                self.page_line_exact = True
            else:
                self.page_start_line = self.index.approximate_line_number(page_start)
                self.page_line_exact = False

        try:
            self.index.observe(page_start, lines, page_end, self.page_start_line, self.page_line_exact)
        except AttributeError:
            pass

        self._rendering = True
        try:
            self.text.configure(state="normal")
            self.text.delete("1.0", "end")
            body = "\n".join(line.text for line in lines)
            if lines and page_end < self.backend.size:
                body += "\n"
            self.text.insert("1.0", body)

            for key in MARK_COLORS:
                self.text.tag_remove(f"ann_{key}", "1.0", "end")
            self.text.tag_remove("severity_error", "1.0", "end")
            self.text.tag_remove("severity_warn", "1.0", "end")
            self.text.tag_remove("search_all", "1.0", "end")
            self.text.tag_remove("search_hit", "1.0", "end")
            self.visible_search_signature = None

            self._apply_severity_tags()
            self._apply_annotation_tags()
            self._apply_search_tag()

            for key in MARK_COLORS:
                self.text.tag_raise(f"ann_{key}")
            self.text.tag_raise("search_all")
            self.text.tag_raise("search_hit")
            self._raise_selection_tag()
            self.text.configure(state="disabled")

            if view_byte is not None:
                idx = self._byte_to_text_index(max(self.page_start, min(int(view_byte), self.page_end)))
                if idx:
                    try:
                        self.text.yview(idx)
                    except tk.TclError:
                        pass
        finally:
            self._rendering = False

        self._sync_virtual_scrollbar()
        self._update_status(truncated)
        # dlineinfo() is valid only after the widget has been laid out/mapped;
        # defer the lightweight gutter paint to idle instead of blocking first paint.
        self._schedule_gutter_render()
        self.after_idle(self._refresh_click_caret)
        if getattr(self.backend, "is_remote", False) and hasattr(self.backend, "prefetch_around"):
            # Warm a wider range in the background after first paint. Nearby
            # wheel/page movement then behaves like the local mmap path and
            # does not wait for a new SFTP round trip on every cache edge.
            try:
                anchor = view_byte if view_byte is not None else page_start
                self.backend.prefetch_around(anchor)
            except Exception:
                pass

    def _render_around(self, target_byte: int, line_hint=None, exact_hint=False):
        """Load an overscanned buffer around the requested visible top byte."""
        if not self.backend:
            return
        target = self.backend.align_line_start(max(0, min(int(target_byte), self.backend.size)))
        overscan = max(48, min(160, self._visible_line_capacity() * 3))
        try:
            buffer_start, moved_back = self.backend.move_lines_count(target, -overscan)
        except Exception:
            buffer_start, moved_back = target, 0
        buffer_hint = None
        if line_hint is not None:
            buffer_hint = max(1, int(line_hint) + int(moved_back))
        self.render_at(buffer_start, buffer_hint, exact_hint, view_byte=target)

    def _render_gutter(self):
        """Paint only visible logical line numbers, aligned to wrapped display rows."""
        if self.closed or not hasattr(self, "gutter"):
            return
        try:
            self.gutter.delete("all")
            if not self.page_lines or not self.text.winfo_ismapped():
                self.gutter_was_approx = not self.page_line_exact
                return

            first_idx = self.text.index("@0,0")
            first_line = max(1, int(first_idx.split(".")[0]))
            height = max(1, int(self.gutter.winfo_height()))
            line_px = max(1, int(self._gutter_font.metrics("linespace")))
            # Avoid _visible_line_capacity() here because it calls
            # update_idletasks(); doing that from an idle gutter paint can
            # re-enter pending gutter callbacks and duplicate Canvas items.
            visible_cap = max(8, min(PAGE_LINES, height // line_px + 2))
            stop_line = min(len(self.page_lines), first_line + visible_cap * 2 + 8)
            width = max(1, int(self.gutter.winfo_width()))
            prefix = "" if self.page_line_exact else "~"

            # Keep the old ~10-character gutter width but grow slightly if a very
            # large line number needs it.  Width changes are rare and capped.
            max_number = self.page_start_line + max(0, stop_line - 1)
            wanted = max(72, min(132, self._gutter_font.measure(prefix + f"{max_number:,}") + 12))
            current_width = int(float(self.gutter.cget("width")))
            if abs(current_width - wanted) >= 6:
                self.gutter.configure(width=wanted)
                width = wanted

            seen_visible = False
            for logical in range(first_line, stop_line + 1):
                info = self.text.dlineinfo(f"{logical}.0")
                if not info:
                    if seen_visible:
                        break
                    continue
                seen_visible = True
                _x, y, _w, row_h, _baseline = info
                if y > height:
                    break
                if y + row_h < 0:
                    continue
                number = self.page_start_line + logical - 1
                self.gutter.create_text(
                    width - 6, y, anchor="ne", text=f"{prefix}{number}",
                    font=self._gutter_font, fill="#666666"
                )
            self.gutter_was_approx = not self.page_line_exact
        except (tk.TclError, TypeError, ValueError):
            pass

    def _visible_top_index(self):
        try:
            return self.text.index("@1,1")
        except tk.TclError:
            return "1.0"

    def _visible_top_byte(self):
        try:
            return self._text_index_to_byte(self._visible_top_index())
        except Exception:
            return self.page_start

    def _visible_top_line(self):
        try:
            logical = max(1, int(self._visible_top_index().split(".")[0]))
            return max(1, self.page_start_line + logical - 1), self.page_line_exact
        except Exception:
            return self.page_start_line, self.page_line_exact

    def _visible_bottom_byte(self):
        try:
            h = max(1, self.text.winfo_height() - 2)
            idx = self.text.index(f"@1,{h}")
            return self._text_index_to_byte(idx)
        except Exception:
            return self.page_end

    def _sync_virtual_scrollbar(self):
        if not self.backend:
            return
        size = max(1, int(self.backend.size))
        top = max(0, min(self._visible_top_byte(), size))
        bottom = max(top, min(self._visible_bottom_byte(), size))
        first = min(1.0, top / size)
        last = min(1.0, max(bottom / size, first + 0.004))
        if last >= 1.0 and first < 1.0:
            first = min(first, 0.996)
        try:
            self.vscroll.set(first, last)
        except tk.TclError:
            pass

    def _schedule_scroll_sync(self):
        if self._scroll_sync_after is not None or self.closed:
            return
        self._scroll_sync_after = self.after(16, self._finish_scroll_sync)

    def _finish_scroll_sync(self):
        self._scroll_sync_after = None
        if self.closed:
            return
        self._render_gutter()
        self._sync_virtual_scrollbar()
        if (
            getattr(self.backend, "is_remote", False) and self.remote_new_bytes > 0 and
            int(self.page_end) >= int(self.backend.size)
        ):
            try:
                if float(self.text.yview()[1]) >= 0.995:
                    self.remote_new_bytes = 0
            except (tk.TclError, IndexError, TypeError, ValueError):
                pass
        self._update_status()
        self._refresh_click_caret()

    def _on_text_yview(self, _first, _last):
        if self._rendering:
            return
        self._schedule_scroll_sync()

    def _update_status(self, truncated=False):
        idx_bytes, idx_complete, _, idx_error = self.index.snapshot()
        top_byte = self._visible_top_byte()
        pct = 100.0 if self.backend.size == 0 else top_byte / self.backend.size * 100.0
        top_line, top_exact = self._visible_top_line()
        line_text = f"行 {top_line:,}" if top_exact else f"约行 {top_line:,}"
        if getattr(self.backend, "is_remote", False):
            idx_text = "SSH/SFTP 按需读取"
        else:
            idx_pct = self.index.progress() * 100.0
            idx_text = "行索引完成" if idx_complete else f"行索引 {idx_pct:.1f}%"
            if idx_error:
                idx_text = f"行索引错误: {idx_error}"
        extra = " | 超长单行截断显示" if truncated else ""
        if self.searching:
            extra += " | 正在搜索…"
        if getattr(self.backend, "is_remote", False):
            if self.remote_new_bytes > 0:
                extra += f" | 有新内容 +{human_size(self.remote_new_bytes)}"
            if self._remote_live_error:
                extra += " | 实时更新暂时重试中"
        click_text = ""
        if self.click_byte is not None and self.click_line is not None:
            click_prefix = "" if getattr(self, "click_line_exact", False) else "约"
            click_text = (
                f" | 点位 {click_prefix}行 {self.click_line:,} / 列 {self.click_col:,}"
                f" / 字节 {self.click_byte:,}"
            )
        remote_text = " | 远程" if getattr(self.backend, "is_remote", False) else ""
        self.status.config(
            text=f"{human_size(self.backend.size)} | {self.backend.encoding}{remote_text} | {line_text} | "
                 f"字节 {top_byte:,}/{self.backend.size:,} ({pct:.2f}%) | "
                 f"{idx_text} | 标注 {len(self.annotations)} | 书签 {len(self.bookmarks)}{click_text}{extra}"
        )

    def _apply_severity_tags(self):
        error_ranges = []
        warn_ranges = []
        for i, pl in enumerate(self.page_lines, start=1):
            s = pl.text
            if SEVERITY_ERROR_RE.search(s):
                error_ranges.extend((f"{i}.0", f"{i}.end"))
            elif SEVERITY_WARN_RE.search(s):
                warn_ranges.extend((f"{i}.0", f"{i}.end"))
        self._tag_add_ranges("severity_error", error_ranges)
        self._tag_add_ranges("severity_warn", warn_ranges)

    def _vscroll_press(self, _event=None):
        self._scroll_dragging = True

    def _vscroll_release(self, _event=None):
        self._scroll_dragging = False
        if self._scroll_drag_after is not None:
            try:
                self.after_cancel(self._scroll_drag_after)
            except Exception:
                pass
            self._scroll_drag_after = None
        if self._pending_scroll_fraction is not None:
            self._perform_scroll_drag()

    def _on_vscroll(self, *args):
        if not self.backend or not args:
            return
        if args[0] == "moveto":
            frac = max(0.0, min(1.0, float(args[1])))
            self.follow_tail = False
            self.app.sync_toolbar_from_active()
            self._pending_scroll_fraction = frac
            # Let the thumb follow the mouse immediately. Content refreshes are coalesced.
            try:
                first, last = self.vscroll.get()
                span = max(0.004, float(last) - float(first))
                self.vscroll.set(frac, min(1.0, frac + span))
            except Exception:
                pass
            if getattr(self.backend, "is_remote", False) and self._scroll_dragging:
                # Network I/O while the thumb is held would make dragging stutter.
                # Keep the thumb fully local; fetch exactly once on release.
                self.status.config(text=f"远程定位预览：{frac * 100:.2f}%（松开后读取）")
            elif self._scroll_drag_after is None:
                delay = 70 if getattr(self.backend, "is_remote", False) else 18
                self._scroll_drag_after = self.after(delay, self._perform_scroll_drag)
        elif args[0] == "scroll":
            amount = int(args[1])
            unit = args[2]
            if unit == "pages":
                self.quick_flip_pages(-1 if amount < 0 else 1, abs(amount))
            else:
                self._native_scroll_units(amount)

    def _perform_scroll_drag(self):
        self._scroll_drag_after = None
        if self.closed or self._pending_scroll_fraction is None:
            return
        frac = self._pending_scroll_fraction
        self._pending_scroll_fraction = None
        target = int(self.backend.size * frac)
        self._render_around(target)
        # If more drag events arrived while rendering, only process the newest one.
        if self._pending_scroll_fraction is not None and self._scroll_drag_after is None:
            delay = 70 if getattr(self.backend, "is_remote", False) else 18
            self._scroll_drag_after = self.after(delay, self._perform_scroll_drag)

    def _mousewheel(self, event):
        if event.delta == 0:
            return "break"
        if abs(event.delta) >= 120:
            steps = -int(event.delta / 120)
        else:
            steps = -1 if event.delta > 0 else 1
        return self._native_scroll_units(steps)

    def _native_scroll_units(self, delta: int):
        """Use Tk's native display-line scroll inside the loaded buffer for smooth motion."""
        if not self.backend or not delta:
            return "break"
        self.follow_tail = False
        self.app.sync_toolbar_from_active()
        before = self.text.yview()
        try:
            self.text.yview_scroll(int(delta), "units")
        except tk.TclError:
            return "break"
        after = self.text.yview()
        if after != before:
            self._schedule_scroll_sync()
            return "break"

        # We reached the edge of the cached page. Refill with overscan around
        # the next logical line, then continue using native scrolling.
        top_byte = self._visible_top_byte()
        top_line, exact = self._visible_top_line()
        new_top, moved = self.backend.move_lines_count(top_byte, int(delta))
        if new_top != top_byte:
            self._render_around(new_top, max(1, top_line + moved), exact)
        return "break"

    def _wheel_lines(self, delta: int):
        """Logical-file movement used by quick page navigation, anchored at visible top."""
        if not self.backend:
            return "break"
        current = self._visible_top_byte()
        current_line, exact = self._visible_top_line()
        new_start, moved = self.backend.move_lines_count(current, int(delta))
        if new_start != current:
            self.follow_tail = False
            self.app.sync_toolbar_from_active()
            self._render_around(new_start, max(1, current_line + moved), exact)
        return "break"

    def _screen_logical_capacity(self):
        """How many logical file lines currently fit in roughly one visible screen."""
        try:
            self.update_idletasks()
            height = max(2, int(self.text.winfo_height()) - 2)
            top = self.text.index("@0,0")
            bottom = self.text.index(f"@0,{height}")
            top_line = int(top.split(".")[0])
            bottom_line = int(bottom.split(".")[0])
            return max(1, bottom_line - top_line + 1)
        except Exception:
            return max(1, self._visible_line_capacity())

    def quick_flip_pages(self, direction: int, pages: int):
        """Move backward/forward by N visible screens without building a full index."""
        if not self.backend:
            return "break"
        try:
            pages = max(1, min(10000, int(pages)))
        except (TypeError, ValueError):
            pages = 10
        direction = -1 if int(direction) < 0 else 1
        per_page = max(1, self._screen_logical_capacity() - 1)
        delta = direction * pages * per_page
        return self._wheel_lines(delta)

    def _text_index_to_byte(self, idx: str):
        if not self.backend or not self.page_lines:
            return 0
        line_s, col_s = str(self.text.index(idx)).split(".")
        line_no = max(1, int(line_s))
        col = max(0, int(col_s))
        if line_no > len(self.page_lines):
            return self.page_end
        pl = self.page_lines[line_no - 1]
        prefix = pl.text[:col]
        b = prefix.encode(self.backend.encoding, errors="replace")
        return min(pl.byte_end, pl.byte_start + len(b))

    def _byte_to_text_index(self, byte_pos: int):
        if not self.backend or not self.page_lines:
            return None
        byte_pos = int(byte_pos)
        starts = self.page_byte_starts or [int(pl.byte_start) for pl in self.page_lines]
        idx = bisect.bisect_right(starts, byte_pos) - 1
        if idx < 0:
            return "1.0"
        idx = min(idx, len(self.page_lines) - 1)
        pl = self.page_lines[idx]
        line_no = idx + 1
        if byte_pos <= pl.byte_end:
            raw = self.backend.read_bytes(pl.byte_start, byte_pos)
            col = len(raw.decode(self.backend.encoding, errors="replace"))
            return f"{line_no}.{col}"
        if idx + 1 < len(self.page_lines) and byte_pos < self.page_lines[idx + 1].byte_start:
            return f"{line_no}.end"
        if byte_pos >= self.page_lines[-1].byte_end:
            return f"{len(self.page_lines)}.end"
        return None

    def _reveal_text_index(self, idx, center=False):
        """Reveal an exact Tk text index; optionally center its wrapped display row.

        Byte jumps are stored against logical file lines, but one logical log line can
        wrap into many screen rows.  Centering by a fixed number of logical lines
        therefore drifts badly on long JSON/log messages.  This routine measures the
        actual display row containing *idx* and recenters using the Text widget's
        current yview fractions, so wrapping and window size are both accounted for.
        """
        if not idx:
            return
        try:
            self.text.see(idx)
            if center:
                self.text.update_idletasks()
                for _ in range(3):
                    info = self.text.dlineinfo(idx)
                    if not info:
                        self.text.see(idx)
                        self.text.update_idletasks()
                        info = self.text.dlineinfo(idx)
                    if not info:
                        break
                    first, last = self.text.yview()
                    span = max(0.0, float(last) - float(first))
                    height = max(1.0, float(self.text.winfo_height()))
                    row_mid = float(info[1]) + float(info[3]) / 2.0
                    error = row_mid / height - 0.5
                    if span <= 0.0 or abs(error) <= 0.025:
                        break
                    max_first = max(0.0, 1.0 - span)
                    wanted = max(0.0, min(max_first, float(first) + error * span))
                    if abs(wanted - float(first)) < 1e-7:
                        break
                    self.text.yview_moveto(wanted)
                    self.text.update_idletasks()
            self._render_gutter()
            self._schedule_scroll_sync()
        except (tk.TclError, TypeError, ValueError):
            pass

    def add_annotation(self, color=None):
        ranges = self.text.tag_ranges("sel")
        if len(ranges) != 2:
            # Annotation is intentionally non-modal: keep the document exactly
            # where it is and report the missing selection in the status bar.
            self._update_status()
            try:
                self.status.config(text=f"{self.status.cget('text')} | 请先选中要标注的文本")
            except tk.TclError:
                pass
            return

        i1, i2 = str(ranges[0]), str(ranges[1])
        start = self._text_index_to_byte(i1)
        end = self._text_index_to_byte(i2)
        if end <= start:
            return
        if color is None:
            color = LABEL_TO_MARK.get(self.app.mark_color_var.get(), "yellow")
        excerpt = self.text.get(i1, i2).replace("\n", " ↵ ").strip()
        if len(excerpt) > 220:
            excerpt = excerpt[:217] + "..."

        # Notes default to empty so marking is a single action with no dialog.
        # Do not re-render the page here: re-rendering changes yview/xview and
        # makes the document appear to jump after every annotation.
        self.app.store.add_annotation(self.path, start, end, "", color, excerpt)
        self.annotations = self.app.store.list_annotations(self.path)
        self._reload_annotation_tree()

        tag = f"ann_{color}" if color in MARK_COLORS else "ann_yellow"
        try:
            self.text.tag_add(tag, i1, i2)
            self._raise_selection_tag()
        except tk.TclError:
            pass
        self._update_status()

    def _apply_annotation_tags(self):
        grouped = {f"ann_{key}": [] for key in MARK_COLORS}
        for ann in self.annotations:
            a, b = ann["start_byte"], ann["end_byte"]
            if b < self.page_start or a > self.page_end:
                continue
            i1 = self._byte_to_text_index(max(a, self.page_start))
            i2 = self._byte_to_text_index(min(b, self.page_end))
            if i1 and i2:
                tag = f"ann_{ann['color']}" if ann["color"] in MARK_COLORS else "ann_yellow"
                grouped.setdefault(tag, []).extend((i1, i2))
        for tag, ranges in grouped.items():
            self._tag_add_ranges(tag, ranges)

    def _reload_annotation_tree(self):
        for item in self.ann_tree.get_children():
            self.ann_tree.delete(item)
        for ann in self.annotations:
            self.ann_tree.insert(
                "", "end", iid=str(ann["id"]),
                values=(MARK_LABELS.get(ann["color"], ann["color"]),
                        ann["excerpt"].replace("\n", " "),
                        ann["note"].replace("\n", " "))
            )

    def delete_selected_annotation(self):
        sel = self.ann_tree.selection()
        if not sel:
            return
        if not messagebox.askyesno("删除标注", "确定删除选中的标注？", parent=self):
            return
        self.app.store.delete_annotation(int(sel[0]))
        self.annotations = self.app.store.list_annotations(self.path)
        self._reload_annotation_tree()
        self.render_at(self.page_start, self.page_start_line, self.page_line_exact)

    def _select_annotation_after_jump(self, ann):
        """Select the annotation range after its destination page has been rendered."""
        if self.closed or not ann:
            return
        i1 = self._byte_to_text_index(max(int(ann["start_byte"]), self.page_start))
        i2 = self._byte_to_text_index(min(int(ann["end_byte"]), self.page_end))
        if not i1 or not i2:
            return
        try:
            self.text.tag_remove("sel", "1.0", "end")
            self.text.tag_add("sel", i1, i2)
            self._raise_selection_tag()
            self.text.mark_set("insert", i2)
            self.text.focus_set()
            # Use the exact wrapped display row, not a fixed logical-line offset.
            self._reveal_text_index(i1, center=True)
            self._position_click_caret(i1)
        except tk.TclError:
            pass

    def _jump_annotation(self, event=None):
        # On a double click, resolve the row directly from the pointer instead of
        # relying on a possibly stale Treeview selection from the first click.
        item = ""
        if event is not None:
            try:
                item = self.ann_tree.identify_row(event.y) or ""
                if item:
                    self.ann_tree.selection_set(item)
                    self.ann_tree.focus(item)
            except tk.TclError:
                item = ""
        if not item:
            sel = self.ann_tree.selection()
            if not sel:
                return
            item = sel[0]
        try:
            ann_id = int(item)
        except (TypeError, ValueError):
            return
        ann = next((x for x in self.annotations if x["id"] == ann_id), None)
        if ann:
            self.jump_to_byte(ann["start_byte"], center=True)
            self.after_idle(lambda a=ann: self._select_annotation_after_jump(a))

    def add_bookmark_at_context(self):
        byte_pos = self._text_index_to_byte(self.context_index)
        self.add_bookmark(byte_pos)

    def add_bookmark_current(self):
        try:
            idx = self.text.index("insert")
        except tk.TclError:
            idx = "1.0"
        self.add_bookmark(self._text_index_to_byte(idx))

    def add_bookmark(self, byte_pos: int):
        idx = self._byte_to_text_index(byte_pos) or "1.0"
        line_num = int(str(idx).split(".")[0])
        excerpt = ""
        if 1 <= line_num <= len(self.page_lines):
            excerpt = self.page_lines[line_num - 1].text.strip()
        if len(excerpt) > 220:
            excerpt = excerpt[:217] + "..."
        label = simpledialog.askstring("添加书签", "书签名称（可留空）：", parent=self)
        if label is None:
            return
        self.app.store.add_bookmark(self.path, byte_pos, label, excerpt)
        self.bookmarks = self.app.store.list_bookmarks(self.path)
        self._reload_bookmark_tree()
        self._update_status()

    def _reload_bookmark_tree(self):
        for item in self.bm_tree.get_children():
            self.bm_tree.delete(item)
        for bm in self.bookmarks:
            label = bm["label"] or f"@ byte {bm['byte_pos']:,}"
            self.bm_tree.insert("", "end", iid=str(bm["id"]), values=(label, bm["excerpt"]))

    def delete_selected_bookmark(self):
        sel = self.bm_tree.selection()
        if not sel:
            return
        if not messagebox.askyesno("删除书签", "确定删除选中的书签？", parent=self):
            return
        self.app.store.delete_bookmark(int(sel[0]))
        self.bookmarks = self.app.store.list_bookmarks(self.path)
        self._reload_bookmark_tree()
        self._update_status()

    def _jump_bookmark(self, _event=None):
        sel = self.bm_tree.selection()
        if not sel:
            return
        bm_id = int(sel[0])
        bm = next((x for x in self.bookmarks if x["id"] == bm_id), None)
        if bm:
            self.jump_to_byte(bm["byte_pos"], center=True)

    def jump_to_byte(self, byte_pos: int, center=False):
        target_byte = max(0, min(int(byte_pos), self.backend.size))
        start = self.backend.align_line_start(target_byte)
        if center:
            # Keep some content before the destination in the loaded buffer, but
            # do not assume those logical lines correspond to screen rows: long
            # log/JSON lines can wrap dozens of times.  Exact visual centering is
            # done from the target byte after rendering.
            start, _moved = self.backend.move_lines_count(start, -12)
        self.follow_tail = False
        self.app.sync_toolbar_from_active()
        self.render_at(start)
        idx = self._byte_to_text_index(target_byte)
        if idx:
            self._reveal_text_index(idx, center=center)

    def goto_byte_dialog(self):
        value = simpledialog.askstring(
            "跳转到字节", f"输入字节偏移（0 ~ {self.backend.size:,}）：",
            initialvalue=str(self.page_start), parent=self
        )
        if value is None:
            return
        try:
            byte_pos = int(value.replace(",", "").strip(), 0)
        except ValueError:
            messagebox.showerror("无效输入", "请输入十进制整数，或 0x 开头的十六进制数。", parent=self)
            return
        self.jump_to_byte(byte_pos)

    def goto_line_dialog(self):
        value = simpledialog.askstring(
            "跳转到行", "输入目标行号：",
            initialvalue=str(self.page_start_line), parent=self
        )
        if value is None:
            return
        try:
            line = int(value.replace(",", "").strip())
            if line < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("无效输入", "请输入大于等于 1 的整数行号。", parent=self)
            return
        self.goto_line(line)

    def goto_line(self, line: int):
        if getattr(self.backend, "is_remote", False):
            self._remote_jump_generation += 1
            gen = self._remote_jump_generation
            self.status.config(text=f"正在远程定位第 {line:,} 行…")
            def worker():
                try:
                    off = self.backend.offset_for_line(line)
                    err = None
                except Exception as e:
                    off, err = None, str(e)
                self._remote_jump_results.put((gen, line, off, err))
            threading.Thread(target=worker, daemon=True, name="TextMarkRemoteLineJump").start()
            self._schedule_remote_jump_poll()
            return

        if not self.backend.mm:
            return
        offset = self.index.offset_for_line(line, self.backend.mm)
        if offset is not None:
            self.pending_jump_line = None
            self._render_around(offset, line_hint=line, exact_hint=True)
            return
        _, complete, total_nl, _ = self.index.snapshot()
        if complete:
            messagebox.showinfo("跳转到行", f"文件只有约 {total_nl + 1:,} 行，目标行不存在。", parent=self)
            return
        self.pending_jump_line = line
        self.status.config(text=f"目标第 {line:,} 行尚未索引到；正在后台建立行索引，索引到后会自动跳转。")

    def _schedule_remote_jump_poll(self):
        if self.closed or self._remote_jump_poll_scheduled:
            return
        self._remote_jump_poll_scheduled = True
        self.after(50, self._poll_remote_jump)

    def _poll_remote_jump(self):
        self._remote_jump_poll_scheduled = False
        if self.closed:
            return
        got = False
        while True:
            try:
                gen, line, off, err = self._remote_jump_results.get_nowait()
            except queue.Empty:
                break
            got = True
            if gen != self._remote_jump_generation:
                continue
            if err:
                messagebox.showerror("跳转到行", f"远程定位失败：{err}", parent=self)
            elif off is None:
                messagebox.showinfo("跳转到行", f"目标第 {line:,} 行不存在。", parent=self)
            else:
                self._render_around(off, line_hint=line, exact_hint=True)
        if not got and not self.closed:
            self._schedule_remote_jump_poll()

    def _visible_line_capacity(self):
        """Approximate how many physical text rows fit in the current widget."""
        try:
            self.update_idletasks()
            font = tkfont.Font(font=self.text.cget("font"))
            line_px = max(1, int(font.metrics("linespace")))
            height_px = max(1, int(self.text.winfo_height()))
            # Leave a tiny margin so the actual last log line is never pushed below the viewport.
            return max(6, min(PAGE_LINES, max(1, height_px // line_px) - 1))
        except Exception:
            return 40

    def jump_tail(self):
        """
        Put the actual EOF at the visible bottom.

        Older builds loaded ~500 lines before EOF but left Tk's Text yview at the
        first of those lines, so users saw a position hundreds of lines before the tail.
        """
        if not self.backend or self.backend.size == 0:
            self.render_at(0, line_hint=1, exact_hint=True)
            return "break"

        visible = self._visible_line_capacity()
        last_line_start = self.backend.align_line_start(self.backend.size)

        # If the file ends in a newline, EOF is the empty position *after* the last
        # actual log line, so move back N lines. Otherwise last_line_start already
        # points at the final line, so only N-1 moves are required.
        back = visible if self.backend.ends_with_newline() else max(0, visible - 1)
        start, _ = self.backend.move_lines_count(last_line_start, -back)

        self.render_at(start)

        # Guarantee the final character/line is visible even if font metrics, DPI,
        # borders or theme padding make the capacity estimate off by a row.
        try:
            self.text.yview_moveto(1.0)
            self.text.see("end-1c")
            self._schedule_gutter_render()
        except tk.TclError:
            pass
        if getattr(self.backend, "is_remote", False):
            self.remote_new_bytes = 0
        return "break"

    def set_follow_tail(self, enabled: bool):
        self.follow_tail = bool(enabled)
        if enabled:
            self.remote_new_bytes = 0
            self.jump_tail()

    def _replace_index(self):
        """Replace the line index object without blocking the GUI on an old worker thread."""
        try:
            self.index.stop()
        except Exception:
            pass
        if getattr(self.backend, "is_remote", False):
            self.index = RemoteLineIndex(self.backend)
        else:
            self.index = LazyLineIndex(
                self.path, self.backend.size, self.backend.mtime_ns,
                self.backend.newline, self.backend.bom
            )

    def set_encoding_choice(self, choice: str):
        if choice not in ENCODING_CHOICES:
            return
        self.encoding_choice = choice
        encoding = self.backend.detected_encoding if choice == "自动" else ENCODING_MAP[choice]
        if encoding == self.backend.encoding and choice != "自动":
            return
        self.backend.set_encoding(encoding)
        self.current_match = None
        self.pending_jump_line = None
        self._replace_index()
        self.render_at(self.page_start)

    def _search_signature(self):
        return (self.search_text, bool(self.regex_mode), bool(self.case_sensitive), self.page_start, self.page_end)

    @staticmethod
    def _line_starts_for_text(text):
        starts = [0]
        pos = text.find("\n")
        while pos >= 0:
            starts.append(pos + 1)
            pos = text.find("\n", pos + 1)
        return starts

    def _char_offset_to_text_index(self, offset):
        starts = self.visible_search_line_starts or [0]
        offset = max(0, int(offset))
        line_idx = max(0, bisect.bisect_right(starts, offset) - 1)
        return f"{line_idx + 1}.{offset - starts[line_idx]}"

    def _text_index_to_char_offset(self, idx):
        try:
            line_s, col_s = str(self.text.index(idx)).split(".")
            line_no = max(1, int(line_s))
            col = max(0, int(col_s))
            starts = self.visible_search_line_starts or [0]
            if line_no > len(starts):
                return starts[-1]
            return starts[line_no - 1] + col
        except Exception:
            return 0

    def _refresh_visible_search_matches(self):
        signature = self._search_signature()
        if signature == self.visible_search_signature:
            return True

        self.visible_search_signature = signature
        self.visible_search_spans = []
        self.visible_search_line_starts = [0]
        try:
            self.text.tag_remove("search_all", "1.0", "end")
            self.text.tag_remove("search_hit", "1.0", "end")
        except tk.TclError:
            return False

        pattern = self.search_text
        if not pattern:
            return True
        try:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            rx = re.compile(pattern if self.regex_mode else re.escape(pattern), flags)
        except re.error:
            return False

        try:
            shown = self.text.get("1.0", "end-1c")
        except tk.TclError:
            return False
        self.visible_search_line_starts = self._line_starts_for_text(shown)

        spans = []
        tag_ranges = []
        for m in rx.finditer(shown):
            a, b = m.span()
            if b <= a:
                continue
            spans.append((a, b))
            tag_ranges.extend((self._char_offset_to_text_index(a), self._char_offset_to_text_index(b)))
        self._tag_add_ranges("search_all", tag_ranges)
        self.visible_search_spans = spans
        self._raise_selection_tag()
        return True

    def _visible_match_from_byte(self, start, backwards, include_containing=False):
        if not self.visible_search_spans or not (self.page_start <= start <= self.page_end):
            return None
        idx = self._byte_to_text_index(start)
        if not idx:
            return None
        anchor = self._text_index_to_char_offset(idx)
        spans = self.visible_search_spans
        chosen = None

        if include_containing:
            for a, b in spans:
                if a <= anchor < b:
                    chosen = (a, b)
                    break

        if chosen is None and backwards:
            for a, b in reversed(spans):
                if b <= anchor:
                    chosen = (a, b)
                    break
        elif chosen is None:
            for a, b in spans:
                if a >= anchor:
                    chosen = (a, b)
                    break

        if chosen is None:
            return None
        i1 = self._char_offset_to_text_index(chosen[0])
        i2 = self._char_offset_to_text_index(chosen[1])
        a = self._text_index_to_byte(i1)
        b = self._text_index_to_byte(i2)
        return (a, b) if b > a else None

    def _show_search_match(self, found, rerender_if_needed=True):
        self.current_match = found
        a, b = found
        visible = self.page_start <= a <= self.page_end and self.page_start <= b <= self.page_end
        if rerender_if_needed and not visible:
            line_start = self.backend.align_line_start(a)
            self._render_around(line_start)
        else:
            self._refresh_visible_search_matches()
            try:
                self.text.tag_remove("search_hit", "1.0", "end")
            except tk.TclError:
                pass
            i1 = self._byte_to_text_index(a)
            i2 = self._byte_to_text_index(b)
            if i1 and i2:
                try:
                    self.text.tag_add("search_hit", i1, i2)
                    self.text.tag_raise("search_hit")
                    self._raise_selection_tag()
                except tk.TclError:
                    pass

        i1 = self._byte_to_text_index(a)
        if i1:
            try:
                self.text.see(i1)
                self._render_gutter()
                self._schedule_scroll_sync()
            except tk.TclError:
                pass

    def find_next(self, backwards=False, pattern=None, regex_mode=None, case_sensitive=None):
        if pattern is None:
            pattern = self.app.search_var.get()
        if regex_mode is None:
            regex_mode = self.app.regex_var.get()
        if case_sensitive is None:
            case_sensitive = self.app.case_var.get()

        query_changed = (
            pattern != self.search_text or
            bool(regex_mode) != self.regex_mode or
            bool(case_sensitive) != self.case_sensitive
        )
        self.search_text = pattern
        self.regex_mode = bool(regex_mode)
        self.case_sensitive = bool(case_sensitive)
        if not pattern:
            self.visible_search_signature = None
            self._refresh_visible_search_matches()
            self.app.focus_search()
            return

        if query_changed:
            self.current_match = None
            self.visible_search_signature = None

        using_click_anchor = self.current_match is None and self.click_byte is not None
        if self.current_match and not self.search_anchor_pending:
            start = self.current_match[0] if backwards else self.current_match[1]
        elif self.click_byte is not None:
            start = self.click_byte
        else:
            start = self._visible_top_byte()

        # Mark every visible hit immediately. If the requested next/previous hit
        # is already on screen, select it locally and avoid an SSH round trip.
        valid_visible_pattern = self._refresh_visible_search_matches()
        if valid_visible_pattern:
            local_found = self._visible_match_from_byte(
                start, backwards, include_containing=using_click_anchor
            )
            if local_found is not None:
                self.search_generation += 1
                self.searching = False
                self.search_anchor_pending = False
                self.follow_tail = False
                self.app.sync_toolbar_from_active()
                self._show_search_match(local_found, rerender_if_needed=False)
                self._update_status()
                return

        self.search_generation += 1
        gen = self.search_generation
        self.searching = True
        self.search_anchor_pending = False
        self._update_status()

        path = self.path
        encoding = self.backend.encoding
        newline = self.backend.newline
        bom = self.backend.bom
        size = self.backend.size

        def worker():
            try:
                cancelled = lambda: self.closed or gen != self.search_generation
                if getattr(self.backend, "is_remote", False):
                    found = self.backend.search(
                        pattern, start, backwards, bool(regex_mode), bool(case_sensitive)
                    )
                    if found is None and not cancelled() and (
                        (backwards and start > bom) or (not backwards and start < size)
                    ):
                        wrap_start = size if backwards else bom
                        found = self.backend.search(
                            pattern, wrap_start, backwards, bool(regex_mode), bool(case_sensitive)
                        )
                else:
                    use_regex = bool(regex_mode) or not bool(case_sensitive)
                    if use_regex:
                        expr = pattern if regex_mode else re.escape(pattern)
                        found = regex_search_file(
                            path, encoding, newline, bom, expr, start, backwards,
                            case_sensitive, cancel_check=cancelled
                        )
                        if found is None and not cancelled() and (
                            (backwards and start > bom) or (not backwards and start < size)
                        ):
                            wrap_start = size if backwards else bom
                            found = regex_search_file(
                                path, encoding, newline, bom, expr, wrap_start, backwards,
                                case_sensitive, cancel_check=cancelled
                            )
                    else:
                        local = MappedTextFile(path)
                        local.set_encoding(encoding)
                        try:
                            found = local.search_literal(pattern, start, backwards)
                            if found is None and not cancelled() and (
                                (backwards and start > local.bom) or
                                (not backwards and start < local.size)
                            ):
                                wrap_start = local.size if backwards else local.bom
                                found = local.search_literal(pattern, wrap_start, backwards)
                        finally:
                            local.close()
                err = None
            except re.error as e:
                found, err = None, f"正则表达式错误：{e}"
            except Exception as e:
                found, err = None, f"搜索失败：{e}"
            self.search_results.put((gen, pattern, found, err))

        threading.Thread(target=worker, daemon=True, name="TextMarkSearch").start()
        self._schedule_search_poll(30)

    def _schedule_search_poll(self, delay=50):
        if self.closed or self.search_poll_scheduled:
            return
        self.search_poll_scheduled = True
        self.after(delay, self._poll_search_results)

    def _poll_search_results(self):
        self.search_poll_scheduled = False
        if self.closed:
            return
        while True:
            try:
                gen, pattern, found, err = self.search_results.get_nowait()
            except queue.Empty:
                break
            self._search_done(gen, pattern, found, err)
        if self.searching:
            self._schedule_search_poll(50)

    def _search_done(self, gen, pattern, found, err):
        if self.closed or gen != self.search_generation:
            return
        self.searching = False
        if err:
            self._update_status()
            messagebox.showerror("搜索", err, parent=self)
            return
        if not found:
            self.current_match = None
            try:
                self.text.tag_remove("search_hit", "1.0", "end")
            except tk.TclError:
                pass
            self._refresh_visible_search_matches()
            self._update_status()
            self.bell()
            messagebox.showinfo("搜索", f"未找到：{pattern}", parent=self)
            return
        self.follow_tail = False
        self.app.sync_toolbar_from_active()
        self._show_search_match(found, rerender_if_needed=True)
        self._update_status()

    def _apply_search_tag(self):
        self._refresh_visible_search_matches()
        if not self.current_match:
            return
        a, b = self.current_match
        if b < self.page_start or a > self.page_end:
            return
        i1 = self._byte_to_text_index(max(a, self.page_start))
        i2 = self._byte_to_text_index(min(b, self.page_end))
        if i1 and i2:
            try:
                self.text.tag_add("search_hit", i1, i2)
                self._raise_selection_tag()
            except tk.TclError:
                pass

    def _is_view_at_remote_tail(self):
        if not getattr(self.backend, "is_remote", False):
            return False
        if int(self.page_end) < int(self.backend.size):
            return False
        try:
            return float(self.text.yview()[1]) >= 0.995
        except (tk.TclError, IndexError, TypeError, ValueError):
            return False

    def _start_remote_live_poll(self):
        if (
            self.closed or self._remote_live_inflight or
            not getattr(self.backend, "is_remote", False) or
            not hasattr(self.backend, "poll_live_update")
        ):
            return
        now = time.monotonic()
        # The app's main periodic tick is 700 ms; this threshold produces one
        # non-blocking SFTP stat per tick while a remote tab is open.
        if now - self._remote_live_last_request < 0.55:
            return
        self._remote_live_last_request = now
        self._remote_live_inflight = True
        backend = self.backend
        expected_size = int(backend.size)
        expected_mtime = int(backend.mtime_ns)
        # Remote logs auto-follow while the user is physically at the tail even
        # when the lock-style "跟随尾部" checkbox is off. Scrolling upward pauses
        # visual movement but live metadata monitoring continues.
        include_append = bool(self.follow_tail or self._is_view_at_remote_tail())

        def worker():
            try:
                value = backend.poll_live_update(
                    expected_size, expected_mtime, include_append=include_append
                )
                err = None
            except Exception as exc:
                value, err = None, str(exc)
            self._remote_live_results.put((backend, expected_size, value, err))

        threading.Thread(
            target=worker, daemon=True, name="TextMarkRemoteLiveTail"
        ).start()

    def _poll_remote_live_results(self):
        if self.closed:
            return
        while True:
            try:
                backend, expected_size, update, err = self._remote_live_results.get_nowait()
            except queue.Empty:
                break
            self._remote_live_inflight = False
            if backend is not self.backend:
                continue
            if err:
                self._remote_live_error = err
                self._update_status()
                continue
            self._remote_live_error = ""
            if not update or int(self.backend.size) != int(expected_size):
                continue
            kind = update.get("kind")
            if kind in ("none", "stale"):
                continue
            if kind in ("reset", "rewrite"):
                # Rotation/truncation is not an append. It is rare, so use the
                # normal refresh path to reopen the remote handle safely.
                self.remote_new_bytes = 0
                self.refresh_if_needed(force=True)
                continue
            if kind not in ("append", "append_large"):
                continue

            delta = max(0, int(update.get("new_size", expected_size)) - int(expected_size))
            # Decide against the old EOF before accepting the new size. If the
            # user scrolled upward while the worker was reading, do not pull the
            # viewport back down under their pointer.
            should_follow = bool(self.follow_tail or self._is_view_at_remote_tail())
            if not self.backend.apply_live_update(update):
                continue

            if should_follow:
                # For normal updates, jump_tail/render_at reads the tail entirely
                # from the cache that was extended with only the new SSH bytes.
                # Very large bursts use only a bounded newest-tail cache window.
                self.remote_new_bytes = 0
                self.jump_tail()
            else:
                # Keep the exact reading position unchanged while still tracking
                # the new remote EOF. The status bar makes pending data obvious.
                self.remote_new_bytes += delta
                self._sync_virtual_scrollbar()
                self._update_status()

    def refresh_if_needed(self, force=False):
        if not force and not self.backend.has_changed():
            return False

        old_size = self.backend.size
        old_top = self._visible_top_byte()
        old_frac = old_top / old_size if old_size else 0.0
        old_encoding = self.backend.encoding
        old_newline = self.backend.newline
        old_bom = self.backend.bom

        try:
            if getattr(self.backend, "is_remote", False):
                self.backend.refresh()
                if self.encoding_choice != "自动":
                    self.backend.set_encoding(ENCODING_MAP[self.encoding_choice])
                self._replace_index()
            else:
                self.backend.close()
                self.backend = MappedTextFile(self.path)
                if self.encoding_choice != "自动":
                    self.backend.set_encoding(ENCODING_MAP[self.encoding_choice])

                same_encoding = (
                    self.backend.encoding == old_encoding and
                    self.backend.newline == old_newline and
                    self.backend.bom == old_bom
                )
                if same_encoding and self.backend.size >= old_size:
                    if not self.index.extend_if_append(self.backend.size, self.backend.mtime_ns):
                        self._replace_index()
                else:
                    self._replace_index()

            if self.follow_tail:
                self.jump_tail()
            else:
                self._render_around(int(self.backend.size * old_frac))
            return True
        except Exception as e:
            self.status.config(text=f"刷新失败：{e}")
            return False

    def periodic(self):
        if self.closed:
            return
        if getattr(self.backend, "is_remote", False):
            self._poll_remote_live_results()
            self._start_remote_live_poll()
        elif self.follow_tail and self.backend.has_changed():
            self.refresh_if_needed(force=True)

        if self.pending_jump_line is not None and getattr(self.backend, "mm", None):
            target = self.pending_jump_line
            offset = self.index.offset_for_line(target, self.backend.mm)
            if offset is not None:
                self.pending_jump_line = None
                self._render_around(offset, line_hint=target, exact_hint=True)
                return

        if self.gutter_was_approx and getattr(self.backend, "mm", None):
            exact = self.index.line_number_at(self.page_start, self.backend.mm)
            if exact is not None:
                self.page_start_line = exact
                self.page_line_exact = True
                self._render_gutter()

        if (
            self.click_byte is not None and
            not getattr(self, "click_line_exact", False) and
            getattr(self.backend, "mm", None)
        ):
            exact_click = self.index.line_number_at(self.click_byte, self.backend.mm)
            if exact_click is not None:
                self.click_line = exact_click
                self.click_line_exact = True

        self._update_status()

    def export_data(self):
        default = os.path.basename(getattr(self.backend, "path", self.path)) + ".textmark.json"
        target = filedialog.asksaveasfilename(
            title="导出标注与书签",
            initialfile=default,
            defaultextension=".json",
            filetypes=[
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("Markdown", "*.md"),
            ],
            parent=self
        )
        if not target:
            return
        ext = Path(target).suffix.lower()
        try:
            if ext == ".csv":
                self._export_csv(target)
            elif ext in (".md", ".markdown"):
                self._export_markdown(target)
            else:
                self._export_json(target)
            messagebox.showinfo(
                "导出完成",
                f"已导出 {len(self.annotations)} 条标注、{len(self.bookmarks)} 个书签。\n\n{target}",
                parent=self
            )
        except Exception as e:
            messagebox.showerror("导出失败", str(e), parent=self)

    def _export_json(self, target):
        payload = {
            "app": APP_NAME,
            "version": VERSION,
            "source_file": self.path,
            "source_size": self.backend.size,
            "encoding": self.backend.encoding,
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "annotations": self.annotations,
            "bookmarks": self.bookmarks,
        }
        Path(target).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _export_csv(self, target):
        with open(target, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["type", "start_byte", "end_byte", "color", "label", "note", "excerpt", "created_at"])
            for a in self.annotations:
                w.writerow(["annotation", a["start_byte"], a["end_byte"], a["color"], "",
                            a["note"], a["excerpt"], a["created_at"]])
            for b in self.bookmarks:
                w.writerow(["bookmark", b["byte_pos"], "", "", b["label"], "",
                            b["excerpt"], b["created_at"]])

    def _export_markdown(self, target):
        def esc(s):
            return str(s or "").replace("|", r"\|").replace("\n", " ")
        parts = [
            f"# TextMark Export",
            "",
            f"- Source: `{self.path}`",
            f"- Encoding: `{self.backend.encoding}`",
            f"- Exported: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Annotations",
            "",
            "| Byte range | Color | Excerpt | Note | Created |",
            "|---:|---|---|---|---|",
        ]
        for a in self.annotations:
            parts.append(
                f"| {a['start_byte']:,}–{a['end_byte']:,} | {esc(a['color'])} | "
                f"{esc(a['excerpt'])} | {esc(a['note'])} | {esc(a['created_at'])} |"
            )
        parts += [
            "",
            "## Bookmarks",
            "",
            "| Byte | Label | Excerpt | Created |",
            "|---:|---|---|---|",
        ]
        for b in self.bookmarks:
            parts.append(
                f"| {b['byte_pos']:,} | {esc(b['label'])} | {esc(b['excerpt'])} | {esc(b['created_at'])} |"
            )
        Path(target).write_text("\n".join(parts) + "\n", encoding="utf-8")



class RemoteBrowserDialog(tk.Toplevel):
    """Integrated SSH/SFTP browser with optional one-hop ProxyJump."""
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self.title("SSH/SFTP 远程文件")
        self.geometry("980x720")
        self.minsize(800, 580)
        self.transient(app.root)
        self.session = None
        self.current_dir = ""
        self.results = queue.Queue()
        self.busy = False
        self.download_events = queue.Queue()
        self.download_active = False
        self.download_progress_var = tk.DoubleVar(value=0.0)
        self.download_status_var = tk.StringVar(value="后台下载：空闲")
        self.upload_events = queue.Queue()
        self.upload_active = False
        self.upload_progress_var = tk.DoubleVar(value=0.0)
        self.upload_status_var = tk.StringVar(value="后台上传：空闲")
        self.upload_session = None
        self.upload_remote_dir = ""
        self.upload_refresh_pending = False
        self.connection_history = load_remote_history()
        self.active_connection_record = None
        # Remote directory-name search runs on its own SFTP channel.  It must not
        # block ordinary browsing, downloads/uploads or a ProxyJump target session.
        self.dir_search_events = queue.Queue()
        self.dir_search_active = False
        self.dir_search_cancel = None
        self.dir_search_token = 0
        self.dir_search_mode = False
        self.dir_search_session = None
        self.dir_search_root = ""

        self.history_var = tk.StringVar()
        self.jump_history_var = tk.StringVar()
        self.jump_history_records = []
        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value=os.environ.get("USER", ""))
        self.password_var = tk.StringVar()
        self.key_var = tk.StringVar()
        self.trust_var = tk.BooleanVar(value=True)
        self.use_jump_var = tk.BooleanVar(value=False)
        self.jump_host_var = tk.StringVar()
        self.jump_port_var = tk.StringVar(value="22")
        self.jump_user_var = tk.StringVar()
        self.jump_password_var = tk.StringVar()
        self.jump_key_var = tk.StringVar()
        self.path_var = tk.StringVar(value="~")
        self.dir_search_var = tk.StringVar()
        self.dir_search_recursive_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="填写目标 SSH 信息后点击“连接”。")

        self._build_ui()
        self._refresh_history_combo(select_latest=True)
        self._refresh_jump_history_combo(select_current=True)
        # Closing the remote browser only hides it. The live SSH session and
        # opened remote tabs remain owned by TextMark until the app exits.
        self.protocol("WM_DELETE_WINDOW", self.hide_window)
        self.after(60, self._poll_results)

    def hide_window(self):
        try:
            self.withdraw()
        except tk.TclError:
            pass

    def show_window(self):
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
            if self.session is not None:
                state = "已连接" if self.session.is_alive() else "连接已断开，后台将自动重连"
                location = self.current_dir or self.path_var.get() or "~"
                self.status_var.set(f"{self.session.label} | {state} | {location}")
        except tk.TclError:
            pass

    def _build_ui(self):
        # Keep the SSH area compact and aligned: saved endpoint first, then credentials.
        conn = ttk.LabelFrame(self, text="目标 SSH", padding=(10, 8))
        self.target_frame = conn
        conn.pack(fill="x", padx=10, pady=(10, 5))

        ttk.Label(conn, text="最近连接").grid(row=0, column=0, sticky="w")
        self.history_combo = ttk.Combobox(conn, textvariable=self.history_var, state="readonly")
        self.history_combo.grid(row=0, column=1, columnspan=5, sticky="ew", padx=(5, 8))
        self.history_combo.bind("<<ComboboxSelected>>", self._on_history_selected)
        self.connect_btn = ttk.Button(conn, text="连接", command=self._connect)
        self.connect_btn.grid(row=0, column=6, sticky="ew")

        ttk.Label(conn, text="主机").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(conn, textvariable=self.host_var, width=22).grid(
            row=1, column=1, padx=(5, 12), pady=(8, 0), sticky="ew"
        )
        ttk.Label(conn, text="端口").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(conn, textvariable=self.port_var, width=7).grid(
            row=1, column=3, padx=(5, 12), pady=(8, 0), sticky="w"
        )
        ttk.Label(conn, text="用户").grid(row=1, column=4, sticky="w", pady=(8, 0))
        ttk.Entry(conn, textvariable=self.user_var, width=18).grid(
            row=1, column=5, padx=(5, 8), pady=(8, 0), sticky="ew"
        )

        ttk.Label(conn, text="密码").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(conn, textvariable=self.password_var, show="*", width=22).grid(
            row=2, column=1, padx=(5, 12), pady=(8, 0), sticky="ew"
        )
        ttk.Label(conn, text="私钥").grid(row=2, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(conn, textvariable=self.key_var).grid(
            row=2, column=3, columnspan=3, padx=(5, 8), pady=(8, 0), sticky="ew"
        )
        ttk.Button(conn, text="选择…", command=self._choose_key, style="Compact.TButton").grid(
            row=2, column=6, sticky="ew", pady=(8, 0)
        )

        ttk.Checkbutton(
            conn, text="首次连接自动信任主机密钥（TOFU）", variable=self.trust_var
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(
            conn, text="使用跳板机 / ProxyJump", variable=self.use_jump_var, command=self._toggle_jump
        ).grid(row=3, column=3, columnspan=4, sticky="w", pady=(8, 0))

        conn.columnconfigure(1, weight=3)
        conn.columnconfigure(3, weight=1)
        conn.columnconfigure(5, weight=2)

        self.jump_frame = ttk.LabelFrame(self, text="跳板机（一级 SSH）", padding=(10, 8))
        # The jump host has an independent recent-connection selector. Its entries are
        # derived from saved ProxyJump records, so passwords/keys can be reused without
        # tying the jump host to one particular target server.
        ttk.Label(self.jump_frame, text="最近跳板").grid(row=0, column=0, sticky="w")
        self.jump_history_combo = ttk.Combobox(
            self.jump_frame, textvariable=self.jump_history_var, state="readonly"
        )
        self.jump_history_combo.grid(row=0, column=1, columnspan=6, sticky="ew", padx=(5, 0))
        self.jump_history_combo.bind("<<ComboboxSelected>>", self._on_jump_history_selected)

        ttk.Label(self.jump_frame, text="主机").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(self.jump_frame, textvariable=self.jump_host_var, width=22).grid(
            row=1, column=1, padx=(5, 12), pady=(8, 0), sticky="ew"
        )
        ttk.Label(self.jump_frame, text="端口").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(self.jump_frame, textvariable=self.jump_port_var, width=7).grid(
            row=1, column=3, padx=(5, 12), pady=(8, 0), sticky="w"
        )
        ttk.Label(self.jump_frame, text="用户").grid(row=1, column=4, sticky="w", pady=(8, 0))
        ttk.Entry(self.jump_frame, textvariable=self.jump_user_var, width=18).grid(
            row=1, column=5, columnspan=2, padx=(5, 0), pady=(8, 0), sticky="ew"
        )

        ttk.Label(self.jump_frame, text="密码").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(self.jump_frame, textvariable=self.jump_password_var, show="*", width=22).grid(
            row=2, column=1, padx=(5, 12), pady=(8, 0), sticky="ew"
        )
        ttk.Label(self.jump_frame, text="私钥").grid(row=2, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(self.jump_frame, textvariable=self.jump_key_var).grid(
            row=2, column=3, columnspan=3, padx=(5, 8), pady=(8, 0), sticky="ew"
        )
        ttk.Button(self.jump_frame, text="选择…", command=self._choose_jump_key, style="Compact.TButton").grid(
            row=2, column=6, sticky="ew", pady=(8, 0)
        )
        self.jump_frame.columnconfigure(1, weight=3)
        self.jump_frame.columnconfigure(3, weight=1)
        self.jump_frame.columnconfigure(4, weight=1)
        self.jump_frame.columnconfigure(5, weight=2)

        nav = ttk.Frame(self, padding=(10, 3, 10, 3))
        nav.pack(fill="x")
        ttk.Button(nav, text="上级", command=self._go_up, style="Compact.TButton").pack(side="left")
        ttk.Label(nav, text="路径:").pack(side="left", padx=(8, 3))
        entry = ttk.Entry(nav, textvariable=self.path_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self._load_path(self.path_var.get()))
        ttk.Button(nav, text="转到", command=lambda: self._load_path(self.path_var.get()), style="Compact.TButton").pack(side="left", padx=(5, 0))
        ttk.Button(nav, text="刷新", command=lambda: self._load_path(self.current_dir or self.path_var.get()), style="Compact.TButton").pack(side="left", padx=(5, 0))

        # Filename/directory search starts at the currently visible remote directory.
        # Recursive scans use an independent SFTP channel, so the rest of the SSH UI
        # remains responsive even on a large tree or a second-level ProxyJump target.
        search_bar = ttk.Frame(self, padding=(10, 1, 10, 3))
        search_bar.pack(fill="x")
        ttk.Label(search_bar, text="目录搜索:").pack(side="left")
        self.dir_search_entry = ttk.Entry(search_bar, textvariable=self.dir_search_var)
        self.dir_search_entry.pack(side="left", fill="x", expand=True, padx=(5, 7))
        self.dir_search_entry.bind("<Return>", lambda _e: self._toggle_remote_dir_search())
        ttk.Checkbutton(
            search_bar, text="包含子目录", variable=self.dir_search_recursive_var
        ).pack(side="left", padx=(0, 7))
        self.dir_search_btn = ttk.Button(
            search_bar, text="搜索", command=self._toggle_remote_dir_search, style="Compact.TButton"
        )
        self.dir_search_btn.pack(side="left")
        ttk.Button(
            search_bar, text="清除", command=self._clear_remote_dir_search, style="Compact.TButton"
        ).pack(side="left", padx=(5, 0))

        frame = ttk.Frame(self, padding=(10, 4, 10, 4))
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(
            frame, columns=("name", "type", "size", "mtime", "location", "fullpath"),
            displaycolumns=("name", "type", "size", "mtime"),
            show="headings", selectmode="browse", height=3
        )
        self.tree.heading("name", text="名称")
        self.tree.heading("type", text="类型")
        self.tree.heading("size", text="大小")
        self.tree.heading("mtime", text="修改时间")
        self.tree.heading("location", text="所在目录")
        self.tree.column("name", width=410, stretch=True)
        self.tree.column("type", width=72, stretch=False)
        self.tree.column("size", width=92, stretch=False, anchor="e")
        self.tree.column("mtime", width=155, stretch=False)
        self.tree.column("location", width=270, stretch=True)
        self.tree.column("fullpath", width=0, stretch=False)
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._activate_selection)
        self.tree.bind("<Return>", self._activate_selection)

        bottom = ttk.Frame(self, padding=(10, 4, 10, 8))
        bottom.pack(fill="x")
        ttk.Label(bottom, textvariable=self.status_var).grid(row=0, column=0, columnspan=4, sticky="ew")

        ttk.Label(bottom, text="后台下载").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.download_progress = ttk.Progressbar(
            bottom, variable=self.download_progress_var, maximum=100.0, mode="determinate"
        )
        self.download_progress.grid(row=1, column=1, sticky="ew", padx=(7, 7), pady=(6, 0))
        ttk.Label(bottom, textvariable=self.download_status_var, foreground="#666666").grid(
            row=1, column=2, sticky="e", padx=(0, 8), pady=(6, 0)
        )
        self.download_btn = ttk.Button(
            bottom, text="下载到本地", command=self._download_selected, style="Compact.TButton"
        )
        self.download_btn.grid(row=1, column=3, sticky="e", pady=(6, 0))

        ttk.Label(bottom, text="后台上传").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.upload_progress = ttk.Progressbar(
            bottom, variable=self.upload_progress_var, maximum=100.0, mode="determinate"
        )
        self.upload_progress.grid(row=2, column=1, sticky="ew", padx=(7, 7), pady=(6, 0))
        ttk.Label(bottom, textvariable=self.upload_status_var, foreground="#666666").grid(
            row=2, column=2, sticky="e", padx=(0, 8), pady=(6, 0)
        )
        self.upload_btn = ttk.Button(
            bottom, text="上传到当前目录", command=self._upload_files, style="Compact.TButton"
        )
        self.upload_btn.grid(row=2, column=3, sticky="e", pady=(6, 0))
        bottom.columnconfigure(1, weight=1)

    @staticmethod
    def _history_label(record):
        target = f"{record.get('user', '')}@{record.get('host', '')}:{int(record.get('port', 22) or 22)}"
        if record.get("use_jump") and record.get("jump_host"):
            jump = f"{record.get('jump_user', '')}@{record.get('jump_host', '')}:{int(record.get('jump_port', 22) or 22)}"
            return f"{target}  ←  {jump}"
        return target

    @staticmethod
    def _jump_history_label(record):
        return f"{record.get('jump_user', '')}@{record.get('jump_host', '')}:{int(record.get('jump_port', 22) or 22)}"

    @staticmethod
    def _jump_history_key(record):
        return (
            str(record.get("jump_host", "")).strip().lower(),
            int(record.get("jump_port", 22) or 22),
            str(record.get("jump_user", "")).strip(),
        )

    def _collect_jump_history(self):
        rows = []
        seen = set()
        # connection_history is newest-first, so duplicate jump hosts naturally keep
        # the latest saved password/key.
        for record in self.connection_history:
            if not record.get("use_jump") or not record.get("jump_host") or not record.get("jump_user"):
                continue
            key = self._jump_history_key(record)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "jump_host": str(record.get("jump_host", "")),
                "jump_port": int(record.get("jump_port", 22) or 22),
                "jump_user": str(record.get("jump_user", "")),
                "jump_password": str(record.get("jump_password", "")),
                "jump_key": str(record.get("jump_key", "")),
                "updated_at": float(record.get("updated_at", 0) or 0),
            })
        return rows[:REMOTE_HISTORY_LIMIT]

    def _refresh_jump_history_combo(self, select_current=False):
        if not hasattr(self, "jump_history_combo"):
            return
        self.jump_history_records = self._collect_jump_history()
        labels = [self._jump_history_label(x) for x in self.jump_history_records]
        self.jump_history_combo.configure(values=labels)
        if not labels:
            self.jump_history_var.set("")
            return
        if select_current:
            current_key = (
                self.jump_host_var.get().strip().lower(),
                int(self.jump_port_var.get().strip() or "22"),
                self.jump_user_var.get().strip(),
            )
            for idx, record in enumerate(self.jump_history_records):
                if self._jump_history_key(record) == current_key:
                    self.jump_history_combo.current(idx)
                    return
            self.jump_history_var.set("")

    def _apply_jump_history_record(self, record):
        self.jump_host_var.set(str(record.get("jump_host", "")))
        self.jump_port_var.set(str(int(record.get("jump_port", 22) or 22)))
        self.jump_user_var.set(str(record.get("jump_user", "")))
        self.jump_password_var.set(str(record.get("jump_password", "")))
        self.jump_key_var.set(str(record.get("jump_key", "")))

    def _on_jump_history_selected(self, _event=None):
        idx = self.jump_history_combo.current()
        if 0 <= idx < len(self.jump_history_records):
            self._apply_jump_history_record(self.jump_history_records[idx])

    def _refresh_history_combo(self, select_latest=False):
        if not hasattr(self, "history_combo"):
            return
        labels = [self._history_label(x) for x in self.connection_history]
        self.history_combo.configure(values=labels)
        if select_latest and self.connection_history:
            self.history_combo.current(0)
            self._apply_history_record(self.connection_history[0])
        elif not labels:
            self.history_var.set("")

    def _apply_history_record(self, record):
        self.host_var.set(str(record.get("host", "")))
        self.port_var.set(str(int(record.get("port", 22) or 22)))
        self.user_var.set(str(record.get("user", "")))
        self.key_var.set(str(record.get("key", "")))
        self.trust_var.set(bool(record.get("trust", True)))
        self.use_jump_var.set(bool(record.get("use_jump", False)))
        self.jump_host_var.set(str(record.get("jump_host", "")))
        self.jump_port_var.set(str(int(record.get("jump_port", 22) or 22)))
        self.jump_user_var.set(str(record.get("jump_user", "")))
        self.jump_key_var.set(str(record.get("jump_key", "")))
        self.path_var.set(str(record.get("last_dir", "~") or "~"))
        self.password_var.set(str(record.get("password", "")))
        self.jump_password_var.set(str(record.get("jump_password", "")))
        self._toggle_jump()
        self._refresh_jump_history_combo(select_current=True)

    def _on_history_selected(self, _event=None):
        idx = self.history_combo.current()
        if 0 <= idx < len(self.connection_history):
            self._apply_history_record(self.connection_history[idx])

    def _record_from_fields(self):
        use_jump = bool(self.use_jump_var.get())
        return {
            "host": self.host_var.get().strip(),
            "port": int(self.port_var.get().strip() or "22"),
            "user": self.user_var.get().strip(),
            "password": self.password_var.get(),
            "key": self.key_var.get().strip(),
            "trust": bool(self.trust_var.get()),
            "use_jump": use_jump,
            "jump_host": self.jump_host_var.get().strip() if use_jump else "",
            "jump_port": int(self.jump_port_var.get().strip() or "22") if use_jump else 22,
            "jump_user": self.jump_user_var.get().strip() if use_jump else "",
            "jump_password": self.jump_password_var.get() if use_jump else "",
            "jump_key": self.jump_key_var.get().strip() if use_jump else "",
            "last_dir": "~",
        }

    def _existing_history_record(self, record):
        key = _remote_record_key(record)
        return next((x for x in self.connection_history if _remote_record_key(x) == key), None)

    def _remember_connection(self, record, last_dir=None):
        saved = dict(record)
        # The user explicitly opted into password autofill for recent connections.
        # remote_connections.json is limited to the current OS user (0600 where supported).
        if last_dir:
            saved["last_dir"] = last_dir
        elif not saved.get("last_dir"):
            saved["last_dir"] = "~"
        saved["updated_at"] = time.time()
        key = _remote_record_key(saved)
        rows = [x for x in self.connection_history if _remote_record_key(x) != key]
        self.connection_history = [saved] + rows
        try:
            save_remote_history(self.connection_history)
        except Exception as e:
            self.status_var.set(f"连接已建立，但本地连接记录保存失败：{e}")
            return
        self._refresh_history_combo()
        self.history_combo.current(0)
        self._refresh_jump_history_combo(select_current=True)

    def _toggle_jump(self):
        if self.use_jump_var.get():
            self.jump_frame.pack(fill="x", padx=10, pady=(0, 6), after=self.target_frame)
        else:
            self.jump_frame.pack_forget()

    def _choose_key(self):
        p = filedialog.askopenfilename(title="选择目标服务器 SSH 私钥", parent=self)
        if p:
            self.key_var.set(p)

    def _choose_jump_key(self):
        p = filedialog.askopenfilename(title="选择跳板机 SSH 私钥", parent=self)
        if p:
            self.jump_key_var.set(p)

    def _set_busy(self, busy: bool, text: str = ""):
        self.busy = busy
        self.connect_btn.configure(state="disabled" if busy else "normal")
        # Background downloads have an independent SFTP channel and progress
        # state; ordinary browse/connect tasks must not pause or reset them.
        if text:
            self.status_var.set(text)

    def _start_task(self, kind, func):
        if self.busy:
            return
        self._set_busy(True)
        def worker():
            try:
                value = func()
                err = None
            except Exception as e:
                value, err = None, str(e)
            self.results.put((kind, value, err))
        threading.Thread(target=worker, daemon=True, name=f"TextMarkRemote-{kind}").start()

    def _connect(self):
        self._cancel_remote_dir_search(invalidate=True)
        self._set_dir_search_view(False)
        if not HAS_PARAMIKO:
            messagebox.showerror(
                "SSH/SFTP",
                "当前环境没有 Paramiko。请先运行本包的 install_ubuntu.sh，\n"
                "它会在独立 .venv 中安装 SSH/SFTP 依赖。",
                parent=self,
            )
            return
        host = self.host_var.get().strip()
        user = self.user_var.get().strip()
        if not host or not user:
            messagebox.showinfo("SSH/SFTP", "请填写目标服务器主机和用户名。", parent=self)
            return
        try:
            port = int(self.port_var.get().strip() or "22")
        except ValueError:
            messagebox.showerror("SSH/SFTP", "目标端口必须是整数。", parent=self)
            return

        jump_host = jump_user = jump_password = jump_key = ""
        jump_port = 22
        if self.use_jump_var.get():
            jump_host = self.jump_host_var.get().strip()
            jump_user = self.jump_user_var.get().strip()
            if not jump_host or not jump_user:
                messagebox.showinfo("SSH/SFTP", "启用跳板机后，请填写跳板机主机和用户名。", parent=self)
                return
            try:
                jump_port = int(self.jump_port_var.get().strip() or "22")
            except ValueError:
                messagebox.showerror("SSH/SFTP", "跳板机端口必须是整数。", parent=self)
                return
            jump_password = self.jump_password_var.get()
            jump_key = self.jump_key_var.get().strip()

        password = self.password_var.get()
        key = self.key_var.get().strip()
        trust = self.trust_var.get()
        record = self._record_from_fields()
        existing = self._existing_history_record(record)
        if existing and existing.get("last_dir"):
            record["last_dir"] = existing.get("last_dir")
        if jump_host:
            self.status_var.set(
                f"正在连接 {jump_user}@{jump_host}:{jump_port} → {user}@{host}:{port} …"
            )
        else:
            self.status_var.set(f"正在连接 {user}@{host}:{port} …")
        self._start_task(
            "connect",
            lambda: (
                RemoteSession(
                    host, port, user, password, key, trust,
                    jump_host=jump_host, jump_port=jump_port,
                    jump_username=jump_user, jump_password=jump_password,
                    jump_key_filename=jump_key,
                ),
                record,
            )
        )

    def _load_path(self, path):
        if not self.session:
            return
        # Any explicit navigation leaves the search-result view. The search term
        # stays in the box so it can be repeated quickly in the new directory.
        if self.dir_search_active:
            self._cancel_remote_dir_search(invalidate=True)
        if self.dir_search_mode:
            self._set_dir_search_view(False)
        raw = path.strip() or self.current_dir or "~"
        self.status_var.set(f"正在读取目录 {raw} …")
        def task():
            p = self.session.normalize_path(raw)
            return p, self.session.listdir(p)
        self._start_task("list", task)

    def _go_up(self):
        if not self.session:
            return
        p = self.current_dir or self.session.home_dir()
        self._load_path(posixpath.dirname(p.rstrip("/")) or "/")

    def _set_dir_search_view(self, enabled: bool):
        """Show the extra location column only while displaying search results."""
        self.dir_search_mode = bool(enabled)
        if enabled:
            self.tree.configure(displaycolumns=("name", "type", "size", "mtime", "location"))
            self.tree.column("name", width=275, stretch=True)
            self.tree.column("location", width=275, stretch=True)
        else:
            self.tree.configure(displaycolumns=("name", "type", "size", "mtime"))
            self.tree.column("name", width=410, stretch=True)

    def _cancel_remote_dir_search(self, invalidate=True):
        event = self.dir_search_cancel
        if event is not None:
            event.set()
        self.dir_search_cancel = None
        self.dir_search_active = False
        if invalidate:
            self.dir_search_token += 1
        if hasattr(self, "dir_search_btn"):
            try:
                self.dir_search_btn.configure(text="搜索")
            except tk.TclError:
                pass

    def _toggle_remote_dir_search(self):
        if self.dir_search_active:
            if self.dir_search_cancel is not None:
                self.dir_search_cancel.set()
            self.status_var.set("正在停止远程目录搜索…")
            return
        self._start_remote_dir_search()

    def _start_remote_dir_search(self):
        if not self.session:
            messagebox.showinfo("SSH/SFTP", "请先连接远程服务器。", parent=self)
            return
        term = self.dir_search_var.get().strip()
        if not term:
            self.dir_search_entry.focus_set()
            self.status_var.set("请输入要搜索的远程文件或目录名称。")
            return
        root = self.current_dir or self.path_var.get().strip()
        if not root:
            messagebox.showinfo("SSH/SFTP", "请先进入要搜索的远程目录。", parent=self)
            return

        # Invalidate a prior worker without waiting for it. Every scan owns an
        # independent SFTP channel, and stale queue events are ignored by token.
        self._cancel_remote_dir_search(invalidate=True)
        token = self.dir_search_token
        cancel = threading.Event()
        session = self.session
        recursive = bool(self.dir_search_recursive_var.get())
        self.dir_search_cancel = cancel
        self.dir_search_active = True
        self.dir_search_session = session
        self.dir_search_root = root
        self.dir_search_btn.configure(text="停止")
        scope = "当前目录及子目录" if recursive else "当前目录"
        self.status_var.set(f"正在搜索 {scope}：{term} …")

        def progress(info):
            self.dir_search_events.put((token, session, "progress", info, None))

        def worker():
            try:
                info = session.search_paths(
                    root, term, recursive=recursive, max_results=2000,
                    progress_callback=progress, cancel_event=cancel,
                )
                err = None
            except Exception as exc:
                info, err = None, str(exc)
            self.dir_search_events.put((token, session, "done", info, err))

        threading.Thread(
            target=worker, daemon=True, name="TextMarkRemoteDirectorySearch"
        ).start()

    def _clear_remote_dir_search(self):
        was_search_view = self.dir_search_mode
        self._cancel_remote_dir_search(invalidate=True)
        self.dir_search_var.set("")
        self._set_dir_search_view(False)
        if was_search_view and self.session and (self.current_dir or self.path_var.get().strip()):
            self._load_path(self.current_dir or self.path_var.get())
        elif self.session:
            self.status_var.set(
                f"{self.session.label}  |  {self.current_dir or self.path_var.get()}  |  后台保活"
            )

    def _poll_remote_dir_search_events(self):
        while True:
            try:
                token, session, kind, info, err = self.dir_search_events.get_nowait()
            except queue.Empty:
                break
            if token != self.dir_search_token or session is not self.dir_search_session:
                continue
            if kind == "progress":
                data = info or {}
                self.status_var.set(
                    f"目录搜索中：已扫描 {int(data.get('scanned_dirs', 0) or 0)} 个目录 / "
                    f"{int(data.get('scanned_items', 0) or 0)} 项，命中 "
                    f"{int(data.get('matches', 0) or 0)} 项…"
                )
                continue

            self.dir_search_active = False
            self.dir_search_cancel = None
            self.dir_search_btn.configure(text="搜索")
            if err:
                short = err.replace("\n", " ").strip()
                if len(short) > 100:
                    short = short[:97] + "..."
                self.status_var.set(f"目录搜索失败：{short}")
                continue
            result = info or {}
            if result.get("cancelled"):
                self.status_var.set("远程目录搜索已停止。")
                continue

            self._set_dir_search_view(True)
            for item in self.tree.get_children():
                self.tree.delete(item)
            rows = list(result.get("matches", []) or [])
            type_labels = {"dir": "目录", "file": "文件", "link": "链接", "other": "其他"}
            for i, row in enumerate(rows):
                typ = type_labels.get(row.get("type"), str(row.get("type", "")))
                size = "" if row.get("type") == "dir" else human_size(int(row.get("size", 0) or 0))
                mt_raw = int(row.get("mtime", 0) or 0)
                mt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mt_raw)) if mt_raw else ""
                rel = str(row.get("relative", row.get("name", "")))
                location = posixpath.dirname(rel) or "."
                self.tree.insert(
                    "", "end", iid=f"s{i}",
                    values=(row.get("name", ""), typ, size, mt, location, row.get("path", "")),
                )

            count = len(rows)
            scanned_dirs = int(result.get("scanned_dirs", 0) or 0)
            scanned_items = int(result.get("scanned_items", 0) or 0)
            skipped = int(result.get("skipped_dirs", 0) or 0)
            extras = []
            if result.get("truncated"):
                extras.append(f"结果已达到 {int(result.get('max_results', 2000) or 2000)} 条上限")
            if skipped:
                extras.append(f"跳过 {skipped} 个不可访问目录")
            tail = (" | " + "；".join(extras)) if extras else ""
            self.status_var.set(
                f"搜索完成：{count} 项 | 扫描 {scanned_dirs} 个目录 / {scanned_items} 项{tail}"
            )

    def _selected_row(self):
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return None
        full = str(vals[5]) if len(vals) > 5 and vals[5] else posixpath.join(self.current_dir, vals[0])
        return {"name": vals[0], "type": vals[1], "path": full}

    def _activate_selection(self, _event=None):
        row = self._selected_row()
        if not row:
            return
        full = row.get("path") or posixpath.join(self.current_dir, row["name"])
        if row["type"] == "目录":
            self._load_path(full)
        elif row["type"] == "文件":
            self._open_path(full)
        elif row["type"] == "链接":
            self.status_var.set(f"正在解析符号链接 {full} …")
            self._start_task("activate", lambda: (full, self.session.path_kind(full)))
        else:
            messagebox.showinfo("SSH/SFTP", f"该远程项类型暂不支持打开：{row['type']}", parent=self)

    def _open_selected(self):
        self._activate_selection()

    def _download_selected(self):
        if not self.session:
            messagebox.showinfo("SSH/SFTP", "请先连接远程服务器。", parent=self)
            return
        if self.download_active:
            self.download_status_var.set("已有后台下载正在进行")
            return
        row = self._selected_row()
        if not row:
            messagebox.showinfo("SSH/SFTP", "请先选择要下载的远程文件或目录。", parent=self)
            return
        if row["type"] not in ("文件", "目录", "链接"):
            messagebox.showinfo("SSH/SFTP", f"该远程项类型暂不支持下载：{row['type']}", parent=self)
            return
        full = row.get("path") or posixpath.join(self.current_dir, row["name"])
        local_root = local_textmark_download_dir()
        try:
            local_root.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            messagebox.showerror(
                "SSH/SFTP", f"无法创建本地下载目录：\n{local_root}\n\n{e}", parent=self
            )
            return

        # Capture the current session so reconnecting/browsing another endpoint
        # cannot redirect an already-running transfer.
        session = self.session
        self.download_active = True
        self.download_btn.configure(state="disabled")
        self.download_progress.stop()
        self.download_progress.configure(mode="indeterminate")
        self.download_progress_var.set(0.0)
        self.download_progress.start(12)
        self.download_status_var.set(f"正在统计：{row['name']}")

        def progress(info):
            self.download_events.put(("progress", info, None))

        def worker():
            try:
                info = session.download_path(full, local_root, progress_callback=progress)
                err = None
            except Exception as exc:
                info, err = None, str(exc)
            self.download_events.put(("done", info, err))

        threading.Thread(
            target=worker, daemon=True, name="TextMarkBackgroundDownload"
        ).start()

    def _apply_download_progress(self, info):
        info = info or {}
        phase = info.get("phase", "")
        if phase == "scan":
            if str(self.download_progress.cget("mode")) != "indeterminate":
                self.download_progress.configure(mode="indeterminate")
                self.download_progress.start(12)
            items = int(info.get("items", 0) or 0)
            files = int(info.get("files_total", 0) or 0)
            self.download_status_var.set(f"统计中：{items} 项 / {files} 文件")
            return

        if phase in ("download", "done"):
            self.download_progress.stop()
            self.download_progress.configure(mode="determinate")
            done = max(0, int(info.get("transferred", 0) or 0))
            total = max(0, int(info.get("total_bytes", 0) or 0))
            pct = 100.0 if phase == "done" else (done / total * 100.0 if total else 0.0)
            self.download_progress_var.set(max(0.0, min(100.0, pct)))
            files_done = int(info.get("files_done", 0) or 0)
            files_total = int(info.get("files_total", 0) or 0)
            current = posixpath.basename(str(info.get("current", "")).rstrip("/"))
            if len(current) > 36:
                current = current[:33] + "..."
            if phase == "done":
                self.download_status_var.set(
                    f"完成：{files_done}/{files_total} 文件 · {human_size(total)}"
                )
            else:
                tail = f" · {current}" if current else ""
                self.download_status_var.set(
                    f"{pct:5.1f}% · {human_size(done)}/{human_size(total)} · "
                    f"{files_done}/{files_total} 文件{tail}"
                )

    def _poll_download_events(self):
        while True:
            try:
                kind, info, err = self.download_events.get_nowait()
            except queue.Empty:
                break
            if kind == "progress":
                self._apply_download_progress(info)
                continue

            self.download_active = False
            self.download_btn.configure(state="normal")
            self.download_progress.stop()
            self.download_progress.configure(mode="determinate")
            if err:
                # Silent background transfer: report failure in-place rather than
                # interrupting the user's current SSH browsing with a modal box.
                self.download_progress_var.set(0.0)
                short = err.replace("\n", " ").strip()
                if len(short) > 72:
                    short = short[:69] + "..."
                self.download_status_var.set(f"失败：{short}")
                continue

            result = info or {}
            total = int(result.get("bytes", result.get("total_bytes", 0)) or 0)
            files = int(result.get("files", 0) or 0)
            self.download_progress_var.set(100.0)
            self.download_status_var.set(f"完成：{files} 文件 · {human_size(total)}")

    def _upload_files(self):
        if not self.session:
            messagebox.showinfo("SSH/SFTP", "请先连接远程服务器。", parent=self)
            return
        if self.upload_active:
            self.upload_status_var.set("已有后台上传正在进行")
            return
        remote_dir = self.current_dir or self.path_var.get().strip()
        if not remote_dir:
            messagebox.showinfo("SSH/SFTP", "请先进入要上传到的远程目录。", parent=self)
            return

        paths = filedialog.askopenfilenames(
            title=f"选择要上传到 {remote_dir} 的本地文件",
            parent=self,
        )
        if not paths:
            return

        # Capture both the exact session and directory. If the user navigates to
        # another directory or reconnects while the upload is running, the transfer
        # still goes to the directory that was visible when it was started. For a
        # ProxyJump connection this session is the second-level target host.
        session = self.session
        self.upload_session = session
        self.upload_remote_dir = remote_dir
        self.upload_refresh_pending = False
        self.upload_active = True
        self.upload_btn.configure(state="disabled")
        self.upload_progress.stop()
        self.upload_progress.configure(mode="determinate")
        self.upload_progress_var.set(0.0)
        self.upload_status_var.set(f"准备上传：{len(paths)} 个文件")

        def progress(info):
            self.upload_events.put(("progress", info, None))

        def worker():
            try:
                info = session.upload_files(paths, remote_dir, progress_callback=progress)
                err = None
            except Exception as exc:
                info, err = None, str(exc)
            self.upload_events.put(("done", info, err))

        threading.Thread(
            target=worker, daemon=True, name="TextMarkBackgroundUpload"
        ).start()

    def _apply_upload_progress(self, info):
        info = info or {}
        phase = info.get("phase", "")
        if phase not in ("upload", "done"):
            return
        done = max(0, int(info.get("transferred", 0) or 0))
        total = max(0, int(info.get("total_bytes", 0) or 0))
        pct = 100.0 if phase == "done" else (done / total * 100.0 if total else 0.0)
        self.upload_progress_var.set(max(0.0, min(100.0, pct)))
        files_done = int(info.get("files_done", 0) or 0)
        files_total = int(info.get("files_total", 0) or 0)
        current = os.path.basename(str(info.get("current", "")))
        if len(current) > 36:
            current = current[:33] + "..."
        if phase == "done":
            self.upload_status_var.set(
                f"完成：{files_done}/{files_total} 文件 · {human_size(total)}"
            )
        else:
            tail = f" · {current}" if current else ""
            self.upload_status_var.set(
                f"{pct:5.1f}% · {human_size(done)}/{human_size(total)} · "
                f"{files_done}/{files_total} 文件{tail}"
            )

    def _poll_upload_events(self):
        while True:
            try:
                kind, info, err = self.upload_events.get_nowait()
            except queue.Empty:
                break
            if kind == "progress":
                self._apply_upload_progress(info)
                continue

            self.upload_active = False
            self.upload_btn.configure(state="normal")
            if err:
                # Keep uploads silent/non-modal just like downloads. Errors stay in
                # the transfer row so the user can keep browsing/searching normally.
                self.upload_progress_var.set(0.0)
                short = err.replace("\n", " ").strip()
                if len(short) > 72:
                    short = short[:69] + "..."
                self.upload_status_var.set(f"失败：{short}")
                continue

            result = info or {}
            self._apply_upload_progress(result)
            # Refresh only if the browser is still showing the exact destination on
            # the same SSH session. Otherwise do not disturb the user's new location.
            result_dir = str(result.get("remote_dir", self.upload_remote_dir) or "")
            if self.session is self.upload_session and self.current_dir == result_dir:
                self.upload_refresh_pending = True

    def _maybe_refresh_after_upload(self):
        if not self.upload_refresh_pending or self.busy:
            return
        if self.session is not self.upload_session or self.current_dir != self.upload_remote_dir:
            self.upload_refresh_pending = False
            return
        self.upload_refresh_pending = False
        self._load_path(self.upload_remote_dir)

    def _open_path(self, full):
        if not self.session:
            return
        self.status_var.set(f"正在按需打开 {full} …")
        self._start_task("open", lambda: self.session.open_file(full))

    def _poll_results(self):
        if not self.winfo_exists():
            return
        self._poll_download_events()
        self._poll_upload_events()
        self._poll_remote_dir_search_events()
        try:
            while True:
                kind, value, err = self.results.get_nowait()
                self._set_busy(False)
                if err:
                    self.status_var.set(f"失败：{err}")
                    messagebox.showerror("SSH/SFTP", err, parent=self)
                    continue
                if kind == "connect":
                    self.session, record = value
                    self.active_connection_record = dict(record)
                    self.app.register_remote_session(self.session)
                    # Keep both password fields intact after a successful connection so
                    # reconnecting or browsing another saved endpoint feels continuous.
                    keep = "后台保活已启用"
                    self.status_var.set(f"已连接：{self.session.label} | {keep}")
                    self._remember_connection(self.active_connection_record)
                    # Every target (including the second-level target behind a jump host)
                    # owns its own remembered directory. Never reuse another session's path.
                    self._load_path(self.active_connection_record.get("last_dir") or "~")
                elif kind == "list":
                    path, rows = value
                    self.current_dir = path
                    self.path_var.set(path)
                    self._set_dir_search_view(False)
                    for item in self.tree.get_children():
                        self.tree.delete(item)
                    for i, row in enumerate(rows):
                        typ = {"dir": "目录", "file": "文件", "link": "链接", "other": "其他"}.get(row["type"], row["type"])
                        size = "" if row["type"] == "dir" else human_size(row["size"])
                        mt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["mtime"])) if row["mtime"] else ""
                        full = posixpath.join(path, row["name"])
                        self.tree.insert(
                            "", "end", iid=f"r{i}",
                            values=(row["name"], typ, size, mt, "", full),
                        )
                    if self.active_connection_record is not None:
                        self.active_connection_record["last_dir"] = path
                        self._remember_connection(self.active_connection_record, last_dir=path)
                    self.status_var.set(f"{self.session.label}  |  {path}  |  {len(rows)} 项 | 后台保活")
                elif kind == "activate":
                    full, path_kind = value
                    if path_kind in ("dir", "dirlink"):
                        self._load_path(full)
                    elif path_kind in ("file", "filelink"):
                        self._open_path(full)
                    else:
                        messagebox.showinfo("SSH/SFTP", f"该符号链接目标不是普通目录/文件：\n{full}", parent=self)
                elif kind == "open":
                    backend = value
                    self.status_var.set(f"已打开：{backend.path} | SSH 后台持续连接")
                    self.app.open_remote_backend(backend)
                    # The file is now in the main notebook. Keep this exact
                    # browser/session object alive, but get the dialog out of
                    # the way; the toolbar can restore it instantly.
                    self.after_idle(self.hide_window)
        except queue.Empty:
            pass
        self._maybe_refresh_after_upload()
        try:
            self.after(60, self._poll_results)
        except tk.TclError:
            pass

class TextMarkApp:
    def __init__(self, root: tk.Tk, initial_paths=None):
        self.root = root
        self.root.title(f"{APP_NAME} {VERSION}")
        self.root.geometry("1450x860")
        self.root.minsize(980, 620)
        self.store = AnnotationStore()
        self.views = {}
        self.remote_sessions = []
        self.remote_browser = None

        self.search_var = tk.StringVar()
        self.regex_var = tk.BooleanVar(value=False)
        self.case_var = tk.BooleanVar(value=False)
        self.follow_var = tk.BooleanVar(value=False)
        self.mark_color_var = tk.StringVar(value="黄色")
        self.encoding_var = tk.StringVar(value="自动")
        self.quick_pages_var = tk.StringVar(value="10")

        self._configure_styles()
        # The top menu row duplicated toolbar/shortcut actions and is hidden by
        # design. Keyboard shortcuts and toolbar controls remain available.
        self._build_toolbar()

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self.sync_toolbar_from_active())
        self.notebook.bind("<Button-2>", self._middle_close_tab)
        self.register_drop_target(self.notebook)
        self.register_drop_target(self.root)

        self._bind_keys()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(700, self._periodic)

        initial_paths = initial_paths or []
        for path in initial_paths:
            if os.path.isfile(path):
                self.open_path(path)

        if not self.views:
            self._show_welcome()

    def _configure_styles(self):
        """Small cross-platform visual polish without changing application behavior."""
        style = ttk.Style(self.root)
        style.configure("TButton", padding=(8, 4))
        style.configure("TNotebook.Tab", padding=(10, 5))
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=("TkDefaultFont", 9, "bold"))
        style.configure("Toolbar.TFrame", padding=0)
        style.configure("Toolbar.TLabel", padding=(0, 0))
        style.configure("Compact.TButton", padding=(7, 3))

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        fm = tk.Menu(menubar, tearoff=0)
        fm.add_command(label="打开文件...", accelerator="Ctrl+O", command=self.choose_files)
        fm.add_command(label="SSH/SFTP 远程文件...", command=self.show_remote_browser)
        fm.add_command(label="关闭当前标签", accelerator="Ctrl+W", command=self.close_current_tab)
        fm.add_separator()
        fm.add_command(label="刷新当前文件", accelerator="F5", command=lambda: self.active_call("refresh_if_needed", True))
        fm.add_command(label="导出标注/书签...", command=lambda: self.active_call("export_data"))
        fm.add_separator()
        fm.add_command(label="退出", command=self.on_close)
        menubar.add_cascade(label="文件", menu=fm)

        nav = tk.Menu(menubar, tearoff=0)
        nav.add_command(label="跳转到行...", accelerator="Ctrl+G", command=lambda: self.active_call("goto_line_dialog"))
        nav.add_command(label="跳转到字节...", command=lambda: self.active_call("goto_byte_dialog"))
        nav.add_command(label="文件开头", accelerator="Ctrl+Home", command=lambda: self._goto_start())
        nav.add_command(label="文件末尾", accelerator="Ctrl+End", command=lambda: self.active_call("jump_tail"))
        menubar.add_cascade(label="跳转", menu=nav)

        mark = tk.Menu(menubar, tearoff=0)
        mark.add_command(label="添加标注", accelerator="Ctrl+M", command=lambda: self.active_call("add_annotation"))
        mark.add_command(label="添加书签", accelerator="Ctrl+B", command=lambda: self.active_call("add_bookmark_current"))
        mark.add_command(label="导出标注/书签...", command=lambda: self.active_call("export_data"))
        menubar.add_cascade(label="标注", menu=mark)

        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="快捷键", command=self.show_shortcuts)
        helpm.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=helpm)

        self.root.config(menu=menubar)

    def _build_toolbar(self):
        # Two compact rows keep the controls readable even on the minimum window width.
        bar = ttk.Frame(self.root, style="Toolbar.TFrame", padding=(8, 7, 8, 5))
        bar.pack(fill="x")

        primary = ttk.Frame(bar, style="Toolbar.TFrame")
        primary.pack(fill="x")
        ttk.Button(primary, text="打开文件", command=self.choose_files, style="Compact.TButton").grid(
            row=0, column=0, sticky="w"
        )
        self.remote_browser_btn = ttk.Button(
            primary, text="远程文件", command=self.show_remote_browser, style="Compact.TButton"
        )
        self.remote_browser_btn.grid(row=0, column=1, sticky="w", padx=(5, 5))
        self.close_tab_btn = ttk.Button(
            primary, text="关闭标签", command=self.close_current_tab, style="Compact.TButton", state="disabled"
        )
        self.close_tab_btn.grid(row=0, column=2, sticky="w", padx=(0, 10))

        ttk.Separator(primary, orient="vertical").grid(row=0, column=3, sticky="ns", padx=(0, 10))
        ttk.Label(primary, text="搜索", style="Toolbar.TLabel").grid(row=0, column=4, sticky="w")
        self.search_entry = ttk.Entry(primary, textvariable=self.search_var, width=30)
        self.search_entry.grid(row=0, column=5, sticky="ew", padx=(6, 6))
        primary.columnconfigure(5, weight=1)
        ttk.Checkbutton(primary, text="正则", variable=self.regex_var).grid(row=0, column=6, sticky="w", padx=(2, 0))
        ttk.Checkbutton(primary, text="区分大小写", variable=self.case_var).grid(row=0, column=7, sticky="w", padx=(6, 8))
        ttk.Button(primary, text="上一个", command=lambda: self.find_active(True), style="Compact.TButton").grid(
            row=0, column=8, sticky="e"
        )
        ttk.Button(primary, text="下一个", command=lambda: self.find_active(False), style="Compact.TButton").grid(
            row=0, column=9, sticky="e", padx=(5, 0)
        )

        secondary = ttk.Frame(bar, style="Toolbar.TFrame")
        secondary.pack(fill="x", pady=(6, 0))

        ttk.Label(secondary, text="标注").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            secondary, textvariable=self.mark_color_var, values=list(MARK_LABELS.values()),
            state="readonly", width=6
        ).grid(row=0, column=1, sticky="w", padx=(6, 5))
        ttk.Button(
            secondary, text="标注选区", command=lambda: self.active_call("add_annotation"), style="Compact.TButton"
        ).grid(row=0, column=2, sticky="w")
        ttk.Button(
            secondary, text="书签", command=lambda: self.active_call("add_bookmark_current"), style="Compact.TButton"
        ).grid(row=0, column=3, sticky="w", padx=(5, 10))

        ttk.Separator(secondary, orient="vertical").grid(row=0, column=4, sticky="ns", padx=(0, 10))
        ttk.Label(secondary, text="编码").grid(row=0, column=5, sticky="w")
        enc = ttk.Combobox(secondary, textvariable=self.encoding_var, values=ENCODING_CHOICES, state="readonly", width=10)
        enc.grid(row=0, column=6, sticky="w", padx=(6, 8))
        enc.bind("<<ComboboxSelected>>", self._encoding_changed)
        ttk.Checkbutton(
            secondary, text="跟随尾部", variable=self.follow_var, command=self._follow_changed
        ).grid(row=0, column=7, sticky="w", padx=(0, 10))

        ttk.Separator(secondary, orient="vertical").grid(row=0, column=8, sticky="ns", padx=(0, 10))
        ttk.Label(secondary, text="快翻页").grid(row=0, column=9, sticky="w")
        self.quick_pages_spin = ttk.Spinbox(
            secondary, from_=1, to=10000, textvariable=self.quick_pages_var, width=5
        )
        self.quick_pages_spin.grid(row=0, column=10, sticky="w", padx=(6, 5))
        self.quick_back_btn = ttk.Button(secondary, text="快退10页", command=lambda: self._quick_flip(-1), style="Compact.TButton")
        self.quick_back_btn.grid(row=0, column=11, sticky="w")
        self.quick_forward_btn = ttk.Button(secondary, text="快进10页", command=lambda: self._quick_flip(1), style="Compact.TButton")
        self.quick_forward_btn.grid(row=0, column=12, sticky="w", padx=(5, 0))
        self.quick_pages_var.trace_add("write", lambda *_: self._update_quick_buttons())

        self.search_entry.bind("<Return>", lambda e: self.find_active(False))
        self.search_entry.bind("<Shift-Return>", lambda e: self.find_active(True))

    def _bind_keys(self):
        self.root.bind("<Control-o>", lambda e: self.choose_files())
        self.root.bind("<Control-w>", lambda e: self.close_current_tab())
        self.root.bind("<Control-f>", self._focus_search_event)
        self.root.bind("<F3>", lambda e: self.find_active(False))
        self.root.bind("<Shift-F3>", lambda e: self.find_active(True))
        self.root.bind("<Control-m>", lambda e: self.active_call("add_annotation"))
        self.root.bind("<Control-b>", lambda e: self.active_call("add_bookmark_current"))
        self.root.bind("<Control-g>", lambda e: self.active_call("goto_line_dialog"))
        self.root.bind("<F5>", lambda e: self.active_call("refresh_if_needed", True))

    def _show_welcome(self):
        frame = ttk.Frame(self.notebook, padding=30)
        ttk.Label(frame, text="TextStudio 2.0", font=("TkDefaultFont", 18, "bold")).pack(pady=(50, 10))
        dnd_text = (
            "可直接把 .log / .txt / .log.1 文件拖到窗口中打开"
            if HAS_NATIVE_DND else
            "Ctrl+O 打开文件；安装 tkinterdnd2 后可直接拖文件到窗口"
        )
        ttk.Label(
            frame,
            text=f"大文件日志查看 + 标注 + SSH/SFTP 远程浏览\n\n{dnd_text}",
            justify="center"
        ).pack()
        ttk.Button(frame, text="打开文件", command=self.choose_files).pack(pady=18)
        self.notebook.add(frame, text="欢迎")
        self.welcome_frame = frame
        self.register_drop_target(frame)

    def _remove_welcome(self):
        if hasattr(self, "welcome_frame") and str(self.welcome_frame) in self.notebook.tabs():
            self.notebook.forget(self.welcome_frame)

    def register_drop_target(self, widget):
        """Register a widget as a native file drop target when tkDnD is available."""
        if not HAS_NATIVE_DND or widget is None:
            return False
        try:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self._on_file_drop, add="+")
            return True
        except Exception:
            return False

    def _on_file_drop(self, event):
        try:
            paths = list(self.root.tk.splitlist(event.data))
        except Exception:
            paths = [getattr(event, "data", "")]
        opened = self.open_dropped_paths(paths)
        if opened:
            return "copy"
        return None

    def open_dropped_paths(self, paths):
        """Open one or more dropped filesystem paths. Returns number of files opened."""
        opened = 0
        seen = set()
        for raw in paths:
            if raw is None:
                continue
            path = os.path.abspath(os.path.expanduser(str(raw).strip()))
            if not path or path in seen:
                continue
            seen.add(path)

            if os.path.isfile(path):
                self.open_path(path)
                opened += 1
            elif os.path.isdir(path):
                # A dropped directory is intentionally not scanned recursively: that could
                # accidentally open thousands of logs. Open immediate common text files only.
                try:
                    candidates = sorted(
                        p for p in Path(path).iterdir()
                        if p.is_file() and (
                            p.suffix.lower() in (".log", ".txt", ".out", ".err")
                            or ".log." in p.name.lower()
                        )
                    )
                except OSError:
                    candidates = []
                for p in candidates[:100]:
                    self.open_path(str(p))
                    opened += 1
        return opened

    def show_remote_browser(self):
        if self.remote_browser is not None:
            try:
                if self.remote_browser.winfo_exists():
                    self.remote_browser.show_window()
                    return
            except tk.TclError:
                pass
        self.remote_browser = RemoteBrowserDialog(self)

    def _sync_remote_button(self):
        btn = getattr(self, "remote_browser_btn", None)
        if btn is None:
            return
        alive = sum(1 for s in self.remote_sessions if getattr(s, "is_alive", lambda: False)())
        btn.configure(text=f"远程文件({alive})" if alive else "远程文件")

    def register_remote_session(self, session):
        if session not in self.remote_sessions:
            self.remote_sessions.append(session)
        self._sync_remote_button()

    def open_remote_backend(self, backend):
        # Keep the owning SSH session alive even if the browser window is closed.
        # The session is released only when the application exits.
        try:
            self.register_remote_session(backend.session)
        except Exception:
            pass
        identity = backend.identity
        for view in self.views.values():
            if view.path == identity:
                try:
                    backend.close()
                except Exception:
                    pass
                self.notebook.select(view)
                return
        self._remove_welcome()
        try:
            view = DocumentView(self, self.notebook, identity, backend=backend)
        except Exception as e:
            try:
                backend.close()
            except Exception:
                pass
            messagebox.showerror("打开远程文件失败", f"{identity}\n\n{e}", parent=self.root)
            return
        label = f"{safe_basename(backend.path)}@{backend.session.host}"
        self.notebook.add(view, text=label)
        self.views[str(view)] = view
        self.notebook.select(view)
        self.sync_toolbar_from_active()

    def choose_files(self):
        paths = filedialog.askopenfilenames(
            title="打开文本/日志文件",
            filetypes=[
                ("日志/文本", "*.log *.txt *.log.* *.out *.err"),
                ("所有文件", "*.*"),
            ],
        )
        for p in paths:
            self.open_path(p)

    def open_path(self, path: str):
        path = os.path.abspath(path)
        for view in self.views.values():
            if view.path == path:
                self.notebook.select(view)
                return

        self._remove_welcome()
        try:
            view = DocumentView(self, self.notebook, path)
        except Exception as e:
            messagebox.showerror("打开失败", f"{path}\n\n{e}", parent=self.root)
            return
        self.notebook.add(view, text=safe_basename(path))
        self.views[str(view)] = view
        self.notebook.select(view)
        self.sync_toolbar_from_active()

    def active_view(self):
        tab = self.notebook.select()
        return self.views.get(tab)

    def active_call(self, method, *args):
        view = self.active_view()
        if view:
            return getattr(view, method)(*args)

    def close_current_tab(self):
        view = self.active_view()
        if not view:
            return
        key = str(view)
        view.close()
        self.notebook.forget(view)
        self.views.pop(key, None)
        if not self.views:
            self._show_welcome()
        self.sync_toolbar_from_active()

    def _middle_close_tab(self, event):
        try:
            idx = self.notebook.index(f"@{event.x},{event.y}")
            tab_id = self.notebook.tabs()[idx]
            view = self.views.get(tab_id)
            if view:
                self.notebook.select(view)
                self.close_current_tab()
        except Exception:
            pass

    def sync_toolbar_from_active(self):
        view = self.active_view()
        if hasattr(self, "close_tab_btn"):
            self.close_tab_btn.configure(state="normal" if view else "disabled")
        if not view:
            self.follow_var.set(False)
            self.encoding_var.set("自动")
            self.root.title(f"{APP_NAME} {VERSION}")
            return
        self.follow_var.set(view.follow_tail)
        self.encoding_var.set(view.encoding_choice)
        self.regex_var.set(view.regex_mode)
        self.case_var.set(view.case_sensitive)
        if view.search_text:
            self.search_var.set(view.search_text)
        self.root.title(f"{APP_NAME} {VERSION} — {os.path.basename(view.path)}")

    def _encoding_changed(self, _event=None):
        view = self.active_view()
        if view:
            view.set_encoding_choice(self.encoding_var.get())

    def _follow_changed(self):
        view = self.active_view()
        if view:
            view.set_follow_tail(self.follow_var.get())

    def _quick_pages_value(self):
        try:
            return max(1, min(10000, int(self.quick_pages_var.get().strip())))
        except (ValueError, AttributeError):
            return 10

    def _update_quick_buttons(self):
        if not hasattr(self, "quick_back_btn"):
            return
        n = self._quick_pages_value()
        self.quick_back_btn.configure(text=f"快退{n}页")
        self.quick_forward_btn.configure(text=f"快进{n}页")

    def _quick_flip(self, direction):
        view = self.active_view()
        if not view:
            return
        pages = self._quick_pages_value()
        # Normalize invalid typed values when the action is actually used.
        if self.quick_pages_var.get().strip() != str(pages):
            self.quick_pages_var.set(str(pages))
        return view.quick_flip_pages(direction, pages)

    def find_active(self, backwards=False):
        view = self.active_view()
        if view:
            view.find_next(
                backwards=backwards,
                pattern=self.search_var.get(),
                regex_mode=self.regex_var.get(),
                case_sensitive=self.case_var.get()
            )

    def _focus_search_event(self, _event=None):
        self.focus_search()
        return "break"

    def focus_search(self, source_view=None):
        view = source_view or self.active_view()
        # Only pull a selection automatically when Ctrl+F originated in the body
        # text. This avoids an old body selection unexpectedly replacing a query
        # when Ctrl+F is pressed while the search box or another control has focus.
        take_selection = source_view is not None
        if not take_selection and view:
            try:
                take_selection = self.root.focus_get() is view.text
            except tk.TclError:
                take_selection = False
        if view and take_selection:
            try:
                ranges = view.text.tag_ranges("sel")
                if len(ranges) == 2:
                    selected = view.text.get(ranges[0], ranges[1])
                    if selected.strip():
                        self.search_var.set(selected)
            except tk.TclError:
                pass
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, "end")
        self.search_entry.icursor("end")

    def _goto_start(self):
        view = self.active_view()
        if view:
            view.follow_tail = False
            view.render_at(0, line_hint=1, exact_hint=True)
            self.sync_toolbar_from_active()

    def _periodic(self):
        try:
            for view in list(self.views.values()):
                view.periodic()
        finally:
            self.root.after(700, self._periodic)

    def show_shortcuts(self):
        messagebox.showinfo(
            "快捷键",
            "Ctrl+O      打开文件\n"
            "Ctrl+W      关闭当前标签\n"
            "Ctrl+F      搜索（正文有选区时自动带入）\n"
            "F3          下一个匹配\n"
            "Shift+F3    上一个匹配\n"
            "Ctrl+M      标注选中文本\n"
            "Ctrl+B      添加书签\n"
            "Ctrl+G      跳转到行\n"
            "Ctrl+Home   文件开头\n"
            "Ctrl+End    文件末尾\n"
            "PgUp/PgDn   前后翻 1 屏\n"
            "F5          刷新\n"
            "左键点击     记录搜索起点/显示行列与字节\n"
            "双击文字     选中当前单词（含中文/数字/下划线）\n"
            "快翻页数     可自定义快退/快进的屏数\n"
            "鼠标右键    标注 / 书签 / 复制",
            parent=self.root
        )

    def show_about(self):
        messagebox.showinfo(
            "关于 TextMark",
            f"{APP_NAME} {VERSION}\n\n"
            "mmap 本地大文件视口读取 · SSH/SFTP 远程增量跟随 · ProxyJump 跳板 · 后台下载 · 多标签 · 行号 · 标注 · 书签\n"
            "鼠标点位搜索起点 · 自定义快翻页数 · 原生逐显示行滚动 · 窗口自适应换行 · 双击选词\n"
            "ERROR/WARN 自动着色 · 编码检测 · 行/字节跳转 · JSON/CSV/Markdown 导出\n\n"
            "精确行号依赖后台轻量分块索引；打开文件本身不会等待完整索引。",
            parent=self.root
        )

    def on_close(self):
        for view in list(self.views.values()):
            view.close()
        for session in list(self.remote_sessions):
            try:
                session.close()
            except Exception:
                pass
        self.store.close()
        self.root.destroy()


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "sample.log"
        rows = []
        for i in range(25000):
            level = "ERROR" if i % 997 == 0 else ("WARN" if i % 211 == 0 else "INFO")
            rows.append(f"2026-09-01 22:22:{i%60:02d} {level} row={i} hello 世界\n")
        p.write_text("".join(rows), encoding="utf-8")

        b = MappedTextFile(str(p))
        assert b.encoding == "utf-8"
        page, start, end, trunc = b.read_page(0)
        assert len(page) == PAGE_LINES
        assert "row=0" in page[0].text
        hit = b.search_literal("row=1234", 0)
        assert hit is not None

        idx = LazyLineIndex(str(p), b.size, b.mtime_ns, b.newline, b.bom)
        deadline = time.time() + 5
        while not idx.complete and time.time() < deadline:
            time.sleep(0.02)
        assert idx.complete
        assert idx.line_number_at(hit[0], b.mm) == 1235
        off = idx.offset_for_line(20000, b.mm)
        assert off is not None
        page2, *_ = b.read_page(off, max_lines=1)
        assert "row=19999" in page2[0].text

        rhit = regex_search_file(str(p), b.encoding, b.newline, b.bom, r"ERROR\s+row=997", 0, False, True)
        assert rhit is not None
        idx.stop()
        b.close()

        store = AnnotationStore()
        aid = store.add_annotation(str(p), 1, 5, "note", "red", "test")
        bid = store.add_bookmark(str(p), 10, "bm", "excerpt")
        assert any(x["id"] == aid for x in store.list_annotations(str(p)))
        assert any(x["id"] == bid for x in store.list_bookmarks(str(p)))
        store.delete_annotation(aid)
        store.delete_bookmark(bid)
        store.close()

    print("TextMark self-test: OK")
    return 0


def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        return self_test()
    if "-h" in args or "--help" in args:
        print(
            f"TextMark {VERSION}\n"
            "Usage: python3 TextMark.py [file1.log file2.txt ...]\n"
            "       python3 TextMark.py --self-test"
        )
        return 0

    initial = [x for x in args if not x.startswith("-")]
    root = TkinterDnD.Tk() if HAS_NATIVE_DND else tk.Tk()
    TextMarkApp(root, initial)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
