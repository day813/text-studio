#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH/SFTP support for TextStudio.

Uses Paramiko when installed. Remote files are never copied in full: the viewer
reads only byte ranges needed for the current page. Searches and line jumps are
executed on the remote host with python3 when available, with SFTP fallback for
literal searches.
"""
from __future__ import annotations

import base64
import json
import os
import posixpath
import shlex
import stat as statmod
import threading
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import paramiko
    HAS_PARAMIKO = True
except Exception:
    paramiko = None
    HAS_PARAMIKO = False

REMOTE_CACHE_BYTES = 256 * 1024
REMOTE_PREFETCH_BYTES = 128 * 1024
# A second, asynchronous read-ahead cache makes sequential remote browsing feel
# much closer to mmap-backed local files without delaying the initial open.
REMOTE_WARM_CACHE_BYTES = 4 * 1024 * 1024
REMOTE_WARM_CACHE_BACK_BYTES = 1024 * 1024
REMOTE_READV_BLOCK = 64 * 1024
REMOTE_READV_CONCURRENCY = 12
REMOTE_ENCODING_SAMPLE = 32 * 1024
REMOTE_SCAN_CHUNK = 512 * 1024
REMOTE_PAGE_MAX_BYTES = 4 * 1024 * 1024
REMOTE_PAGE_LINES = 240
# Live-follow normally transfers only the bytes appended since the previous poll.
# A very large burst keeps only the newest tail window instead of buffering unbounded data.
REMOTE_LIVE_MAX_APPEND_BYTES = 4 * 1024 * 1024
SESSION_KEEPALIVE_SECONDS = 15
SESSION_WATCHDOG_SECONDS = 12


@dataclass
class RemotePageLine:
    byte_start: int
    byte_end: int
    text: str


def remote_identity(user: str, host: str, port: int, path: str) -> str:
    p = posixpath.normpath(path if path.startswith('/') else '/' + path)
    return f"ssh://{user}@{host}:{int(port)}{p}"


class RemoteSession:
    """Persistent SSH/SFTP session with optional one-hop jump host.

    The target SSH connection is always exposed as ``client``/``sftp``.  When a
    jump host is configured, Paramiko opens a ``direct-tcpip`` channel through
    the jump transport and performs the target SSH handshake over that channel.
    The session keeps transports alive in the background and reconnects lazily
    after a broken/idle connection.
    """
    def __init__(self, host: str, port: int, username: str, password: str = "",
                 key_filename: str = "", trust_first_use: bool = True,
                 timeout: float = 12.0, jump_host: str = "", jump_port: int = 22,
                 jump_username: str = "", jump_password: str = "",
                 jump_key_filename: str = ""):
        if not HAS_PARAMIKO:
            raise RuntimeError(
                "缺少 Paramiko，无法使用 SSH/SFTP。请先运行 install_ubuntu.sh，"
                "或执行：python3 -m pip install paramiko"
            )
        self.host = host.strip()
        self.port = int(port)
        self.username = username.strip()
        self.password = password or None
        self.key_filename = os.path.expanduser(key_filename.strip()) if key_filename.strip() else None
        self.trust_first_use = bool(trust_first_use)
        self.timeout = float(timeout)

        self.jump_host = jump_host.strip()
        self.jump_port = int(jump_port or 22)
        self.jump_username = jump_username.strip()
        self.jump_password = jump_password or None
        self.jump_key_filename = (
            os.path.expanduser(jump_key_filename.strip()) if jump_key_filename.strip() else None
        )
        if self.jump_host and not self.jump_username:
            raise ValueError("使用跳板机时必须填写跳板机用户")

        self.client = None
        self.sftp = None
        self.jump_client = None
        self.jump_channel = None
        self.lock = threading.RLock()
        self._connect_lock = threading.RLock()
        self.closed = False
        self.generation = 0
        self.last_error = ""
        self._watchdog_stop = threading.Event()
        self._connect()
        self._watchdog = threading.Thread(
            target=self._watchdog_loop, daemon=True, name="TextStudioSSHKeepalive"
        )
        self._watchdog.start()

    @property
    def label(self):
        target = f"{self.username}@{self.host}:{self.port}"
        if self.jump_host:
            return f"{target} via {self.jump_username}@{self.jump_host}:{self.jump_port}"
        return target

    @property
    def uses_jump(self):
        return bool(self.jump_host)

    @property
    def jump_label(self):
        if not self.jump_host:
            return ""
        return f"{self.jump_username}@{self.jump_host}:{self.jump_port}"

    def _new_client(self):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        app_known = Path.home() / "textstudio" / "known_hosts"
        app_known.parent.mkdir(parents=True, exist_ok=True)
        if app_known.exists():
            try:
                client.load_host_keys(str(app_known))
            except Exception:
                pass
        if self.trust_first_use:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client, app_known

    def _connect_one(self, host, port, username, password, key_filename, sock=None):
        client, app_known = self._new_client()
        kwargs = dict(
            hostname=host,
            port=int(port),
            username=username,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            allow_agent=True,
            look_for_keys=True,
        )
        if password:
            kwargs["password"] = password
        if key_filename:
            kwargs["key_filename"] = key_filename
        if sock is not None:
            kwargs["sock"] = sock
        client.connect(**kwargs)
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(SESSION_KEEPALIVE_SECONDS)
        if self.trust_first_use:
            try:
                client.save_host_keys(str(app_known))
            except Exception:
                pass
        return client

    def _close_live_objects(self):
        try:
            if self.sftp is not None:
                self.sftp.close()
        except Exception:
            pass
        self.sftp = None
        try:
            if self.client is not None:
                self.client.close()
        except Exception:
            pass
        self.client = None
        try:
            if self.jump_channel is not None:
                self.jump_channel.close()
        except Exception:
            pass
        self.jump_channel = None
        try:
            if self.jump_client is not None:
                self.jump_client.close()
        except Exception:
            pass
        self.jump_client = None

    def _connect(self):
        with self._connect_lock:
            if self.closed:
                raise RuntimeError("SSH 连接已关闭")
            self._close_live_objects()
            try:
                if self.jump_host:
                    self.jump_client = self._connect_one(
                        self.jump_host, self.jump_port, self.jump_username,
                        self.jump_password, self.jump_key_filename
                    )
                    jt = self.jump_client.get_transport()
                    if jt is None or not jt.is_active():
                        raise RuntimeError("跳板机 SSH transport 未建立")
                    self.jump_channel = jt.open_channel(
                        "direct-tcpip", (self.host, self.port), ("127.0.0.1", 0),
                        timeout=self.timeout
                    )
                    self.client = self._connect_one(
                        self.host, self.port, self.username,
                        self.password, self.key_filename, sock=self.jump_channel
                    )
                else:
                    self.client = self._connect_one(
                        self.host, self.port, self.username,
                        self.password, self.key_filename
                    )
                self.sftp = self.client.open_sftp()
                self.generation += 1
                self.last_error = ""
            except Exception:
                self._close_live_objects()
                raise

    def _transport_active(self, client):
        if client is None:
            return False
        try:
            t = client.get_transport()
            return bool(t and t.is_active() and t.is_authenticated())
        except Exception:
            return False

    def is_alive(self):
        if self.closed or not self._transport_active(self.client):
            return False
        if self.jump_host and not self._transport_active(self.jump_client):
            return False
        return True

    def ensure_connected(self, force=False):
        if self.closed:
            raise RuntimeError("SSH 连接已关闭")
        if not force and self.is_alive() and self.sftp is not None:
            return
        with self._connect_lock:
            if not force and self.is_alive() and self.sftp is not None:
                return
            self._connect()

    def _watchdog_loop(self):
        while not self._watchdog_stop.wait(SESSION_WATCHDOG_SECONDS):
            if self.closed:
                return
            try:
                # Paramiko transport keepalive packets are active independently;
                # the watchdog only reconnects if the transport is known dead.
                if not self.is_alive():
                    self.ensure_connected(force=True)
            except Exception as exc:
                self.last_error = str(exc)

    def close(self):
        self.closed = True
        self._watchdog_stop.set()
        with self._connect_lock:
            self._close_live_objects()

    def normalize_path(self, path: str) -> str:
        self.ensure_connected()
        p = path.strip() or "."
        if p.startswith("~"):
            home = self.home_dir()
            if p == "~":
                p = home
            elif p.startswith("~/"):
                p = posixpath.join(home, p[2:])
        if not p.startswith("/"):
            try:
                with self.lock:
                    base = self.sftp.normalize(".")
            except Exception:
                base = "/"
            p = posixpath.join(base, p)
        return posixpath.normpath(p)

    def home_dir(self):
        self.ensure_connected()
        with self.lock:
            return self.sftp.normalize(".")

    def stat(self, path: str):
        for attempt in range(2):
            try:
                self.ensure_connected(force=bool(attempt))
                with self.lock:
                    return self.sftp.stat(path)
            except Exception:
                if attempt:
                    raise

    def lstat(self, path: str):
        for attempt in range(2):
            try:
                self.ensure_connected(force=bool(attempt))
                with self.lock:
                    return self.sftp.lstat(path)
            except Exception:
                if attempt:
                    raise

    def path_kind(self, path: str):
        """Return file kind while following symlinks for activation."""
        try:
            lst = self.lstat(path)
        except Exception as exc:
            raise RuntimeError(f"无法读取远程路径：{path}\n{exc}") from exc
        mode = lst.st_mode
        is_link = statmod.S_ISLNK(mode)
        try:
            st = self.stat(path) if is_link else lst
        except Exception as exc:
            if is_link:
                raise RuntimeError(f"符号链接目标不可访问：{path}\n{exc}") from exc
            raise
        mode2 = st.st_mode
        if statmod.S_ISDIR(mode2):
            return "dirlink" if is_link else "dir"
        if statmod.S_ISREG(mode2):
            return "filelink" if is_link else "file"
        return "otherlink" if is_link else "other"

    def listdir(self, path: str):
        for attempt in range(2):
            try:
                self.ensure_connected(force=bool(attempt))
                with self.lock:
                    attrs = self.sftp.listdir_attr(path)
                break
            except Exception:
                if attempt:
                    raise
        rows = []
        for a in attrs:
            mode = a.st_mode
            if statmod.S_ISDIR(mode):
                typ = "dir"
            elif statmod.S_ISREG(mode):
                typ = "file"
            elif statmod.S_ISLNK(mode):
                # Do not stat every symlink while listing a huge directory.
                # Resolve only when the user activates it.
                typ = "link"
            else:
                typ = "other"
            rows.append({
                "name": a.filename,
                "type": typ,
                "size": int(getattr(a, "st_size", 0) or 0),
                "mtime": int(getattr(a, "st_mtime", 0) or 0),
            })
        order = {"dir": 0, "link": 1, "file": 2, "other": 3}
        rows.sort(key=lambda x: (order.get(x["type"], 9), x["name"].lower()))
        return rows

    def search_paths(self, root_path: str, query: str, recursive: bool = True,
                     max_results: int = 2000, progress_callback=None,
                     cancel_event=None) -> dict:
        """Search remote file/directory names under one directory.

        The scan uses an independent SFTP channel so a large recursive search does
        not block normal browsing, opening files, uploads or downloads on the main
        channel. Symbolic links are returned when their own name matches but are
        never traversed, which avoids directory-link loops.
        """
        root_path = self.normalize_path(root_path)
        term = str(query or "").strip()
        if not term:
            raise ValueError("搜索内容不能为空")
        folded = term.casefold()
        max_results = max(1, int(max_results or 2000))
        sftp = self.open_sftp_channel()
        matches = []
        scanned_dirs = 0
        scanned_items = 0
        skipped_dirs = 0
        truncated = False
        cancelled = False
        last_emit = [0.0]

        def emit(force=False):
            if progress_callback is None:
                return
            now = time.monotonic()
            if not force and now - last_emit[0] < 0.18:
                return
            last_emit[0] = now
            try:
                progress_callback({
                    "phase": "search",
                    "root": root_path,
                    "query": term,
                    "scanned_dirs": scanned_dirs,
                    "scanned_items": scanned_items,
                    "matches": len(matches),
                    "skipped_dirs": skipped_dirs,
                })
            except Exception:
                pass

        try:
            stack = [root_path]
            while stack:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
                current = stack.pop()
                try:
                    attrs = sftp.listdir_attr(current)
                except Exception:
                    skipped_dirs += 1
                    emit()
                    continue
                scanned_dirs += 1
                # Reverse-sort before pushing directories so traversal remains
                # deterministic while using a cheap LIFO stack.
                attrs = sorted(attrs, key=lambda a: str(getattr(a, "filename", "")).casefold())
                child_dirs = []
                for attr in attrs:
                    if cancel_event is not None and cancel_event.is_set():
                        cancelled = True
                        break
                    name = str(getattr(attr, "filename", ""))
                    if not name or name in (".", ".."):
                        continue
                    scanned_items += 1
                    full = posixpath.join(current, name)
                    mode = int(getattr(attr, "st_mode", 0) or 0)
                    if statmod.S_ISDIR(mode):
                        typ = "dir"
                        if recursive:
                            child_dirs.append(full)
                    elif statmod.S_ISREG(mode):
                        typ = "file"
                    elif statmod.S_ISLNK(mode):
                        typ = "link"
                    else:
                        typ = "other"

                    # A plain keyword searches basenames. If the user includes a
                    # slash, treat it as a relative-path query (e.g. logs/2026).
                    rel = posixpath.relpath(full, root_path)
                    target = rel if "/" in term else name
                    if folded in target.casefold():
                        matches.append({
                            "name": name,
                            "type": typ,
                            "size": int(getattr(attr, "st_size", 0) or 0),
                            "mtime": int(getattr(attr, "st_mtime", 0) or 0),
                            "path": full,
                            "relative": rel,
                        })
                        if len(matches) >= max_results:
                            truncated = True
                            break
                    if scanned_items % 128 == 0:
                        emit()
                if cancelled or truncated:
                    break
                if recursive:
                    stack.extend(reversed(child_dirs))
                emit()

            order = {"dir": 0, "link": 1, "file": 2, "other": 3}
            matches.sort(key=lambda row: (
                order.get(row.get("type"), 9),
                str(row.get("relative", "")).casefold(),
            ))
            result = {
                "phase": "cancelled" if cancelled else "done",
                "root": root_path,
                "query": term,
                "recursive": bool(recursive),
                "matches": matches,
                "count": len(matches),
                "scanned_dirs": scanned_dirs,
                "scanned_items": scanned_items,
                "skipped_dirs": skipped_dirs,
                "truncated": truncated,
                "cancelled": cancelled,
                "max_results": max_results,
            }
            emit(force=True)
            return result
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    def open_file(self, path: str):
        return RemoteTextFile(self, self.normalize_path(path))

    @staticmethod
    def _safe_local_name(name: str) -> str:
        """Make one remote path component safe on the local platform."""
        value = str(name or "").replace("\x00", "_").replace("/", "_").replace("\\", "_")
        if os.name == "nt":
            for ch in '<>:"/\\|?*':
                value = value.replace(ch, "_")
            value = value.rstrip(" .")
            reserved = {
                "CON", "PRN", "AUX", "NUL",
                *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }
            if value.split(".", 1)[0].upper() in reserved:
                value = "_" + value
        if value in ("", ".", ".."):
            value = "remote_item"
        return value

    @staticmethod
    def _unique_local_path(path: Path) -> Path:
        if not path.exists():
            return path
        parent = path.parent
        if path.is_dir() or not path.suffix:
            stem, suffix = path.name, ""
        else:
            stem, suffix = path.stem, path.suffix
        for i in range(1, 10000):
            candidate = parent / f"{stem}_{i}{suffix}"
            if not candidate.exists():
                return candidate
        raise RuntimeError(f"本地目录中同名文件过多：{path.name}")

    def download_path(self, remote_path: str, local_root, progress_callback=None) -> dict:
        """Download one remote file/directory into the local TextStudio folder.

        The transfer uses its own SFTP channel, so browsing/opening remote files can
        continue on the main session. Directories are scanned once in the worker
        thread to calculate an accurate byte total for the UI progress bar. Existing
        local items are never overwritten, and directory symlinks are skipped to
        avoid recursive loops.
        """
        remote_path = self.normalize_path(remote_path)
        local_root = Path(local_root).expanduser().resolve()
        local_root.mkdir(parents=True, exist_ok=True)
        sftp = self.open_sftp_channel()
        stats = {"files": 0, "dirs": 0, "bytes": 0, "skipped": 0}
        last_emit = [0.0]

        def emit(payload, force=False):
            if progress_callback is None:
                return
            now = time.monotonic()
            if not force and now - last_emit[0] < 0.08:
                return
            last_emit[0] = now
            try:
                progress_callback(dict(payload))
            except Exception:
                # UI progress must never be able to abort the actual download.
                pass

        plan = []
        total_bytes = 0
        total_files = 0
        scanned_items = 0

        def scan_dir(rpath: str, rel_parts, st=None):
            nonlocal total_bytes, total_files, scanned_items
            plan.append(("dir", rpath, tuple(rel_parts), st))
            for attr in sftp.listdir_attr(rpath):
                name = getattr(attr, "filename", "")
                if not name or name in (".", ".."):
                    continue
                scanned_items += 1
                child_remote = posixpath.join(rpath, name)
                child_rel = tuple(rel_parts) + (name,)
                mode = int(getattr(attr, "st_mode", 0) or 0)
                if statmod.S_ISDIR(mode):
                    scan_dir(child_remote, child_rel, attr)
                elif statmod.S_ISREG(mode):
                    size = int(getattr(attr, "st_size", 0) or 0)
                    total_bytes += max(0, size)
                    total_files += 1
                    plan.append(("file", child_remote, child_rel, attr))
                elif statmod.S_ISLNK(mode):
                    try:
                        target = sftp.stat(child_remote)
                    except Exception:
                        stats["skipped"] += 1
                        continue
                    target_mode = int(getattr(target, "st_mode", 0) or 0)
                    if statmod.S_ISREG(target_mode):
                        size = int(getattr(target, "st_size", 0) or 0)
                        total_bytes += max(0, size)
                        total_files += 1
                        plan.append(("file", child_remote, child_rel, target))
                    else:
                        # Following directory symlinks recursively can loop forever.
                        stats["skipped"] += 1
                else:
                    stats["skipped"] += 1
                emit({
                    "phase": "scan", "items": scanned_items, "files_total": total_files,
                    "total_bytes": total_bytes, "current": child_remote,
                })

        try:
            emit({"phase": "scan", "items": 0, "files_total": 0, "total_bytes": 0, "current": remote_path}, force=True)
            lst = sftp.lstat(remote_path)
            mode = int(getattr(lst, "st_mode", 0) or 0)
            target = sftp.stat(remote_path) if statmod.S_ISLNK(mode) else lst
            target_mode = int(getattr(target, "st_mode", 0) or 0)
            base_name = posixpath.basename(remote_path.rstrip("/")) or "root"
            destination = self._unique_local_path(local_root / self._safe_local_name(base_name))

            if statmod.S_ISDIR(target_mode):
                scan_dir(remote_path, (), target)
            elif statmod.S_ISREG(target_mode):
                total_bytes = max(0, int(getattr(target, "st_size", 0) or 0))
                total_files = 1
                plan.append(("file", remote_path, (), target))
            else:
                raise RuntimeError(f"该远程项不是普通文件或目录：{remote_path}")

            emit({
                "phase": "download", "transferred": 0, "total_bytes": total_bytes,
                "files_done": 0, "files_total": total_files, "current": remote_path,
            }, force=True)

            transferred_base = 0
            files_done = 0
            dir_entries = []
            local_dirs = {}

            if statmod.S_ISDIR(target_mode):
                destination.mkdir(parents=True, exist_ok=False)
                local_dirs[()] = destination

            for kind, rpath, rel_parts, st in plan:
                if kind == "dir":
                    if rel_parts:
                        parent = local_dirs[tuple(rel_parts[:-1])]
                        lpath = self._unique_local_path(
                            parent / self._safe_local_name(rel_parts[-1])
                        )
                        lpath.mkdir(parents=True, exist_ok=False)
                        local_dirs[tuple(rel_parts)] = lpath
                    else:
                        lpath = destination
                        local_dirs[()] = lpath
                    stats["dirs"] += 1
                    dir_entries.append((lpath, st))
                    continue

                if statmod.S_ISDIR(target_mode):
                    parent = local_dirs[tuple(rel_parts[:-1])]
                    lpath = self._unique_local_path(
                        parent / self._safe_local_name(rel_parts[-1])
                    )
                else:
                    lpath = destination
                lpath.parent.mkdir(parents=True, exist_ok=True)
                tmp = lpath.with_name(lpath.name + ".part")
                file_size = max(0, int(getattr(st, "st_size", 0) or 0))

                try:
                    if tmp.exists():
                        tmp.unlink()

                    def on_file_progress(done, _total, *, _base=transferred_base, _rpath=rpath):
                        emit({
                            "phase": "download",
                            "transferred": min(total_bytes, _base + max(0, int(done or 0))),
                            "total_bytes": total_bytes,
                            "files_done": files_done,
                            "files_total": total_files,
                            "current": _rpath,
                        })

                    sftp.get(rpath, str(tmp), callback=on_file_progress)
                    os.replace(str(tmp), str(lpath))
                except Exception:
                    try:
                        if tmp.exists():
                            tmp.unlink()
                    except Exception:
                        pass
                    raise

                try:
                    mtime = int(getattr(st, "st_mtime", 0) or 0)
                    if mtime > 0:
                        os.utime(str(lpath), (mtime, mtime))
                except Exception:
                    pass

                files_done += 1
                transferred_base += file_size
                stats["files"] += 1
                stats["bytes"] += file_size
                emit({
                    "phase": "download", "transferred": min(total_bytes, transferred_base),
                    "total_bytes": total_bytes, "files_done": files_done,
                    "files_total": total_files, "current": rpath,
                }, force=True)

            # Restore directory mtimes after children have been written.
            for lpath, st in reversed(dir_entries):
                if st is None:
                    continue
                try:
                    mtime = int(getattr(st, "st_mtime", 0) or 0)
                    if mtime > 0:
                        os.utime(str(lpath), (mtime, mtime))
                except Exception:
                    pass

            result = {"destination": str(destination), **stats, "total_bytes": total_bytes}
            emit({
                "phase": "done", "transferred": total_bytes, "total_bytes": total_bytes,
                "files_done": files_done, "files_total": total_files,
                "current": remote_path, "destination": str(destination),
            }, force=True)
            return result
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    def upload_files(self, local_paths, remote_dir: str, progress_callback=None) -> dict:
        """Upload local files into one remote directory without blocking browsing.

        A dedicated SFTP channel is used, exactly like background downloads.  For a
        ProxyJump session that channel belongs to the *target* SSH connection, so the
        same method works for both direct SSH and the second-level host behind a jump
        server. Existing remote files are never overwritten; duplicate names receive
        ``_1``, ``_2`` ... suffixes. Each file is first written to a temporary remote
        name and renamed only after a successful transfer, avoiding half-written final
        files if the connection drops.
        """
        paths = [Path(x).expanduser().resolve() for x in (local_paths or [])]
        if not paths:
            raise ValueError("没有选择要上传的本地文件")
        for path in paths:
            if not path.exists():
                raise FileNotFoundError(f"本地文件不存在：{path}")
            if not path.is_file():
                raise RuntimeError(f"当前仅支持上传普通文件：{path}")

        remote_dir = self.normalize_path(remote_dir)
        total_bytes = sum(max(0, int(path.stat().st_size)) for path in paths)
        total_files = len(paths)
        sftp = self.open_sftp_channel()
        last_emit = [0.0]

        def emit(payload, force=False):
            if progress_callback is None:
                return
            now = time.monotonic()
            if not force and now - last_emit[0] < 0.08:
                return
            last_emit[0] = now
            try:
                progress_callback(dict(payload))
            except Exception:
                # UI progress must never interrupt an in-flight SFTP transfer.
                pass

        def unique_name(name, occupied):
            name = str(name or "upload_file").replace("\x00", "_")
            if name in ("", ".", ".."):
                name = "upload_file"
            if name not in occupied:
                occupied.add(name)
                return name
            stem, suffix = posixpath.splitext(name)
            if not stem:
                stem, suffix = name, ""
            for idx in range(1, 10000):
                candidate = f"{stem}_{idx}{suffix}"
                if candidate not in occupied:
                    occupied.add(candidate)
                    return candidate
            raise RuntimeError(f"远程目录中同名文件过多：{name}")

        try:
            dst_stat = sftp.stat(remote_dir)
            if not statmod.S_ISDIR(int(getattr(dst_stat, "st_mode", 0) or 0)):
                raise RuntimeError(f"远程目标不是目录：{remote_dir}")

            occupied = {
                str(getattr(attr, "filename", ""))
                for attr in sftp.listdir_attr(remote_dir)
                if getattr(attr, "filename", "")
            }
            plan = []
            for local_path in paths:
                remote_name = unique_name(local_path.name, occupied)
                plan.append((local_path, posixpath.join(remote_dir, remote_name)))

            emit({
                "phase": "upload", "transferred": 0, "total_bytes": total_bytes,
                "files_done": 0, "files_total": total_files,
                "current": str(paths[0]), "remote_dir": remote_dir,
            }, force=True)

            transferred_base = 0
            files_done = 0
            uploaded = []
            nonce_base = f"textstudio-{os.getpid()}-{threading.get_ident()}"

            for file_index, (local_path, remote_path) in enumerate(plan):
                file_size = max(0, int(local_path.stat().st_size))
                remote_name = posixpath.basename(remote_path)
                tmp_name = f".{remote_name}.{nonce_base}-{file_index}.part"
                while tmp_name in occupied:
                    file_index += 1
                    tmp_name = f".{remote_name}.{nonce_base}-{file_index}.part"
                occupied.add(tmp_name)
                tmp_path = posixpath.join(remote_dir, tmp_name)

                try:
                    def on_file_progress(done, _total, *, _base=transferred_base,
                                         _local=local_path, _remote=remote_path):
                        emit({
                            "phase": "upload",
                            "transferred": min(total_bytes, _base + max(0, int(done or 0))),
                            "total_bytes": total_bytes,
                            "files_done": files_done,
                            "files_total": total_files,
                            "current": str(_local),
                            "remote": _remote,
                            "remote_dir": remote_dir,
                        })

                    sftp.put(str(local_path), tmp_path, callback=on_file_progress, confirm=True)
                    sftp.rename(tmp_path, remote_path)
                    try:
                        st = local_path.stat()
                        sftp.utime(remote_path, (int(st.st_atime), int(st.st_mtime)))
                    except Exception:
                        pass
                except Exception:
                    try:
                        sftp.remove(tmp_path)
                    except Exception:
                        pass
                    raise
                finally:
                    occupied.discard(tmp_name)

                files_done += 1
                transferred_base += file_size
                uploaded.append(remote_path)
                emit({
                    "phase": "upload",
                    "transferred": min(total_bytes, transferred_base),
                    "total_bytes": total_bytes,
                    "files_done": files_done,
                    "files_total": total_files,
                    "current": str(local_path),
                    "remote": remote_path,
                    "remote_dir": remote_dir,
                }, force=True)

            result = {
                "phase": "done", "files": files_done, "bytes": transferred_base,
                "total_bytes": total_bytes, "files_done": files_done,
                "files_total": total_files, "transferred": transferred_base,
                "remote_dir": remote_dir, "uploaded": uploaded,
                "current": str(paths[-1]),
            }
            emit(result, force=True)
            return result
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    def open_sftp_channel(self):
        self.ensure_connected()
        try:
            return self.client.open_sftp()
        except Exception:
            self.ensure_connected(force=True)
            return self.client.open_sftp()

    def exec_python(self, script: str, args, timeout: float = 120.0):
        self.ensure_connected()
        enc = base64.b64encode(script.encode("utf-8")).decode("ascii")
        arg_json = base64.b64encode(json.dumps(list(args), ensure_ascii=False).encode("utf-8")).decode("ascii")
        launcher = (
            "import base64,json,sys;"
            "code=base64.b64decode(sys.argv[1]);"
            "argv=json.loads(base64.b64decode(sys.argv[2]).decode('utf-8'));"
            "sys.argv=['remote']+argv;exec(compile(code,'<textstudio-remote>','exec'))"
        )
        cmd = "python3 -c {} {} {}".format(
            shlex.quote(launcher), shlex.quote(enc), shlex.quote(arg_json)
        )
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        except Exception:
            self.ensure_connected(force=True)
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        try:
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
        finally:
            try:
                stdin.close()
            except Exception:
                pass
        if rc != 0:
            raise RuntimeError(err.strip() or f"远程 python3 执行失败，退出码 {rc}")
        return out.strip()

    def remote_search(self, path: str, pattern: str, encoding: str, newline: bytes,
                      bom: int, start: int, backwards: bool, regex_mode: bool,
                      case_sensitive: bool):
        script = r'''import sys,mmap,re,base64
p,pat64,enc,nlhex,bom_s,start_s,back_s,regex_s,case_s=sys.argv[1:]
pat=base64.b64decode(pat64).decode('utf-8')
nl=bytes.fromhex(nlhex); bom=int(bom_s); start=int(start_s)
back=back_s=='1'; regex_mode=regex_s=='1'; case=case_s=='1'
with open(p,'rb',buffering=0) as f:
    size=f.seek(0,2); f.seek(0)
    if size<=0:
        print(''); raise SystemExit
    mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    try:
        start=max(bom,min(start,size))
        if not regex_mode:
            needle=pat.encode(enc,errors='replace')
            if case:
                pos=mm.rfind(needle,bom,start) if back else mm.find(needle,start,size)
                if pos>=0: print(f'{pos},{pos+len(needle)}')
                else: print('')
                raise SystemExit
            # The default search mode is case-insensitive. For ASCII literals in
            # common log encodings, search the mmap as bytes instead of decoding
            # every chunk and running a Unicode regex. This keeps exact byte
            # offsets and is substantially faster on large remote logs.
            if pat.isascii() and enc.lower().replace('_','-') in ('utf-8','utf8','gb18030','latin-1','latin1'):
                # Build byte alternatives that preserve Python Unicode
                # re.IGNORECASE semantics for ASCII literals, including its
                # four documented non-ASCII simple-case partners (İ, ı, ſ, K).
                norm=enc.lower().replace('_','-')
                special={'i':['İ','ı'],'s':['ſ'],'k':['K']}
                parts=[]; max_span=0
                for ch in pat:
                    if 'a' <= ch.lower() <= 'z' and ch.isalpha():
                        vals=[ch.lower(),ch.upper()]
                        if norm not in ('latin-1','latin1'):
                            vals += special.get(ch.lower(),[])
                        encoded=[]
                        for v in vals:
                            try: bv=v.encode(enc)
                            except Exception: continue
                            if bv not in encoded: encoded.append(bv)
                        max_span += max(len(x) for x in encoded)
                        parts.append(b'(?:'+b'|'.join(re.escape(x) for x in encoded)+b')')
                    else:
                        bv=ch.encode(enc); max_span += len(bv); parts.append(re.escape(bv))
                brx=re.compile(b''.join(parts))
                if not back:
                    m=brx.search(mm,start,size)
                    if m: print(f'{m.start()},{m.end()}')
                    else: print('')
                    raise SystemExit
                CHB=4*1024*1024
                ce=start
                while ce>bom:
                    cs=max(bom,ce-CHB)
                    # Preserve the prior Unicode-regex behavior: a backwards
                    # hit is eligible when its start is before the anchor, even
                    # if the match itself extends a few bytes past the anchor.
                    scan_end=min(size,ce+max(0,max_span-1))
                    last=None
                    for m in brx.finditer(mm,cs,scan_end):
                        if m.start()<ce: last=m
                        else: break
                    if last:
                        print(f'{last.start()},{last.end()}'); raise SystemExit
                    if cs<=bom: break
                    ce=cs
                print(''); raise SystemExit
        flags=0 if case else re.IGNORECASE
        rx=re.compile(pat if regex_mode else re.escape(pat),flags)
        CH=524288
        def align(off):
            off=max(bom,min(off,size))
            if off<=bom:return bom
            if len(nl)==2 and (off-bom)%2: off-=1
            q=mm.rfind(nl,bom,off)
            return bom if q<0 else q+len(nl)
        if not back:
            cs=align(start); first=True
            while cs<size:
                nominal=min(size,cs+CH)
                if nominal<size:
                    q=mm.find(nl,nominal,size); ce=size if q<0 else q+len(nl)
                else: ce=size
                raw=bytes(mm[cs:ce]); txt=raw.decode(enc,errors='replace')
                char_from=0
                if first and start>cs:
                    char_from=len(bytes(mm[cs:start]).decode(enc,errors='replace'))
                m=rx.search(txt,char_from)
                if m:
                    a=cs+len(txt[:m.start()].encode(enc,errors='replace'))
                    hit=len(txt[m.start():m.end()].encode(enc,errors='replace'))
                    print(f'{a},{a+hit}'); raise SystemExit
                if ce>=size: break
                cs=ce; first=False
            print('')
        else:
            limit=start
            q=mm.find(nl,start,size); ce=size if q<0 else q+len(nl)
            while ce>bom:
                cs=align(max(bom,ce-CH))
                raw=bytes(mm[cs:ce]); txt=raw.decode(enc,errors='replace')
                if limit<=cs: lim=0
                elif limit>=ce: lim=len(txt)
                else: lim=len(bytes(mm[cs:limit]).decode(enc,errors='replace'))
                last=None
                for m in rx.finditer(txt):
                    if m.start()<lim: last=m.span()
                    else: break
                if last:
                    a0,b0=last
                    a=cs+len(txt[:a0].encode(enc,errors='replace'))
                    hit=len(txt[a0:b0].encode(enc,errors='replace'))
                    print(f'{a},{a+hit}'); raise SystemExit
                if cs<=bom: break
                ce=cs
            print('')
    finally:
        mm.close()
'''
        pat64 = base64.b64encode(pattern.encode("utf-8")).decode("ascii")
        out = self.exec_python(script, [
            path, pat64, encoding, newline.hex(), str(int(bom)), str(int(start)),
            "1" if backwards else "0", "1" if regex_mode else "0", "1" if case_sensitive else "0"
        ])
        if not out:
            return None
        a, b = out.split(",", 1)
        return int(a), int(b)

    def remote_line_offset(self, path: str, target_line: int, newline: bytes, bom: int):
        script = r'''import sys
p,line_s,nlhex,bom_s=sys.argv[1:]
target=max(1,int(line_s)); nl=bytes.fromhex(nlhex); bom=int(bom_s)
if target==1:
 print(bom); raise SystemExit
need=target-1; pos=bom; carry=b''; count=0
with open(p,'rb',buffering=0) as f:
 f.seek(bom)
 while True:
  chunk=f.read(4*1024*1024)
  if not chunk: print(-1); break
  data=carry+chunk; base=pos-len(carry); start=0
  while True:
   q=data.find(nl,start)
   if q<0: break
   count+=1
   if count==need:
    print(base+q+len(nl)); raise SystemExit
   start=q+len(nl)
  keep=max(0,len(nl)-1); carry=data[-keep:] if keep else b''; pos+=len(chunk)
'''
        out = self.exec_python(script, [path, str(int(target_line)), newline.hex(), str(int(bom))])
        try:
            off = int(out.strip())
        except Exception:
            return None
        return None if off < 0 else off


class RemoteTextFile:
    is_remote = True

    def __init__(self, session: RemoteSession, path: str):
        self.session = session
        self.path = posixpath.normpath(path)
        self.identity = remote_identity(session.username, session.host, session.port, self.path)
        self.size = 0
        self.mtime_ns = 0
        self.encoding = "utf-8"
        self.detected_encoding = "utf-8"
        self.encoding_confidence = "高"
        self.bom = 0
        self.newline = b"\n"
        self.mm = None
        self._fp = None
        self._sftp = None
        self._owns_sftp = False
        self._io_lock = threading.RLock()
        self._cache_start = 0
        self._cache = b""
        self._warm_cache_start = 0
        self._warm_cache = b""
        self._prefetch_lock = threading.RLock()
        self._prefetch_pending = None
        self._prefetch_running = False
        self._prefetch_active_center = None
        self._prefetch_generation = 0
        self._closed = False
        self._last_stat_check = 0.0
        self._last_stat_changed = False
        self._session_generation = -1
        self._open()

    def _open(self):
        self._closed = False
        st = self.session.stat(self.path)
        self.size = int(st.st_size)
        self.mtime_ns = int(getattr(st, "st_mtime", 0) * 1_000_000_000)
        self._open_io_channel()
        self._cache_start = 0
        self._cache = b""
        self._warm_cache_start = 0
        self._warm_cache = b""
        self._detect_encoding()

    def _open_io_channel(self):
        if self._fp is not None:
            try:
                self._fp.close()
            except Exception:
                pass
            self._fp = None
        if self._owns_sftp and self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
        if hasattr(self.session, "open_sftp_channel"):
            self._sftp = self.session.open_sftp_channel()
            self._owns_sftp = True
        else:
            self._sftp = self.session.sftp
            self._owns_sftp = False
        self._fp = self._sftp.open(self.path, "rb")
        self._session_generation = int(getattr(self.session, "generation", 0))

    def close(self):
        self._closed = True
        with self._prefetch_lock:
            self._prefetch_generation += 1
            self._prefetch_pending = None
        with self._io_lock:
            if self._fp is not None:
                try:
                    self._fp.close()
                except Exception:
                    pass
                self._fp = None
            if self._owns_sftp and self._sftp is not None:
                try:
                    self._sftp.close()
                except Exception:
                    pass
            self._sftp = None
            self._owns_sftp = False
            self._cache = b""
            self._warm_cache = b""

    def refresh(self):
        # refresh() reuses the backend object; it is not a final close.
        self._closed = False
        with self._prefetch_lock:
            self._prefetch_generation += 1
            self._prefetch_pending = None
        with self._io_lock:
            if self._fp is not None:
                try:
                    self._fp.close()
                except Exception:
                    pass
                self._fp = None
            if self._owns_sftp and self._sftp is not None:
                try:
                    self._sftp.close()
                except Exception:
                    pass
            self._sftp = None
            self._owns_sftp = False
        self._open()

    @staticmethod
    def _read_from_handle(fp, start: int, length: int) -> bytes:
        """Read a range, using SFTP readv when available to pipeline RTTs."""
        if length <= 0:
            return b""
        start = int(start); length = int(length)
        if length >= REMOTE_READV_BLOCK * 2 and hasattr(fp, "readv"):
            chunks = []
            off = start
            remaining = length
            while remaining > 0:
                n = min(REMOTE_READV_BLOCK, remaining)
                chunks.append((off, n))
                off += n
                remaining -= n
            try:
                try:
                    parts = fp.readv(chunks, max_concurrent_prefetch_requests=REMOTE_READV_CONCURRENCY)
                except TypeError:
                    parts = fp.readv(chunks)
                return b"".join(parts)
            except Exception:
                # Older/limited SFTP servers can reject pipelined requests.
                # Fall back to the universally supported seek/read path.
                pass
        fp.seek(start)
        return fp.read(length)

    def _read_raw(self, start: int, length: int) -> bytes:
        if length <= 0 or self.size <= 0:
            return b""
        start = max(0, min(int(start), self.size))
        length = max(0, min(int(length), self.size - start))
        with self._io_lock:
            last_exc = None
            for attempt in range(2):
                try:
                    generation = int(getattr(self.session, "generation", 0))
                    if self._fp is None or generation != self._session_generation:
                        self._open_io_channel()
                    return self._read_from_handle(self._fp, start, length)
                except Exception as exc:
                    last_exc = exc
                    if attempt:
                        break
                    # The session may have been dropped/reconnected while this
                    # file tab was idle. Reconnect and transparently reopen the
                    # dedicated SFTP file channel once.
                    self.session.ensure_connected(force=True)
                    self._open_io_channel()
            raise last_exc

    def _slice_cached(self, start: int, end: int):
        need = end - start
        if self._cache and self._cache_start <= start and end <= self._cache_start + len(self._cache):
            a = start - self._cache_start
            return self._cache[a:a + need]
        with self._prefetch_lock:
            warm = self._warm_cache
            warm_start = self._warm_cache_start
        if warm and warm_start <= start and end <= warm_start + len(warm):
            a = start - warm_start
            return warm[a:a + need]
        return None

    def is_range_cached(self, start: int, end: int) -> bool:
        start = max(0, min(int(start), self.size))
        end = max(start, min(int(end), self.size))
        return self._slice_cached(start, end) is not None

    def read_bytes(self, start: int, end: int) -> bytes:
        start = max(0, min(int(start), self.size))
        end = max(start, min(int(end), self.size))
        cached = self._slice_cached(start, end)
        if cached is not None:
            return cached
        need = end - start
        if need <= REMOTE_CACHE_BYTES:
            fetch_start = max(0, start - 64 * 1024)
            fetch_len = min(self.size - fetch_start, max(REMOTE_CACHE_BYTES, need + 128 * 1024))
        else:
            fetch_start = start
            fetch_len = need
        data = self._read_raw(fetch_start, fetch_len)
        self._cache_start = fetch_start
        self._cache = data
        a = start - fetch_start
        # Read-ahead happens asynchronously. It never delays this request.
        if need <= REMOTE_SCAN_CHUNK:
            self.prefetch_around(start)
        return data[a:a + need]

    def prefetch_around(self, center: int):
        """Coalesce background read-ahead requests around the newest viewport."""
        if self._closed or self.size <= 0:
            return
        center = max(0, min(int(center), self.size))
        with self._prefetch_lock:
            # Avoid a new request if the warm cache already covers a generous
            # neighborhood around the target.
            ws = self._warm_cache_start
            we = ws + len(self._warm_cache)
            margin = min(REMOTE_PREFETCH_BYTES, max(0, self.size - center))
            if self._warm_cache and ws <= max(0, center - margin) and min(self.size, center + margin) <= we:
                return
            active = self._prefetch_active_center
            if self._prefetch_running and active is not None and abs(center - active) <= REMOTE_PREFETCH_BYTES:
                return
            pending = self._prefetch_pending
            if pending is not None and abs(center - pending[0]) <= REMOTE_PREFETCH_BYTES:
                return
            self._prefetch_generation += 1
            generation = self._prefetch_generation
            self._prefetch_pending = (center, generation)
            if self._prefetch_running:
                return
            self._prefetch_running = True
        threading.Thread(target=self._prefetch_worker, daemon=True,
                         name="TextStudioRemotePrefetch").start()

    def _prefetch_worker(self):
        while True:
            with self._prefetch_lock:
                pending = self._prefetch_pending
                self._prefetch_pending = None
                if pending is None or self._closed:
                    self._prefetch_running = False
                    return
            center, generation = pending
            with self._prefetch_lock:
                self._prefetch_active_center = center
            fetch_start = max(0, center - REMOTE_WARM_CACHE_BACK_BYTES)
            fetch_len = min(REMOTE_WARM_CACHE_BYTES, self.size - fetch_start)
            sftp = fp = None
            try:
                sftp = self.session.open_sftp_channel()
                fp = sftp.open(self.path, "rb")
                data = self._read_from_handle(fp, fetch_start, fetch_len)
            except Exception:
                data = None
            finally:
                try:
                    if fp is not None:
                        fp.close()
                except Exception:
                    pass
                try:
                    if sftp is not None:
                        sftp.close()
                except Exception:
                    pass
            with self._prefetch_lock:
                if self._prefetch_active_center == center:
                    self._prefetch_active_center = None
                if data is not None:
                    # A newer request supersedes stale data. Keeping only the
                    # newest window avoids memory growth while seeking around.
                    if generation == self._prefetch_generation and not self._closed:
                        self._warm_cache_start = fetch_start
                        self._warm_cache = data
            # Loop once more if a newer request arrived while I/O was running.

    def _detect_encoding(self):
        if self.size <= 0:
            self.encoding = self.detected_encoding = "utf-8"
            self.encoding_confidence = "高"
            self.bom, self.newline = 0, b"\n"
            return
        # A small sample is enough for BOM/UTF-8/GB18030 detection.  It is
        # fetched through the viewport cache so opening a huge remote file does
        # not immediately transfer megabytes twice.
        sample = self.read_bytes(0, min(self.size, REMOTE_ENCODING_SAMPLE))
        if sample.startswith(b"\xef\xbb\xbf"):
            self.encoding = self.detected_encoding = "utf-8"; self.encoding_confidence = "高(BOM)"; self.bom=3; self.newline=b"\n"; return
        if sample.startswith(b"\xff\xfe"):
            self.encoding = self.detected_encoding = "utf-16-le"; self.encoding_confidence = "高(BOM)"; self.bom=2; self.newline=b"\n\x00"; return
        if sample.startswith(b"\xfe\xff"):
            self.encoding = self.detected_encoding = "utf-16-be"; self.encoding_confidence = "高(BOM)"; self.bom=2; self.newline=b"\x00\n"; return
        if len(sample) >= 16:
            le_nl=sample.count(b"\n\x00"); be_nl=sample.count(b"\x00\n")
            even=sample[0::2]; odd=sample[1::2]
            even_nul=even.count(0)/max(1,len(even)); odd_nul=odd.count(0)/max(1,len(odd))
            if (le_nl>=2 and le_nl>=be_nl*3) or (odd_nul>0.10 and odd_nul>even_nul*3):
                self.encoding=self.detected_encoding="utf-16-le"; self.encoding_confidence="中"; self.bom=0; self.newline=b"\n\x00"; return
            if (be_nl>=2 and be_nl>=le_nl*3) or (even_nul>0.10 and even_nul>odd_nul*3):
                self.encoding=self.detected_encoding="utf-16-be"; self.encoding_confidence="中"; self.bom=0; self.newline=b"\x00\n"; return
        try:
            sample.decode("utf-8")
            self.encoding=self.detected_encoding="utf-8"; self.encoding_confidence="高"; self.bom=0; self.newline=b"\n"; return
        except UnicodeDecodeError:
            pass
        try:
            sample.decode("gb18030")
            self.encoding=self.detected_encoding="gb18030"; self.encoding_confidence="中"; self.bom=0; self.newline=b"\n"; return
        except UnicodeDecodeError:
            self.encoding=self.detected_encoding="latin-1"; self.encoding_confidence="低"; self.bom=0; self.newline=b"\n"

    def set_encoding(self, encoding: str):
        self.encoding = encoding
        head = self.read_bytes(0, min(3, self.size)) if self.size else b""
        self.bom = 3 if encoding == "utf-8" and head.startswith(b"\xef\xbb\xbf") else 0
        if encoding == "utf-16-le":
            self.bom = 2 if head.startswith(b"\xff\xfe") else 0; self.newline = b"\n\x00"
        elif encoding == "utf-16-be":
            self.bom = 2 if head.startswith(b"\xfe\xff") else 0; self.newline = b"\x00\n"
        else:
            self.newline = b"\n"

    def _floor(self):
        return self.bom if self.size >= self.bom else 0

    def align_line_start(self, offset: int) -> int:
        if self.size <= 0:
            return 0
        floor = self._floor(); offset=max(floor,min(int(offset),self.size))
        if offset <= floor:
            return floor
        if len(self.newline)==2 and (offset-floor)%2:
            offset -= 1
        end=offset; chunk=64*1024
        while end>floor:
            begin=max(floor,end-chunk)
            raw=self.read_bytes(begin,end)
            q=raw.rfind(self.newline)
            if q>=0:
                return begin+q+len(self.newline)
            end=begin
            if chunk < 1024*1024:
                chunk *= 2
        return floor

    def line_end_after(self, offset: int) -> int:
        if self.size <= 0:
            return 0
        pos=max(self._floor(),min(int(offset),self.size)); chunk=128*1024
        while pos<self.size:
            end=min(self.size,pos+chunk); raw=self.read_bytes(pos,end); q=raw.find(self.newline)
            if q>=0: return pos+q+len(self.newline)
            pos=end
        return self.size

    def move_lines_count(self, start: int, delta: int):
        if self.size <= 0 or delta == 0:
            return self.align_line_start(start), 0
        floor=self._floor(); pos=self.align_line_start(start); nl=self.newline; nllen=len(nl); moved=0
        if delta>0:
            remaining=delta
            while remaining>0 and pos<self.size:
                end=min(self.size,pos+REMOTE_SCAN_CHUNK); raw=self.read_bytes(pos,end); cur=0
                while remaining>0:
                    q=raw.find(nl,cur)
                    if q<0: break
                    pos=pos+q+nllen; moved+=1; remaining-=1
                    raw=raw[q+nllen:]; cur=0
                    if remaining==0 or pos>=self.size: return pos,moved
                if end>=self.size: return self.align_line_start(self.size),moved
                pos=end
            return min(pos,self.size),moved
        remaining=-delta
        while remaining>0 and pos>floor:
            end=pos; begin=max(floor,end-REMOTE_SCAN_CHUNK); raw=self.read_bytes(begin,end)
            # Exclude the newline immediately before pos: that newline starts the current line.
            search_end=max(0,len(raw)-nllen)
            while remaining>0:
                q=raw.rfind(nl,0,search_end)
                if q<0: break
                pos=begin+q+nllen; moved-=1; remaining-=1
                search_end=q
                if remaining==0: return pos,moved
            if begin<=floor:
                if remaining>0 and pos>floor:
                    pos=floor; moved-=1; remaining-=1
                return pos,moved
            pos=begin
        return pos,moved

    def read_page(self, start: int, max_lines: int = REMOTE_PAGE_LINES, max_bytes: int = REMOTE_PAGE_MAX_BYTES):
        if self.size <= 0:
            return [RemotePageLine(0,0,"")],0,0,False
        start=self.align_line_start(start); start=max(self._floor(),start)
        fetch=min(max_bytes,max(128*1024,min(REMOTE_PREFETCH_BYTES,self.size-start)))
        raw=self.read_bytes(start,min(self.size,start+fetch))
        # Extend only for unusually long lines. Normal logs usually render from
        # the first 512 KiB cache fill, so first paint is independent of total
        # remote file size.
        while raw.count(self.newline) < max_lines and start+len(raw)<self.size and len(raw)<max_bytes:
            more_end=min(self.size,start+min(max_bytes,len(raw)+512*1024))
            raw=self.read_bytes(start,more_end)
        lines=[]; pos=0; absolute=start; nl=self.newline; nllen=len(nl); truncated=False
        for _ in range(max_lines):
            if pos>len(raw): break
            q=raw.find(nl,pos)
            if q<0:
                q=len(raw); next_pos=len(raw)
            else:
                next_pos=q+nllen
            if q==len(raw) and start+q<self.size and len(raw)>=max_bytes:
                truncated=True
            content_start=absolute+pos; content_end=absolute+q
            chunk=raw[pos:q]
            if content_start==0 and self.bom:
                cut=min(self.bom,len(chunk)); chunk=chunk[cut:]; content_start+=cut
            if self.encoding in ("utf-8","gb18030","latin-1") and chunk.endswith(b"\r"):
                chunk=chunk[:-1]; content_end-=1
            elif self.encoding=="utf-16-le" and chunk.endswith(b"\r\x00"):
                chunk=chunk[:-2]; content_end-=2
            elif self.encoding=="utf-16-be" and chunk.endswith(b"\x00\r"):
                chunk=chunk[:-2]; content_end-=2
            lines.append(RemotePageLine(content_start,content_end,chunk.decode(self.encoding,errors="replace")))
            if q>=len(raw):
                break
            pos=next_pos
            if absolute+pos>=self.size: break
        page_end=min(self.size,start+pos if pos else start+len(raw))
        if lines and page_end < lines[-1].byte_end:
            page_end=lines[-1].byte_end
        return lines,start,page_end,truncated

    def search(self, pattern: str, start: int, backwards: bool, regex_mode: bool, case_sensitive: bool):
        try:
            return self.session.remote_search(
                self.path, pattern, self.encoding, self.newline, self.bom,
                start, backwards, regex_mode, case_sensitive
            )
        except Exception:
            # If remote python3 is unavailable, keep the feature working by
            # scanning SFTP chunks. This can transfer more data but never SCPs
            # or materializes the whole file locally.
            return self._search_sftp(pattern, start, backwards, regex_mode, case_sensitive)

    def _search_sftp(self, pattern: str, start: int, backwards: bool,
                     regex_mode: bool, case_sensitive: bool):
        import re
        start=max(self.bom,min(int(start),self.size))
        if (not regex_mode) and case_sensitive:
            needle=pattern.encode(self.encoding,errors="replace")
            if not needle: return None
            overlap=max(0,len(needle)-1)
            if backwards:
                pos=start
                while pos>self.bom:
                    begin=max(self.bom,pos-REMOTE_SCAN_CHUNK)
                    raw=self.read_bytes(begin,pos)
                    q=raw.rfind(needle)
                    if q>=0: return begin+q,begin+q+len(needle)
                    if begin<=self.bom: break
                    pos=begin+overlap
                return None
            pos=start
            while pos<self.size:
                end=min(self.size,pos+REMOTE_SCAN_CHUNK)
                raw=self.read_bytes(pos,end); q=raw.find(needle)
                if q>=0: return pos+q,pos+q+len(needle)
                if end>=self.size: break
                pos=max(pos+1,end-overlap)
            return None

        flags=0 if case_sensitive else re.IGNORECASE
        rx=re.compile(pattern if regex_mode else re.escape(pattern),flags)
        if not backwards:
            chunk_start=self.align_line_start(start); first=True
            while chunk_start<self.size:
                nominal=min(self.size,chunk_start+REMOTE_SCAN_CHUNK)
                chunk_end=self.line_end_after(nominal) if nominal<self.size else self.size
                raw=self.read_bytes(chunk_start,chunk_end)
                text=raw.decode(self.encoding,errors="replace")
                char_from=0
                if first and start>chunk_start:
                    char_from=len(self.read_bytes(chunk_start,start).decode(self.encoding,errors="replace"))
                m=rx.search(text,char_from)
                if m:
                    a=chunk_start+len(text[:m.start()].encode(self.encoding,errors="replace"))
                    hit=len(text[m.start():m.end()].encode(self.encoding,errors="replace"))
                    return a,a+hit
                if chunk_end>=self.size: return None
                chunk_start=chunk_end; first=False
            return None

        search_limit=start
        chunk_end=self.line_end_after(start) if start<self.size else self.size
        while chunk_end>self.bom:
            nominal=max(self.bom,chunk_end-REMOTE_SCAN_CHUNK)
            chunk_start=self.align_line_start(nominal)
            raw=self.read_bytes(chunk_start,chunk_end)
            text=raw.decode(self.encoding,errors="replace")
            if search_limit<=chunk_start: limit_char=0
            elif search_limit>=chunk_end: limit_char=len(text)
            else: limit_char=len(self.read_bytes(chunk_start,search_limit).decode(self.encoding,errors="replace"))
            last=None
            for m in rx.finditer(text):
                if m.start()<limit_char: last=m.span()
                else: break
            if last:
                a0,b0=last
                a=chunk_start+len(text[:a0].encode(self.encoding,errors="replace"))
                hit=len(text[a0:b0].encode(self.encoding,errors="replace"))
                return a,a+hit
            if chunk_start<=self.bom: return None
            chunk_end=chunk_start
        return None

    def poll_live_update(self, expected_size: int, expected_mtime_ns: int,
                         include_append: bool = False,
                         max_append_bytes: int = REMOTE_LIVE_MAX_APPEND_BYTES):
        """Check one remote file revision without touching GUI state.

        This method is designed to run in a background thread. For normal log
        appends it optionally reads exactly ``old_size:new_size`` through a
        dedicated SFTP channel, leaving the viewer's main file handle untouched.
        """
        old_size = max(0, int(expected_size))
        old_mtime = int(expected_mtime_ns or 0)
        st = self.session.stat(self.path)
        new_size = max(0, int(getattr(st, "st_size", 0) or 0))
        new_mtime = int(getattr(st, "st_mtime", 0) * 1_000_000_000)
        result = {
            "expected_size": old_size, "expected_mtime_ns": old_mtime,
            "new_size": new_size, "mtime_ns": new_mtime, "data": None,
        }

        if new_size == old_size and new_mtime == old_mtime:
            result["kind"] = "none"
            return result
        if new_size < old_size:
            result["kind"] = "reset"
            return result
        if new_size == old_size:
            result["kind"] = "rewrite"
            return result

        append_size = new_size - old_size
        result["kind"] = "append"
        result["append_size"] = append_size
        if not include_append:
            return result

        read_start = old_size
        read_size = append_size
        if append_size > max(1, int(max_append_bytes)):
            # A burst larger than the live buffer does not need to be transferred
            # in full just to show the current tail. Fetch only the newest warm
            # cache window; it is still strictly a range inside newly appended data.
            result["kind"] = "append_large"
            read_size = min(REMOTE_WARM_CACHE_BYTES, append_size)
            read_start = new_size - read_size
        result["data_start"] = read_start

        sftp = fp = None
        try:
            sftp = self.session.open_sftp_channel()
            fp = sftp.open(self.path, "rb")
            data = self._read_from_handle(fp, read_start, read_size)
            if len(data) != read_size:
                # The file changed again (commonly rotation/truncation) during
                # the read. Ignore this sample and let the next poll settle it.
                result["kind"] = "stale"
                result["data"] = None
            else:
                result["data"] = data
            return result
        finally:
            try:
                if fp is not None:
                    fp.close()
            except Exception:
                pass
            try:
                if sftp is not None:
                    sftp.close()
            except Exception:
                pass

    @staticmethod
    def _extend_live_cache(cache_start: int, cache: bytes, old_size: int,
                           new_size: int, appended: bytes, limit: int):
        if not appended:
            return cache_start, cache
        cache_start = int(cache_start)
        cache = bytes(cache or b"")
        if cache and cache_start + len(cache) == old_size:
            merged = cache + appended
            merged_start = cache_start
        else:
            merged = appended
            merged_start = old_size
        if len(merged) > limit:
            cut = len(merged) - limit
            merged = merged[cut:]
            merged_start += cut
        # Keep the end aligned with the accepted remote EOF.
        if merged_start + len(merged) > new_size:
            merged = merged[:max(0, new_size - merged_start)]
        return merged_start, merged

    def apply_live_update(self, update) -> bool:
        """Accept metadata/append bytes produced by :meth:`poll_live_update`."""
        expected = int(update.get("expected_size", -1))
        new_size = int(update.get("new_size", expected))
        new_mtime = int(update.get("mtime_ns", self.mtime_ns))
        data = update.get("data")
        data_start = int(update.get("data_start", expected))
        if self._closed or int(self.size) != expected:
            return False

        old_size = int(self.size)
        self.size = max(0, new_size)
        self.mtime_ns = new_mtime
        self._last_stat_check = time.monotonic()
        self._last_stat_changed = False

        if data is not None and new_size >= old_size:
            data = bytes(data)
            with self._prefetch_lock:
                # Supersede prefetches based on the old EOF, then extend the
                # in-memory tail cache with only the newly transferred bytes.
                self._prefetch_generation += 1
                self._prefetch_pending = None
                if data_start == old_size:
                    self._warm_cache_start, self._warm_cache = self._extend_live_cache(
                        self._warm_cache_start, self._warm_cache, old_size, new_size,
                        data, REMOTE_WARM_CACHE_BYTES
                    )
                else:
                    # Large burst: the worker supplied a ready-to-use tail window.
                    keep = data[-REMOTE_WARM_CACHE_BYTES:]
                    self._warm_cache_start = new_size - len(keep)
                    self._warm_cache = keep
            if data_start == old_size:
                self._cache_start, self._cache = self._extend_live_cache(
                    self._cache_start, self._cache, old_size, new_size,
                    data, max(REMOTE_CACHE_BYTES * 2, 512 * 1024)
                )
            else:
                keep = data[-max(REMOTE_CACHE_BYTES * 2, 512 * 1024):]
                self._cache_start = new_size - len(keep)
                self._cache = keep
        return True

    def ends_with_newline(self):
        n=len(self.newline)
        return self.size>=n and self.read_bytes(self.size-n,self.size)==self.newline

    def has_changed(self):
        now=time.monotonic()
        if now-self._last_stat_check < 1.8:
            return self._last_stat_changed
        self._last_stat_check=now
        try:
            st=self.session.stat(self.path)
            size=int(st.st_size); mt=int(getattr(st,"st_mtime",0)*1_000_000_000)
            self._last_stat_changed=(size!=self.size or mt!=self.mtime_ns)
            return self._last_stat_changed
        except Exception:
            return False

    def offset_for_line(self, line: int):
        return self.session.remote_line_offset(self.path, line, self.newline, self.bom)


class RemoteLineIndex:
    """Lightweight line estimator for remote files; exact line jumps run remotely."""
    def __init__(self, backend: RemoteTextFile):
        self.backend=backend
        self.avg_bytes_per_line=96.0
        self.complete=False
        self.error=None
        self._exact={backend.bom:1}
    def stop(self): pass
    def snapshot(self): return (0,False,0,self.error)
    def progress(self): return 0.0
    def line_number_at(self, offset, _mm=None): return self._exact.get(int(offset))
    def approximate_line_number(self, offset): return max(1,int(max(0,int(offset)-self.backend.bom)/max(1.0,self.avg_bytes_per_line))+1)
    def observe(self,start,lines,end,line_hint=None,exact=False):
        if lines and end>start:
            sample=(end-start)/max(1,len(lines)); self.avg_bytes_per_line=self.avg_bytes_per_line*0.75+sample*0.25
        if exact and line_hint is not None: self._exact[int(start)]=int(line_hint)
    def offset_for_line(self,line,_mm=None):
        off=self.backend.offset_for_line(int(line))
        if off is not None: self._exact[int(off)]=int(line)
        return off
    def extend_if_append(self,*_a,**_k): return False
    def reset(self,*_a,**_k): self._exact={self.backend.bom:1}
