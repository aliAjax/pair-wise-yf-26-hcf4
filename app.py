"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024
# 服务端主副本 + 两个离线存储库，销毁申请要求三个存储点齐备。
STORAGE_POINT_COUNT = 3
PRIMARY_LOCATION = "server-primary"


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code
        self.payload: dict | None = None


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        encoded = item.get("content_b64")
        if not isinstance(encoded, str):
            raise BusinessError(f"{raw_path} 缺少 content_b64", 422, "content_required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BusinessError(f"{raw_path} 不是合法 Base64", 422, "invalid_base64")
        if len(content) > MAX_FILE_SIZE:
            raise BusinessError(f"{raw_path} 超过单文件大小限制", 413, "file_too_large")
        result.append(
            {"path": raw_path, "content": content, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return result


class PreservationStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        # 销毁执行串行化：同一时刻全库只有一个销毁执行在推进各存储点。
        self._destroy_lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init_schema(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
                );
                CREATE TABLE IF NOT EXISTS archives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL REFERENCES users(id),
                    retention_until TEXT NOT NULL,
                    restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archive_members(
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    permission TEXT NOT NULL CHECK(permission IN ('read','write')),
                    PRIMARY KEY(archive_id,user_id)
                );
                CREATE TABLE IF NOT EXISTS archive_versions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded','destroyed')),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(archive_id,version)
                );
                CREATE TABLE IF NOT EXISTS archive_files(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    UNIQUE(version_id,path)
                );
                CREATE TABLE IF NOT EXISTS copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded','destroyed')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    UNIQUE(version_id,location)
                );
                CREATE TABLE IF NOT EXISTS copy_files(
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY(copy_id,path)
                );
                CREATE TABLE IF NOT EXISTS migrations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    source_path TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    target_format TEXT NOT NULL,
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS destruction_jobs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    reason TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('in_progress','completed')),
                    requested_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS destruction_items(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL REFERENCES destruction_jobs(id),
                    copy_id INTEGER REFERENCES copies(id),
                    location TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('primary','offline')),
                    state TEXT NOT NULL CHECK(state IN ('pending','done','failed')),
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT,
                    UNIQUE(job_id,location)
                );
                CREATE TABLE IF NOT EXISTS destruction_records(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL UNIQUE REFERENCES destruction_jobs(id),
                    record_no TEXT NOT NULL UNIQUE,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    point_count INTEGER NOT NULL,
                    manifest TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS storage_faults(
                    location TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    set_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def seed(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name,role) VALUES(?,?,?)",
                [
                    ("owner", "机构档案负责人", "owner"),
                    ("archivist", "档案管理员", "archivist"),
                    ("auditor", "独立审计员", "auditor"),
                    ("outsider", "未授权访客", "auditor"),
                ],
            )

    def _user(self, conn, user_id: str | None, roles: set[str] | None = None) -> sqlite3.Row:
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在", 401, "unknown_user")
        if roles and user["role"] not in roles:
            raise BusinessError("当前角色无权执行此操作", 403, "forbidden")
        return user

    def _access(self, conn, archive_id: int, user: sqlite3.Row, require_write: bool = False) -> None:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        if archive["owner_id"] == user["id"]:
            return
        row = conn.execute(
            "SELECT permission FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone()
        if not row or (require_write and row["permission"] != "write"):
            raise BusinessError("没有该受限档案的访问权限", 403, "forbidden")

    def _audit(self, conn, archive_id: int, actor: str, action: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def _active_destroy_job(self, conn, archive_id: int) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM destruction_jobs WHERE archive_id=? AND state='in_progress' ORDER BY id",
            (archive_id,),
        ).fetchone()

    def _guard_archive_writable(self, conn, archive_id: int) -> None:
        """销毁申请执行期间串行挡住同档案的一切上传/写入。"""
        job = self._active_destroy_job(conn, archive_id)
        if job:
            raise BusinessError(
                f"档案存在进行中的销毁申请(job {job['id']})，上传/写入被阻塞", 409, "destruction_in_progress"
            )

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create", {"retention_until": retention_until, "restricted": restricted})
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted}

    def grant(self, actor_id: str, archive_id: int, user_id: str, permission: str) -> dict:
        if permission not in {"read", "write"}:
            raise BusinessError("permission 必须是 read 或 write", 422, "invalid_permission")
        with self.connect() as conn:
            actor = self._user(conn, actor_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["owner_id"] != actor_id:
                raise BusinessError("只有档案所有者可以授权", 403, "forbidden")
            self._user(conn, user_id)
            conn.execute(
                """INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,?)
                   ON CONFLICT(archive_id,user_id) DO UPDATE SET permission=excluded.permission""",
                (archive_id, user_id, permission),
            )
            self._audit(conn, archive_id, actor_id, "access.grant", {"user_id": user_id, "permission": permission})
            return {"archive_id": archive_id, "user_id": user_id, "permission": permission}

    def ingest_version(self, actor_id: str, archive_id: int, files: object) -> dict:
        manifest = verify_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            self._guard_archive_writable(conn, archive_id)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (archive_id, version_no, actor_id, now()),
                )
                version_id = cur.lastrowid
                for item in manifest:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (version_id, item["path"], item["sha256"], item["size"], item["content"]),
                    )
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            self._guard_archive_writable(conn, version["archive_id"])
            if version["state"] == "destroyed":
                raise BusinessError("版本已销毁，不能再创建副本", 409, "version_destroyed")
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,created_at,last_verified_at) VALUES(?,?,?,?)",
                    (version_id, location, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create", {"copy_id": copy_id, "version_id": version_id, "location": location})
                return {"id": copy_id, "version_id": version_id, "location": location, "state": "healthy"}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            except Exception:
                conn.rollback()
                raise

    def get_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            files = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,)
            ).fetchall()
            copies = conn.execute(
                "SELECT id,location,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            job = conn.execute(
                "SELECT id,state,reason,requested_by,created_at,completed_at FROM destruction_jobs WHERE version_id=?",
                (version_id,),
            ).fetchone()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files],
                    "copies": [dict(x) for x in copies],
                    "destruction_job": dict(job) if job else None}

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                if copy["state"] == "destroyed":
                    self._audit(conn, version["archive_id"], user_id, "copy.verify",
                                {"copy_id": copy_id, "state": "destroyed", "skipped": True})
                    return {"copy_id": copy_id, "state": "destroyed", "corrupt_paths": [], "repaired": False}
                stored = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (copy_id,)
                ).fetchall()
                corrupt_paths = [r["path"] for r in stored if hashlib.sha256(r["content"]).hexdigest() != r["sha256"] or len(r["content"]) != r["size"]]
                repaired = False
                if not corrupt_paths:
                    conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                    result_state = "healthy"
                else:
                    conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                    healthy = conn.execute(
                        "SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                        (copy["version_id"], copy_id),
                    ).fetchone()
                    result_state = "degraded"
                    if healthy:
                        donor = conn.execute(
                            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                        ).fetchall()
                        donor_by_path = {r["path"]: r for r in donor}
                        expected = {r["path"]: r for r in conn.execute(
                            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                        ).fetchall()}
                        if set(donor_by_path) == set(expected) and all(
                            hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected[p]["sha256"] for p in expected
                        ):
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                            conn.execute(
                                """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                   SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                (copy_id, healthy["id"]),
                            )
                            conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                            repaired, result_state = True, "healthy"
                    if result_state == "degraded":
                        conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired}
            except Exception:
                conn.rollback()
                raise

    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            if copy["state"] == "destroyed" or version["state"] == "destroyed":
                raise BusinessError("副本/版本已销毁，不能再注入介质故障", 409, "version_destroyed")
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
            self._guard_archive_writable(conn, source_version["archive_id"])
            if source_version["state"] == "destroyed":
                raise BusinessError("源版本已销毁，不能迁移", 409, "version_destroyed")
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now()),
                )
                target_version_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO archive_files(version_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files
                       WHERE version_id=? AND path<>?""",
                    (target_version_id, version_id, source_path),
                )
                conn.execute(
                    "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                    (target_version_id, converted["path"], converted["sha256"], converted["size"], converted["content"]),
                )
                conn.execute(
                    "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (version_id, target_version_id, source_path, converted["path"], target_format.strip(), actor_id, now()),
                )
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip()},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id, "target_path": converted["path"]}
            except Exception:
                conn.rollback()
                raise

    def request_destruction(self, actor_id: str, version_id: int, reason: str) -> dict:
        reason = reason.strip()
        if not reason:
            raise BusinessError("销毁理由不能为空", 422, "reason_required")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            if version["state"] == "destroyed":
                raise BusinessError("版本已销毁，不能重复申请", 409, "version_destroyed")
            existing = conn.execute(
                "SELECT id,state FROM destruction_jobs WHERE version_id=?", (version_id,)
            ).fetchone()
            if existing:
                raise BusinessError(
                    f"该版本已存在销毁申请(job {existing['id']}, {existing['state']})", 409, "destruction_job_exists"
                )
            self._guard_archive_writable(conn, version["archive_id"])
            copies = conn.execute(
                "SELECT id,location,state FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            if len(copies) + 1 != STORAGE_POINT_COUNT:
                raise BusinessError(
                    f"销毁申请要求 {STORAGE_POINT_COUNT} 个存储点（服务端主副本 + {STORAGE_POINT_COUNT - 1} 个离线副本），"
                    f"当前只有 {len(copies) + 1} 个", 409, "storage_topology_invalid"
                )
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO destruction_jobs(version_id,archive_id,reason,state,requested_by,created_at)"
                    " VALUES(?,?,?, 'in_progress',?,?)",
                    (version_id, version["archive_id"], reason, actor_id, now()),
                )
                job_id = cur.lastrowid
                # 三个存储点一起进入待销毁(pending)；离线库先行，服务端主副本最后销毁，
                # 这样主副本在销毁账目落账前始终保留，可作为兜底。
                for cp in copies:
                    conn.execute(
                        "INSERT INTO destruction_items(job_id,copy_id,location,kind,state)"
                        " VALUES(?,?,?, 'offline','pending')",
                        (job_id, cp["id"], cp["location"]),
                    )
                conn.execute(
                    "INSERT INTO destruction_items(job_id,copy_id,location,kind,state)"
                    " VALUES(?,NULL,?, 'primary','pending')",
                    (job_id, PRIMARY_LOCATION),
                )
                points = [r["location"] for r in copies] + [PRIMARY_LOCATION]
                self._audit(conn, version["archive_id"], actor_id, "destruction.request",
                            {"job_id": job_id, "version_id": version_id, "reason": reason, "points": points})
                return {"job_id": job_id, "version_id": version_id, "state": "in_progress", "points": points}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本已存在销毁申请", 409, "destruction_job_exists")
            except Exception:
                conn.rollback()
                raise

    def get_destruction_job(self, user_id: str, job_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            job = conn.execute("SELECT * FROM destruction_jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise BusinessError("销毁申请不存在", 404, "not_found")
            self._access(conn, job["archive_id"], user)
            items = conn.execute(
                "SELECT id,location,kind,state,error,attempts,updated_at FROM destruction_items"
                " WHERE job_id=? ORDER BY id", (job_id,)
            ).fetchall()
            record = conn.execute(
                "SELECT record_no,point_count,manifest,created_by,created_at FROM destruction_records WHERE job_id=?",
                (job_id,),
            ).fetchone()
            return {
                "job": dict(job),
                "items": [dict(x) for x in items],
                "record": (dict(record) | {"manifest": json.loads(record["manifest"])}) if record else None,
            }

    def run_destruction(self, actor_id: str, job_id: int) -> dict:
        """推进销毁：逐存储点执行，已完成的点绝不重跑；任一点失败立即停下。

        进程内互斥锁保证销毁串行执行；每个存储点独立事务提交，成功状态落库后
        即使进程崩溃，恢复重试也只会处理仍然 pending 的存储点。
        """
        with self._destroy_lock:
            with self.connect() as conn:
                actor = self._user(conn, actor_id, {"owner", "archivist"})
                job = conn.execute("SELECT * FROM destruction_jobs WHERE id=?", (job_id,)).fetchone()
                if not job:
                    raise BusinessError("销毁申请不存在", 404, "not_found")
                self._access(conn, job["archive_id"], actor, require_write=True)
                if job["state"] == "completed":
                    items = conn.execute(
                        "SELECT location,kind,state,attempts FROM destruction_items WHERE job_id=? ORDER BY id",
                        (job_id,),
                    ).fetchall()
                    return {"job_id": job_id, "state": "completed", "already": True, "executed": [],
                            "items": [dict(x) for x in items]}
            executed, failure = [], None
            while failure is None:
                with self.connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    # 重试入口：上一轮 failed 的点在确认本轮可执行后回到 pending。
                    conn.execute(
                        "UPDATE destruction_items SET state='pending',updated_at=? WHERE job_id=? AND state='failed'",
                        (now(), job_id),
                    )
                    item = conn.execute(
                        "SELECT * FROM destruction_items WHERE job_id=? AND state='pending' ORDER BY id LIMIT 1",
                        (job_id,),
                    ).fetchone()
                    if item is None:
                        conn.commit()
                        break
                    job = conn.execute("SELECT * FROM destruction_jobs WHERE id=?", (job_id,)).fetchone()
                    version = conn.execute(
                        "SELECT * FROM archive_versions WHERE id=?", (job["version_id"],)
                    ).fetchone()
                    attempts = item["attempts"] + 1
                    fault = conn.execute(
                        "SELECT reason FROM storage_faults WHERE location=?", (item["location"],)
                    ).fetchone()
                    if fault:
                        message = f"介质故障: {fault['reason']}"
                        conn.execute(
                            "UPDATE destruction_items SET state='failed',error=?,attempts=?,updated_at=? WHERE id=?",
                            (message, attempts, now(), item["id"]),
                        )
                        self._audit(conn, job["archive_id"], actor_id, "destruction.item_failed",
                                    {"job_id": job_id, "location": item["location"], "attempts": attempts, "error": message})
                        conn.commit()
                        failure = {"location": item["location"], "error": message, "attempts": attempts}
                        break
                    manifest_snapshot = None
                    try:
                        if item["kind"] == "offline":
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (item["copy_id"],))
                            conn.execute("UPDATE copies SET state='destroyed',last_verified_at=? WHERE id=?",
                                         (now(), item["copy_id"]))
                        else:
                            # 主副本内容删除前，先把不可变清单固化进销毁账目。
                            manifest_snapshot = self._destruction_manifest_snapshot(conn, version["id"])
                            conn.execute("DELETE FROM archive_files WHERE version_id=?", (version["id"],))
                    except Exception as exc:  # pragma: no cover - 介质层面的意外失败
                        conn.execute(
                            "UPDATE destruction_items SET state='failed',error=?,attempts=?,updated_at=? WHERE id=?",
                            (str(exc), attempts, now(), item["id"]),
                        )
                        self._audit(conn, job["archive_id"], actor_id, "destruction.item_failed",
                                    {"job_id": job_id, "location": item["location"], "attempts": attempts, "error": str(exc)})
                        conn.commit()
                        failure = {"location": item["location"], "error": str(exc), "attempts": attempts}
                        break
                    conn.execute(
                        "UPDATE destruction_items SET state='done',error=NULL,attempts=?,updated_at=? WHERE id=?",
                        (attempts, now(), item["id"]),
                    )
                    self._audit(conn, job["archive_id"], actor_id, "destruction.item_done",
                                {"job_id": job_id, "location": item["location"], "kind": item["kind"], "attempts": attempts})
                    # 当前点已 done：若不存在其它 pending 点，则三个存储点全部成功，原子记账。
                    pending_left = conn.execute(
                        "SELECT COUNT(*) FROM destruction_items WHERE job_id=? AND state IN ('pending','failed')",
                        (job_id,),
                    ).fetchone()[0]
                    if pending_left == 0:
                        if manifest_snapshot is None:
                            manifest_snapshot = self._destruction_manifest_snapshot(conn, version["id"])
                        record_no = f"DR-{job_id:06d}"
                        conn.execute("UPDATE archive_versions SET state='destroyed' WHERE id=?", (version["id"],))
                        conn.execute(
                            "INSERT INTO destruction_records(job_id,record_no,archive_id,version_id,point_count,"
                            "manifest,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                            (job_id, record_no, job["archive_id"], version["id"], STORAGE_POINT_COUNT,
                             json.dumps(manifest_snapshot, ensure_ascii=False, sort_keys=True), actor_id, now()),
                        )
                        conn.execute(
                            "UPDATE destruction_jobs SET state='completed',completed_at=? WHERE id=?", (now(), job_id)
                        )
                        self._audit(conn, job["archive_id"], actor_id, "destruction.complete",
                                    {"job_id": job_id, "record_no": record_no, "points": STORAGE_POINT_COUNT})
                    conn.commit()
                    executed.append({"location": item["location"], "kind": item["kind"], "attempts": attempts})
            with self.connect() as conn:
                items = conn.execute(
                    "SELECT location,kind,state,error,attempts FROM destruction_items WHERE job_id=? ORDER BY id",
                    (job_id,),
                ).fetchall()
                state = conn.execute("SELECT state FROM destruction_jobs WHERE id=?", (job_id,)).fetchone()[0]
            result = {"job_id": job_id, "state": state, "executed": executed,
                      "items": [dict(x) for x in items]}
            if failure:
                exc = BusinessError(
                    f"存储点 {failure['location']} 销毁失败，任务停在待处理；恢复介质后重试只会继续未完成的存储点",
                    503, "destruction_point_failed",
                )
                exc.payload = result | {"failed": failure}
                raise exc
            return result

    @staticmethod
    def _destruction_manifest_snapshot(conn, version_id: int) -> list[dict]:
        """销毁账目清单：取自版本入库审计中的不可变清单；找不到再回退主副本当前文件。"""
        rows = conn.execute(
            "SELECT detail FROM audit_log WHERE action='version.ingest' ORDER BY id"
        ).fetchall()
        for r in rows:
            detail = json.loads(r["detail"])
            if detail.get("version_id") == version_id:
                return detail.get("manifest", [])
        return [{"path": r["path"], "sha256": r["sha256"], "size": r["size"]}
                for r in conn.execute(
                    "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,))]

    def set_storage_fault(self, actor_id: str, location: str, reason: str) -> dict:
        """演示/测试用：把某个存储位置（离线库或服务端主副本）标记为介质故障。"""
        location = location.strip()
        if not location:
            raise BusinessError("存储位置不能为空", 422, "invalid_location")
        reason = reason.strip() or "模拟介质故障"
        with self.connect() as conn:
            self._user(conn, actor_id, {"owner", "archivist"})
            conn.execute(
                "INSERT INTO storage_faults(location,reason,set_by,created_at) VALUES(?,?,?,?)"
                " ON CONFLICT(location) DO UPDATE SET reason=excluded.reason,set_by=excluded.set_by,"
                "created_at=excluded.created_at",
                (location, reason, actor_id, now()),
            )
        return {"location": location, "fault": True, "reason": reason}

    def clear_storage_fault(self, actor_id: str, location: str) -> dict:
        """介质恢复：清除故障标记；随后重跑销毁只会处理仍未完成的存储点。"""
        location = location.strip()
        with self.connect() as conn:
            self._user(conn, actor_id, {"owner", "archivist"})
            cur = conn.execute("DELETE FROM storage_faults WHERE location=?", (location,))
            if cur.rowcount == 0:
                raise BusinessError(f"存储点 {location} 当前没有故障标记", 404, "no_fault")
        return {"location": location, "fault": False}

    def reconcile_destruction(self, user_id: str, job_id: int) -> dict:
        """对账页：销毁账目逐条核对三个存储点的实物状态，已成功的点不得被重复销毁。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            job = conn.execute("SELECT * FROM destruction_jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise BusinessError("销毁申请不存在", 404, "not_found")
            self._access(conn, job["archive_id"], user)
            items = conn.execute(
                "SELECT * FROM destruction_items WHERE job_id=? ORDER BY id", (job_id,)
            ).fetchall()
            record = conn.execute("SELECT * FROM destruction_records WHERE job_id=?", (job_id,)).fetchone()
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (job["version_id"],)).fetchone()
            expected_manifest = {
                f["path"]: f for f in self._destruction_manifest_snapshot(conn, version["id"])
            }
            points, mismatches = [], []
            for it in items:
                point = {"location": it["location"], "kind": it["kind"],
                         "item_state": it["state"], "attempts": it["attempts"]}
                if it["kind"] == "offline":
                    cp = conn.execute("SELECT state FROM copies WHERE id=?", (it["copy_id"],)).fetchone()
                    point["physical_state"] = cp["state"] if cp else None
                    files_left = conn.execute(
                        "SELECT COUNT(*) FROM copy_files WHERE copy_id=?", (it["copy_id"],)
                    ).fetchone()[0]
                    point["files_remaining"] = files_left
                    if it["state"] == "done":
                        if point["physical_state"] != "destroyed":
                            mismatches.append({"location": it["location"], "issue": "账目已销毁但副本状态不是 destroyed",
                                               "physical_state": point["physical_state"]})
                        if files_left:
                            mismatches.append({"location": it["location"],
                                               "issue": f"账目已销毁但仍有 {files_left} 个文件残留"})
                    else:
                        if point["physical_state"] == "destroyed":
                            mismatches.append({"location": it["location"], "issue": "实物已销毁但销毁条目未完成（有重复销毁风险）"})
                        else:
                            left_rows = conn.execute(
                                "SELECT path,sha256,size FROM copy_files WHERE copy_id=?", (it["copy_id"],)
                            ).fetchall()
                            for r in left_rows:
                                exp = expected_manifest.get(r["path"])
                                if not exp or r["sha256"] != exp["sha256"] or r["size"] != exp["size"]:
                                    mismatches.append({"location": it["location"], "issue": f"待处理副本文件 {r['path']} 与账目清单不一致"})
                else:
                    files_left = conn.execute(
                        "SELECT COUNT(*) FROM archive_files WHERE version_id=?", (version["id"],)
                    ).fetchone()[0]
                    point["physical_state"] = version["state"]
                    point["files_remaining"] = files_left
                    if it["state"] == "done":
                        if files_left:
                            mismatches.append({"location": PRIMARY_LOCATION,
                                               "issue": f"账目已销毁但主副本仍有 {files_left} 个文件"})
                    elif point["physical_state"] == "destroyed":
                        mismatches.append({"location": PRIMARY_LOCATION, "issue": "主副本实物已销毁但条目未完成"})
                points.append(point)
            if len(items) != STORAGE_POINT_COUNT:
                mismatches.append({"issue": f"存储点数量 {len(items)} 与要求 {STORAGE_POINT_COUNT} 不符"})
            if record:
                if record["point_count"] != STORAGE_POINT_COUNT:
                    mismatches.append({"issue": f"销毁账目记录点数 {record['point_count']} 与实际 {STORAGE_POINT_COUNT} 不符"})
                if record["version_id"] != version["id"]:
                    mismatches.append({"issue": "销毁账目版本号不匹配"})
                if len(json.loads(record["manifest"])) != len(expected_manifest):
                    mismatches.append({"issue": "销毁账目清单条目数与版本清单不符"})
                done_count = sum(1 for p in points if p["item_state"] == "done")
                if done_count == STORAGE_POINT_COUNT and version["state"] != "destroyed":
                    mismatches.append({"issue": "三点均已销毁但版本状态未置为 destroyed"})
                if done_count < STORAGE_POINT_COUNT and version["state"] == "destroyed":
                    mismatches.append({"issue": "存在未完成存储点但版本已标记 destroyed"})
            else:
                if job["state"] == "completed":
                    mismatches.append({"issue": "任务已完成但缺少销毁账目记录"})
                elif all(p["item_state"] == "done" for p in points):
                    mismatches.append({"issue": "三个存储点均已销毁但未写销毁账目"})
            return {
                "job_id": job_id, "state": job["state"],
                "record": ({"record_no": record["record_no"], "point_count": record["point_count"],
                            "manifest": json.loads(record["manifest"]), "created_at": record["created_at"]}
                           if record else None),
                "points": points, "balanced": not mismatches, "mismatches": mismatches,
            }

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            jobs = conn.execute(
                "SELECT id,version_id,state,reason,requested_by,created_at,completed_at FROM destruction_jobs"
                " WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            records = conn.execute(
                "SELECT record_no,job_id,version_id,point_count,created_by,created_at FROM destruction_records"
                " WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "destruction_jobs": [dict(j) for j in jobs],
                "destruction_records": [dict(r) for r in records],
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.0"

    def _store(self):
        return self.server.store  # type: ignore[attr-defined]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict):
            raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        user = self.headers.get("X-User-Id", "")
        if method == "GET" and path == "/":
            body = (BASE_DIR / "web" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True})
        store = self._store()
        if parts == ["api", "archives"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_archive(user, d.get("name", ""), d.get("retention_until", ""), bool(d.get("restricted", True))))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "destruction" and method == "POST":
            d = self._body()
            return self._send(201, store.request_destruction(user, int(parts[2]), d.get("reason", "")))
        if len(parts) == 4 and parts[:3] == ["api", "destruction", "jobs"] and method == "GET":
            return self._send(200, store.get_destruction_job(user, int(parts[3])))
        if len(parts) == 5 and parts[:3] == ["api", "destruction", "jobs"] and parts[4] == "run" and method == "POST":
            return self._send(200, store.run_destruction(user, int(parts[3])))
        if len(parts) == 5 and parts[:3] == ["api", "destruction", "jobs"] and parts[4] == "reconcile" and method == "GET":
            return self._send(200, store.reconcile_destruction(user, int(parts[3])))
        if len(parts) == 3 and parts[:2] == ["api", "storage"] and parts[2] == "fault" and method == "POST":
            d = self._body()
            return self._send(200, store.set_storage_fault(user, d.get("location", ""), d.get("reason", "")))
        if len(parts) == 3 and parts[:2] == ["api", "storage"] and parts[2] == "recover" and method == "POST":
            d = self._body()
            return self._send(200, store.clear_storage_fault(user, d.get("location", "")))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            payload = {"error": {"code": exc.code, "message": exc.message}}
            if exc.payload is not None:
                payload["progress"] = exc.payload
            self._send(exc.status, payload)
        except (ValueError, TypeError):
            self._send(400, {"error": {"code": "invalid_path", "message": "路径参数格式错误"}})
        except Exception as exc:
            self._send(500, {"error": {"code": "internal_error", "message": str(exc)}})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class PreservationServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        self.store = store
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="数字档案长期保存服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--port", type=int, default=8102)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    store = PreservationStore(args.db)
    store.init_schema()
    if args.seed:
        store.seed()
    if args.init or args.seed:
        print(f"数据库已初始化: {args.db}")
        return
    print(f"数字档案服务运行于 http://127.0.0.1:{args.port}")
    server = PreservationServer(("127.0.0.1", args.port), store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
