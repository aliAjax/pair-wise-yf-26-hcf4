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


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


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
        # 销毁执行期间串行挡住上传（ingest/add_copy/migrate），避免与销毁流程并发写同一版本。
        self._write_lock = threading.Lock()

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
                CREATE TABLE IF NOT EXISTS destructions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    status TEXT NOT NULL DEFAULT 'in_progress' CHECK(status IN ('in_progress','completed','partial')),
                    applicant_id TEXT NOT NULL REFERENCES users(id),
                    applied_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS destruction_points(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    destruction_id INTEGER NOT NULL REFERENCES destructions(id),
                    point_kind TEXT NOT NULL CHECK(point_kind IN ('server','copy')),
                    copy_id INTEGER REFERENCES copies(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','destroyed')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    executed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS storage_faults(
                    node_key TEXT PRIMARY KEY,
                    faulty INTEGER NOT NULL DEFAULT 0 CHECK(faulty IN (0,1)),
                    updated_at TEXT NOT NULL
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
        with self._write_lock, self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
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
        with self._write_lock, self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            if version["state"] == "destroyed":
                raise BusinessError("该版本已销毁，不能新增副本", 409, "version_destroyed")
            self._access(conn, version["archive_id"], actor, require_write=True)
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
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files], "copies": [dict(x) for x in copies]}

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                if version and version["state"] == "destroyed":
                    raise BusinessError("该版本已销毁", 409, "version_destroyed")
                self._access(conn, version["archive_id"], user)
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
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self._write_lock, self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            if source_version["state"] == "destroyed":
                raise BusinessError("该版本已销毁，不能迁移", 409, "version_destroyed")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
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

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }


    def _can_access(self, conn, archive_id: int, user: sqlite3.Row) -> bool:
        archive = conn.execute("SELECT owner_id FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            return False
        if archive["owner_id"] == user["id"]:
            return True
        return conn.execute(
            "SELECT 1 FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone() is not None

    def request_destruction(self, actor_id: str, version_id: int) -> dict:
        """管理员发出销毁申请：三个存储点（服务端 + 各离线副本）一起进入待销毁，再逐点执行。"""
        with self._write_lock:
            with self.connect() as conn:
                actor = self._user(conn, actor_id, {"owner", "archivist"})
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
                if not version:
                    raise BusinessError("档案版本不存在", 404, "not_found")
                self._access(conn, version["archive_id"], actor, require_write=True)
                if version["state"] == "destroyed":
                    raise BusinessError("该版本已销毁", 409, "already_destroyed")
                if conn.execute("SELECT 1 FROM destructions WHERE version_id=?", (version_id,)).fetchone():
                    raise BusinessError("该版本已有销毁申请，请使用对账/恢复接口", 409, "destruction_exists")
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    cur = conn.execute(
                        "INSERT INTO destructions(archive_id,version_id,status,applicant_id,applied_at) VALUES(?,?,?,?,?)",
                        (version["archive_id"], version_id, "in_progress", actor_id, now()),
                    )
                    destruction_id = cur.lastrowid
                    # 服务端存储点
                    conn.execute(
                        "INSERT INTO destruction_points(destruction_id,point_kind,copy_id,location,state) VALUES(?,?,NULL,?,'pending')",
                        (destruction_id, "server", "server"),
                    )
                    # 两个（或多个）离线副本存储点
                    for c in conn.execute("SELECT id,location FROM copies WHERE version_id=? ORDER BY id", (version_id,)).fetchall():
                        conn.execute(
                            "INSERT INTO destruction_points(destruction_id,point_kind,copy_id,location,state) VALUES(?,?,?,?, 'pending')",
                            (destruction_id, "copy", c["id"], c["location"]),
                        )
                    point_count = 1 + conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (version_id,)).fetchone()[0]
                    self._audit(
                        conn, version["archive_id"], actor_id, "destruction.request",
                        {"destruction_id": destruction_id, "version_id": version_id, "points": point_count},
                    )
                except Exception:
                    conn.rollback()
                    raise
            self._run_destruction_points(destruction_id)
            with self.connect() as conn:
                return self._destruction_detail(conn, conn.execute("SELECT * FROM destructions WHERE id=?", (destruction_id,)).fetchone())

    def _node_key(self, point: sqlite3.Row) -> str:
        return "server" if point["point_kind"] == "server" else f"copy:{point['copy_id']}"

    def _execute_point(self, conn, point: sqlite3.Row) -> None:
        """执行单个存储点的销毁；介质故障时抛出异常，由调用方回滚并标记待处理。"""
        fault = conn.execute("SELECT faulty FROM storage_faults WHERE node_key=?", (self._node_key(point),)).fetchone()
        if fault and fault["faulty"]:
            raise RuntimeError(f"存储点 {point['location']} 介质故障，销毁未执行")
        if point["point_kind"] == "server":
            conn.execute("DELETE FROM archive_files WHERE version_id=?", (point["version_id"],))
        else:
            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (point["copy_id"],))
            conn.execute("UPDATE copies SET state='destroyed' WHERE id=?", (point["copy_id"],))

    def _run_destruction_points(self, destruction_id: int) -> bool:
        """逐点执行销毁：成功一点提交一点；失败则停在待处理，等恢复时只重试未完成的副本。"""
        with self.connect() as conn:
            d = conn.execute("SELECT * FROM destructions WHERE id=?", (destruction_id,)).fetchone()
            if not d:
                raise BusinessError("销毁单不存在", 404, "not_found")
            points = conn.execute(
                """SELECT dp.*, d.version_id FROM destruction_points dp
                   JOIN destructions d ON d.id=dp.destruction_id
                   WHERE dp.destruction_id=? ORDER BY dp.id""",
                (destruction_id,),
            ).fetchall()
        all_destroyed = True
        for point in points:
            if point["state"] == "destroyed":
                continue  # 幂等：已经成功的存储点不再重复执行
            try:
                with self.connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    self._execute_point(conn, point)
                    conn.execute(
                        "UPDATE destruction_points SET state='destroyed', attempts=attempts+1, last_error=NULL, executed_at=? WHERE id=?",
                        (now(), point["id"]),
                    )
            except Exception as exc:
                all_destroyed = False
                with self.connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute(
                        "UPDATE destruction_points SET state='pending', attempts=attempts+1, last_error=? WHERE id=?",
                        (str(exc), point["id"]),
                    )
                break  # 某个存储点失败后停在待处理，不再继续后续存储点
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if all_destroyed:
                conn.execute("UPDATE destructions SET status='completed', completed_at=? WHERE id=?", (now(), destruction_id))
                conn.execute("UPDATE archive_versions SET state='destroyed' WHERE id=?", (d["version_id"],))
                conn.execute("UPDATE copies SET state='destroyed' WHERE version_id=?", (d["version_id"],))
                self._audit(
                    conn, d["archive_id"], d["applicant_id"], "destruction.completed",
                    {"destruction_id": destruction_id, "version_id": d["version_id"]},
                )
            else:
                conn.execute("UPDATE destructions SET status='partial' WHERE id=?", (destruction_id,))
                self._audit(
                    conn, d["archive_id"], d["applicant_id"], "destruction.partial",
                    {"destruction_id": destruction_id, "version_id": d["version_id"]},
                )
        return all_destroyed

    def reconcile_destruction(self, actor_id: str, destruction_id: int) -> dict:
        """恢复/对账：只重试仍处于待处理的未完成副本，已销毁的存储点不重复执行。"""
        with self._write_lock:
            with self.connect() as conn:
                actor = self._user(conn, actor_id, {"owner", "archivist"})
                d = conn.execute("SELECT * FROM destructions WHERE id=?", (destruction_id,)).fetchone()
                if not d:
                    raise BusinessError("销毁单不存在", 404, "not_found")
                self._access(conn, d["archive_id"], actor, require_write=True)
            self._run_destruction_points(destruction_id)
            with self.connect() as conn:
                d = conn.execute("SELECT * FROM destructions WHERE id=?", (destruction_id,)).fetchone()
                return self._destruction_detail(conn, d)

    def get_destruction(self, user_id: str, destruction_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            d = conn.execute("SELECT * FROM destructions WHERE id=?", (destruction_id,)).fetchone()
            if not d:
                raise BusinessError("销毁单不存在", 404, "not_found")
            self._access(conn, d["archive_id"], user)
            return self._destruction_detail(conn, d)

    def _destruction_detail(self, conn, d: sqlite3.Row) -> dict:
        points = conn.execute(
            """SELECT dp.*, d.version_id FROM destruction_points dp
               JOIN destructions d ON d.id=dp.destruction_id
               WHERE dp.destruction_id=? ORDER BY dp.id""",
            (d["id"],),
        ).fetchall()
        point_details, all_consistent = [], True
        for p in points:
            node_key = self._node_key(p)
            fault = conn.execute("SELECT faulty FROM storage_faults WHERE node_key=?", (node_key,)).fetchone()
            if p["point_kind"] == "server":
                cnt = conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (p["version_id"],)).fetchone()[0]
            else:
                cnt = conn.execute("SELECT COUNT(*) FROM copy_files WHERE copy_id=?", (p["copy_id"],)).fetchone()[0]
            actual = "gone" if cnt == 0 else "exists"
            consistent = (p["state"] == "destroyed" and actual == "gone") or (p["state"] == "pending" and actual == "exists")
            if not consistent:
                all_consistent = False
            point_details.append({
                "id": p["id"], "node_key": node_key, "location": p["location"],
                "state": p["state"], "attempts": p["attempts"], "last_error": p["last_error"],
                "executed_at": p["executed_at"], "actual": actual, "consistent": consistent,
                "faulty": bool(fault["faulty"]) if fault else False,
            })
        return {
            "destruction": dict(d),
            "points": point_details,
            "all_consistent": all_consistent,
            "reconciled_at": now(),
        }

    def list_destructions(self, user_id: str, archive_id: int | None = None) -> list[dict]:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            if archive_id is not None:
                self._access(conn, archive_id, user)
                rows = conn.execute("SELECT * FROM destructions WHERE archive_id=? ORDER BY id DESC", (archive_id,)).fetchall()
            else:
                rows = [r for r in conn.execute("SELECT * FROM destructions ORDER BY id DESC").fetchall()
                        if self._can_access(conn, r["archive_id"], user)]
            result = []
            for r in rows:
                summary = {
                    row["state"]: row["c"]
                    for row in conn.execute(
                        "SELECT state,COUNT(*) c FROM destruction_points WHERE destruction_id=? GROUP BY state", (r["id"],)
                    ).fetchall()
                }
                result.append({"destruction": dict(r), "point_summary": summary})
            return result

    def set_storage_fault(self, actor_id: str, node_key: str, faulty: bool) -> dict:
        """注入/解除存储点介质故障，用于演示“失败后停在待处理、恢复时只重试未完成副本”。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            archive_id = None
            if node_key == "server":
                pass
            elif node_key.startswith("copy:"):
                try:
                    copy_id = int(node_key.split(":", 1)[1])
                except ValueError:
                    raise BusinessError("node_key 格式应为 server 或 copy:<id>", 422, "invalid_node")
                row = conn.execute(
                    "SELECT v.archive_id FROM copies c JOIN archive_versions v ON v.id=c.version_id WHERE c.id=?",
                    (copy_id,),
                ).fetchone()
                if not row:
                    raise BusinessError("副本不存在", 404, "not_found")
                archive_id = row["archive_id"]
                self._access(conn, archive_id, actor, require_write=True)
            else:
                raise BusinessError("node_key 必须是 server 或 copy:<id>", 422, "invalid_node")
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """INSERT INTO storage_faults(node_key,faulty,updated_at) VALUES(?,?,?)
                       ON CONFLICT(node_key) DO UPDATE SET faulty=excluded.faulty, updated_at=excluded.updated_at""",
                    (node_key, int(bool(faulty)), now()),
                )
                if archive_id is not None:
                    self._audit(conn, archive_id, actor_id, "storage.fault", {"node_key": node_key, "faulty": bool(faulty)})
            except Exception:
                conn.rollback()
                raise
            return {"node_key": node_key, "faulty": bool(faulty)}


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

    def _query_params(self) -> dict:
        from urllib.parse import parse_qs
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

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
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "destructions" and method == "POST":
            return self._send(201, store.request_destruction(user, int(parts[2])))
        if parts == ["api", "destructions"] and method == "GET":
            q = self._query_params()
            archive_id = int(q["archive_id"]) if "archive_id" in q else None
            return self._send(200, store.list_destructions(user, archive_id))
        if len(parts) == 3 and parts[:2] == ["api", "destructions"] and method == "GET":
            return self._send(200, store.get_destruction(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "destructions"] and parts[3] == "reconcile" and method == "POST":
            return self._send(200, store.reconcile_destruction(user, int(parts[2])))
        if parts == ["api", "storage", "fault"] and method == "POST":
            d = self._body()
            return self._send(200, store.set_storage_fault(user, d.get("node_key", ""), bool(d.get("faulty", True))))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            self._send(exc.status, {"error": {"code": exc.code, "message": exc.message}})
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
