"""v1 -> v2 模式迁移：旧库打开后新增双人封存/更正表，历史数据不丢。"""
import os
import sqlite3
import tempfile
import unittest

from service_09252_006.persistence.sqlite_repo import SqliteRepository

# 双人封存上线前的 v1 表结构（精简自初版仓储）
_V1_DDL = """
CREATE TABLE users(user_id TEXT PRIMARY KEY, institution_id TEXT,
    roles_json TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '');
CREATE TABLE blobs(sha256 TEXT PRIMARY KEY, data BLOB NOT NULL,
    media_type TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE materials(material_id TEXT PRIMARY KEY, institution_id TEXT NOT NULL,
    kind TEXT NOT NULL, sensitivity TEXT NOT NULL, title TEXT NOT NULL,
    current_version_id TEXT, withdrawn INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL);
CREATE TABLE versions(version_id TEXT PRIMARY KEY,
    material_id TEXT NOT NULL REFERENCES materials(material_id),
    institution_id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
    media_type TEXT NOT NULL, version_no INTEGER NOT NULL,
    supersedes_version_id TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
    withdrawn INTEGER NOT NULL DEFAULT 0, withdrawn_at TEXT,
    UNIQUE(material_id, version_no));
CREATE TABLE packages(package_id TEXT PRIMARY KEY, institution_id TEXT NOT NULL,
    title TEXT NOT NULL, status TEXT NOT NULL, created_by TEXT NOT NULL,
    created_at TEXT NOT NULL, sealed_at TEXT, manifest_fingerprint TEXT,
    decided_at TEXT, decision TEXT, decision_note TEXT,
    review_fingerprint TEXT, supersedes_package_id TEXT);
CREATE TABLE entries(entry_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES packages(package_id),
    material_id TEXT NOT NULL, version_id TEXT NOT NULL REFERENCES versions(version_id),
    sha256 TEXT NOT NULL, kind TEXT NOT NULL, sensitivity TEXT NOT NULL,
    added_at TEXT NOT NULL, UNIQUE(package_id, version_id));
CREATE TABLE requests(request_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES packages(package_id),
    institution_id TEXT NOT NULL, reviewer_id TEXT NOT NULL, status TEXT NOT NULL,
    assigned_by TEXT NOT NULL, assigned_at TEXT NOT NULL, responded_at TEXT,
    completed_at TEXT, verdict TEXT, comment TEXT, deadline_at_utc TEXT,
    deadline_timezone TEXT);
CREATE TABLE objections(objection_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES requests(request_id),
    package_id TEXT NOT NULL REFERENCES packages(package_id),
    institution_id TEXT NOT NULL, reviewer_id TEXT NOT NULL, category TEXT NOT NULL,
    detail TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE audit_log(audit_id TEXT PRIMARY KEY, package_id TEXT,
    institution_id TEXT, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    at TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE idempotency(idempotency_key TEXT PRIMARY KEY, result_json TEXT NOT NULL,
    created_at TEXT NOT NULL);
CREATE TABLE api_tokens(token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id), created_at TEXT NOT NULL);
PRAGMA user_version = 1;
"""


class SchemaMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        fd, self.db_path = tempfile.mkstemp(prefix="qe-v1-", suffix=".db")
        os.close(fd)
        os.unlink(self.db_path)

    def tearDown(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.db_path + suffix)
            except FileNotFoundError:
                pass

    def test_v1_database_migrates_to_v2_with_data_intact(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.executescript(_V1_DDL)
        conn.execute(
            "INSERT INTO users VALUES('u1','inst-a','[\"institution_admin\"]','A')"
        )
        conn.commit()
        conn.close()

        repo = SqliteRepository(self.db_path)
        try:
            self.assertEqual(
                repo._conn.execute("PRAGMA user_version").fetchone()[0], 2
            )
            tables = {
                r[0]
                for r in repo._conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertIn("seal_confirmations", tables)
            self.assertIn("correction_proposals", tables)
            self.assertEqual(repo.get_user("u1").institution_id, "inst-a")
            # 迁移后新流程可用
            self.assertIsNone(repo.get_active_seal_confirmation("pkg-x"))
        finally:
            repo.close()


if __name__ == "__main__":
    unittest.main()
