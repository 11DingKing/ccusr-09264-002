"""双人封存的离线核验与 v1 -> v2 增量迁移。"""
import json
import sqlite3
import unittest

from service_09252_006.application.container import ApplicationContext
from service_09252_006.application.verification import verify_database
from service_09252_006.domain.enums import Role
from service_09252_006.domain.fingerprint import manifest_fingerprint
from service_09252_006.persistence.sqlite_repo import _SCHEMA_V1
from tests.flow import seal_new_package
from tests.support import Harness


class DualSealVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.h.user("auth", Role.QUALITY_AUTHORITY, institution_id=None)
        self.sealed = seal_new_package(self.h, self.admin)
        self.pid = self.sealed.package_id

    def tearDown(self) -> None:
        self.h.close()

    def _raw(self, sql, params=()):
        conn = sqlite3.connect(self.h.db_path)
        conn.execute(sql, params)
        conn.commit()
        conn.close()

    def test_clean_dual_seal_passes_offline_verification(self) -> None:
        self.h.ctx.close()
        report = verify_database(self.h.db_path)
        self.assertTrue(report.ok, report.failures)

    def test_same_person_confirmation_detected(self) -> None:
        self.h.ctx.close()
        self._raw(
            "UPDATE seal_confirmations SET confirmer_id = 'admin-a' WHERE seq = 2"
        )
        report = verify_database(self.h.db_path)
        self.assertFalse(report.ok)
        kinds = {f["kind"] for f in report.failures}
        self.assertIn("seal_confirmation_same_person", kinds)
        # 篡改确认人也会导致 v2 清单指纹不一致
        self.assertIn("manifest_fingerprint_mismatch", kinds)

    def test_missing_second_confirmation_detected(self) -> None:
        self.h.ctx.close()
        self._raw("DELETE FROM seal_confirmations WHERE seq = 2")
        report = verify_database(self.h.db_path)
        self.assertFalse(report.ok)
        self.assertTrue(
            any(f["kind"] == "seal_confirmation_count_invalid" for f in report.failures)
        )

    def test_confirmation_checksum_tampering_detected(self) -> None:
        self.h.ctx.close()
        self._raw(
            "UPDATE seal_confirmations SET sha256 = ? WHERE seq = 1",
            ("sha256:" + "a" * 64,),
        )
        report = verify_database(self.h.db_path)
        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                f["kind"] == "seal_confirmation_digest_mismatch"
                for f in report.failures
            )
        )

    def test_revoked_history_reported_as_warning_not_failure(self) -> None:
        # 新建一个包：第一人确认后撤回，再重新双人封存；历史撤回记录仅警告
        from tests.flow import upload_material

        item = upload_material(self.h, self.admin, data=b"withdraw-then-reseal")
        pkg = self.h.ctx.packages.create_package(self.admin, title="撤回重封")
        pid2 = pkg["package_id"]
        self.h.ctx.packages.add_entry(
            self.admin, package_id=pid2, version_id=item.version["version_id"]
        )
        self.h.ctx.packages.confirm_seal(self.admin, package_id=pid2)
        self.h.ctx.packages.withdraw_seal_confirmation(
            self.admin, package_id=pid2, reason="补材料"
        )
        authority = self.h.repo.get_user("auth")
        self.h.ctx.packages.confirm_seal(self.admin, package_id=pid2)
        self.h.ctx.packages.confirm_seal(authority, package_id=pid2)
        self.h.ctx.close()
        report = verify_database(self.h.db_path)
        self.assertTrue(report.ok, report.failures)
        self.assertTrue(
            any(w["kind"] == "seal_confirmation_revoked_history"
                and w["package_id"] == pid2
                for w in report.warnings)
        )


class LegacyV1ManifestVerificationTests(unittest.TestCase):
    def test_sealed_package_without_confirmations_verified_as_v1(self) -> None:
        with Harness() as h:
            admin = h.user("admin-a", Role.INSTITUTION_ADMIN)
            from tests.flow import upload_material

            item = upload_material(h, admin, data=b"legacy-v1")
            pkg = h.ctx.packages.create_package(admin, title="旧版封存")
            pid = pkg["package_id"]
            h.ctx.packages.add_entry(
                admin, package_id=pid, version_id=item.version["version_id"]
            )
            loaded = h.repo.get_package(pid)
            sealed_at = "2026-09-01T00:00:00+00:00"
            v1_fingerprint = manifest_fingerprint(
                pid,
                loaded.institution_id,
                [
                    {
                        "material_id": e.material_id,
                        "version_id": e.version_id,
                        "sha256": e.sha256,
                        "kind": e.kind,
                        "sensitivity": e.sensitivity,
                    }
                    for e in loaded.entries
                ],
                sealed_at,
            )
            h.ctx.close()
            # 直接把包置为 sealed，写 v1 指纹、不写双人确认（模拟历史库）
            conn = sqlite3.connect(h.db_path)
            conn.execute(
                "UPDATE packages SET status='sealed', sealed_at=?,"
                " manifest_fingerprint=? WHERE package_id=?",
                (sealed_at, v1_fingerprint, pid),
            )
            conn.commit()
            conn.close()

            report = verify_database(h.db_path)
            self.assertTrue(report.ok, report.failures)
            self.assertEqual(report.sealed_count, 1)


class SchemaMigrationTests(unittest.TestCase):
    def test_v1_database_migrates_and_supports_dual_seal(self) -> None:
        import os
        import tempfile

        fd, db_path = tempfile.mkstemp(prefix="qe-migrate-", suffix=".db")
        os.close(fd)
        os.unlink(db_path)
        try:
            # 手工造一个 user_version=1 的历史库
            conn = sqlite3.connect(db_path)
            conn.executescript(_SCHEMA_V1)
            conn.execute(
                "INSERT INTO users(user_id, institution_id, roles_json, display_name)"
                " VALUES(?,?,?,?)",
                ("admin-a", "inst-a", json.dumps(["institution_admin"]), "admin"),
            )
            conn.execute(
                "INSERT INTO packages(package_id, institution_id, title, status,"
                " created_by, created_at) VALUES(?,?,?,?,?,?)",
                ("pkg_old", "inst-a", "旧草稿", "draft", "admin-a",
                 "2026-09-01T00:00:00+00:00"),
            )
            conn.commit()
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 1)
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("SELECT 1 FROM seal_confirmations").fetchall()
            conn.close()

            ctx = ApplicationContext(db_path)
            # 迁移到 v2：新表存在，旧数据保留
            version = ctx.repo._conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(version, 2)
            ctx.repo._conn.execute(
                "SELECT 1 FROM seal_confirmations"
            ).fetchall()
            ctx.repo._conn.execute(
                "SELECT 1 FROM package_corrections"
            ).fetchall()
            self.assertIsNotNone(ctx.repo.get_user("admin-a"))
            self.assertEqual(
                ctx.repo.get_package("pkg_old").status, "draft"
            )

            # 迁移后的库可正常走双人封存
            from tests.flow import upload_material
            from types import SimpleNamespace
            from service_09252_006.domain.models import User

            admin = ctx.repo.get_user("admin-a")
            self.assertIsNone(ctx.repo.get_user("auth"))
            ctx.repo.upsert_user(
                User(user_id="auth", institution_id=None,
                     roles=(Role.QUALITY_AUTHORITY.value,), display_name="权威")
            )
            authority = ctx.repo.get_user("auth")
            item = upload_material(SimpleNamespace(ctx=ctx), admin, data=b"post-migration")
            pkg = ctx.packages.create_package(admin, title="迁移后新包")
            ctx.packages.add_entry(
                admin, package_id=pkg["package_id"],
                version_id=item.version["version_id"],
            )
            ctx.packages.confirm_seal(admin, package_id=pkg["package_id"])
            sealed = ctx.packages.confirm_seal(
                authority, package_id=pkg["package_id"]
            )
            self.assertTrue(sealed["sealed"])
            ctx.close()

            report = verify_database(db_path)
            self.assertTrue(report.ok, report.failures)
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(db_path + suffix)
                except FileNotFoundError:
                    pass


if __name__ == "__main__":
    unittest.main()
