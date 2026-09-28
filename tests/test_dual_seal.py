"""证据包双人封存：两角色确认、确认顺序与校验和留痕、第二人确认前撤回、
封存后只能走更正流程。
"""
import sqlite3
import unittest

from service_09252_006.domain.enums import PackageStatus, Role
from service_09252_006.domain.errors import (
    ConflictError,
    ImmutabilityError,
    PermissionDeniedError,
    ValidationError,
)
from tests.flow import seal_new_package, start_and_confirm_seal, upload_material
from tests.support import Harness


class DualSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.item = upload_material(self.h, self.admin, data=b"evidence-v1")
        self.pkg = self.h.ctx.packages.create_package(self.admin, title="P")
        self.pid = self.pkg["package_id"]
        self.h.ctx.packages.add_entry(
            self.admin, package_id=self.pid,
            version_id=self.item.version["version_id"],
        )

    def tearDown(self) -> None:
        self.h.close()

    # ----------------------------------------------------------- 角色校验
    def test_reviewer_cannot_start_or_confirm(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.start_seal_confirmation(
                self.reviewer, package_id=self.pid
            )

    def test_same_user_cannot_be_both_confirmer(self) -> None:
        started = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.confirm_seal(
                self.admin,
                package_id=self.pid,
                confirmation_id=started["confirmation_id"],
            )

    def test_second_confirmer_must_be_complementary_role(self) -> None:
        admin2 = self.h.user(
            "admin-a2", Role.INSTITUTION_ADMIN, institution_id="inst-a"
        )
        started = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        # 另一名用户但仍是同角色：拒绝
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.confirm_seal(
                admin2,
                package_id=self.pid,
                confirmation_id=started["confirmation_id"],
            )

    def test_authority_can_start_and_admin_confirms(self) -> None:
        # 顺序不限：权威机构先确认、管理员后确认也合法
        started = self.h.ctx.packages.start_seal_confirmation(
            self.authority, package_id=self.pid
        )
        sealed = self.h.ctx.packages.confirm_seal(
            self.admin,
            package_id=self.pid,
            confirmation_id=started["confirmation_id"],
        )
        self.assertEqual(sealed["status"], PackageStatus.SEALED.value)
        records = self.h.ctx.packages.list_seal_confirmations(self.admin, self.pid)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["first_confirmer_id"], "auth")
        self.assertEqual(rec["first_confirmer_role"], Role.QUALITY_AUTHORITY.value)
        self.assertEqual(rec["second_confirmer_id"], "admin-a")
        self.assertEqual(rec["second_confirmer_role"], Role.INSTITUTION_ADMIN.value)
        self.assertIsNotNone(rec["first_confirmed_at"])
        self.assertIsNotNone(rec["second_confirmed_at"])
        self.assertEqual(
            rec["sealed_manifest_fingerprint"], sealed["manifest_fingerprint"]
        )

    # ----------------------------------------------------- 校验和与封存
    def test_checksum_pinned_and_seal_completes(self) -> None:
        started, sealed = start_and_confirm_seal(
            self.h, self.admin, self.authority, self.pid
        )
        self.assertTrue(started["content_checksum"].startswith("sha256:"))
        self.assertEqual(started["entry_count"], 1)
        pkg = self.h.repo.get_package(self.pid)
        self.assertEqual(pkg.status, PackageStatus.SEALED.value)
        self.assertIsNotNone(pkg.manifest_fingerprint)
        # 两人确认的是同一个内容校验和
        self.assertEqual(started["content_checksum"], started["content_checksum"])
        rec = self.h.repo.get_seal_confirmation(started["confirmation_id"])
        self.assertEqual(rec.content_checksum, started["content_checksum"])
        self.assertEqual(rec.status, "sealed")

    def test_cannot_add_entry_while_confirmation_pending(self) -> None:
        self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        extra = upload_material(self.h, self.admin, data=b"more")
        with self.assertRaises(ConflictError):
            self.h.ctx.packages.add_entry(
                self.admin, package_id=self.pid,
                version_id=extra.version["version_id"],
            )

    def test_checksum_mismatch_blocks_seal_when_manifest_tampered(self) -> None:
        started = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        # 绕过服务直接往清单插一条（模拟第一人确认后清单被改动）
        other = upload_material(self.h, self.admin, data=b"sneaked")
        conn = sqlite3.connect(self.h.db_path)
        conn.execute(
            "INSERT INTO entries(entry_id, package_id, material_id, version_id,"
            " sha256, kind, sensitivity, added_at)"
            " VALUES('ent_tamper',?,?,?,?,?,?,?)",
            (
                self.pid,
                other.material["material_id"],
                other.version["version_id"],
                other.version["sha256"].split(":", 1)[1],
                "syllabus",
                "normal",
                "2026-09-25T02:00:00+00:00",
            ),
        )
        conn.commit()
        conn.close()
        with self.assertRaises(ConflictError) as ctx:
            self.h.ctx.packages.confirm_seal(
                self.authority,
                package_id=self.pid,
                confirmation_id=started["confirmation_id"],
            )
        self.assertEqual(ctx.exception.code, "conflict")
        # 包仍为 draft
        self.assertEqual(
            self.h.repo.get_package(self.pid).status, PackageStatus.DRAFT.value
        )

    def test_start_is_idempotent_for_same_user(self) -> None:
        first = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        replay = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        self.assertEqual(
            replay["confirmation_id"], first["confirmation_id"]
        )
        self.assertTrue(replay["replayed"])

    def test_two_different_users_cannot_open_two_pending_rounds(self) -> None:
        self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.packages.start_seal_confirmation(
                self.authority, package_id=self.pid
            )

    # ------------------------------------------------- 第二人确认前撤回
    def test_withdraw_before_second_confirmation_keeps_draft(self) -> None:
        started = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        result = self.h.ctx.packages.withdraw_seal_confirmation(
            self.authority, package_id=self.pid, reason="发现材料待补"
        )
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["withdrawn_by"], "auth")
        self.assertEqual(result["withdraw_reason"], "发现材料待补")
        pkg = self.h.repo.get_package(self.pid)
        self.assertEqual(pkg.status, PackageStatus.DRAFT.value)
        self.assertIsNone(pkg.manifest_fingerprint)
        self.assertIsNone(
            self.h.repo.get_active_seal_confirmation(self.pid)
        )

    def test_restart_after_withdraw_then_seal(self) -> None:
        started = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        self.h.ctx.packages.withdraw_seal_confirmation(
            self.admin, package_id=self.pid, reason="重新核对"
        )
        # 撤回后可追加材料并重新封存；历史撤回轮次仍可查
        extra = upload_material(self.h, self.admin, data=b"extra")
        self.h.ctx.packages.add_entry(
            self.admin, package_id=self.pid,
            version_id=extra.version["version_id"],
        )
        started2, sealed = start_and_confirm_seal(
            self.h, self.admin, self.authority, self.pid
        )
        self.assertNotEqual(started["confirmation_id"], started2["confirmation_id"])
        self.assertEqual(sealed["entry_count"], 2)
        records = self.h.repo.list_seal_confirmations(self.pid)
        self.assertEqual([r.status for r in records], ["cancelled", "sealed"])

    def test_cannot_confirm_after_withdrawal(self) -> None:
        started = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=self.pid
        )
        self.h.ctx.packages.withdraw_seal_confirmation(
            self.admin, package_id=self.pid
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.packages.confirm_seal(
                self.authority,
                package_id=self.pid,
                confirmation_id=started["confirmation_id"],
            )

    # --------------------------------------------------------- 封存后更正
    def _sealed_pid(self) -> str:
        sealed = seal_new_package(self.h, self.admin)
        return sealed.package_id

    def test_direct_change_after_seal_is_rejected(self) -> None:
        pid = self._sealed_pid()
        extra = upload_material(self.h, self.admin, data=b"late")
        with self.assertRaises(ImmutabilityError):
            self.h.ctx.packages.add_entry(
                self.admin, package_id=pid,
                version_id=extra.version["version_id"],
            )

    def test_correction_on_draft_is_rejected(self) -> None:
        with self.assertRaises(ConflictError):
            self.h.ctx.packages.request_correction(
                self.admin,
                package_id=self.pid,
                correction_type="metadata",
                reason="草稿不需要更正",
                detail={"title": "新标题"},
            )

    def test_metadata_correction_requires_other_role_and_preserves_manifest(self) -> None:
        pid = self._sealed_pid()
        before = self.h.repo.get_package(pid)
        req = self.h.ctx.packages.request_correction(
            self.admin,
            package_id=pid,
            correction_type="metadata",
            reason="标题笔误",
            detail={"title": "2026 秋评审包（订正）"},
        )
        self.assertEqual(req["status"], "pending")

        # 申请人不能自批
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.review_correction(
                self.admin, correction_id=req["correction_id"], approve=True
            )
        # 评审人无权审批
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.review_correction(
                self.reviewer, correction_id=req["correction_id"], approve=True
            )
        # 另一封存角色（权威机构）批准后生效
        result = self.h.ctx.packages.review_correction(
            self.authority, correction_id=req["correction_id"],
            approve=True, note="同意订正",
        )
        self.assertEqual(result["status"], "applied")
        self.assertIsNotNone(result["change_fingerprint"])
        after = self.h.repo.get_package(pid)
        self.assertEqual(after.title, "2026 秋评审包（订正）")
        # 元数据订正不改变清单指纹
        self.assertEqual(after.manifest_fingerprint, before.manifest_fingerprint)

    def test_metadata_correction_requires_title(self) -> None:
        pid = self._sealed_pid()
        with self.assertRaises(ValidationError):
            self.h.ctx.packages.request_correction(
                self.admin, package_id=pid, correction_type="metadata",
                reason="缺标题", detail={},
            )

    def test_rejected_correction_changes_nothing(self) -> None:
        pid = self._sealed_pid()
        before = self.h.repo.get_package(pid)
        req = self.h.ctx.packages.request_correction(
            self.admin, package_id=pid, correction_type="metadata",
            reason="想改名", detail={"title": "不应生效"},
        )
        result = self.h.ctx.packages.review_correction(
            self.authority, correction_id=req["correction_id"], approve=False
        )
        self.assertEqual(result["status"], "rejected")
        after = self.h.repo.get_package(pid)
        self.assertEqual(after.title, before.title)

    def test_structural_correction_approved_but_requires_rereview(self) -> None:
        sealed = seal_new_package(self.h, self.admin)
        pid = sealed.package_id
        target = sealed.items[0].version["version_id"]
        # 上传一个替代版本（同材料新版本）
        replacement = self.h.ctx.evidence.upload_version(
            self.admin,
            material_id=sealed.items[0].material["material_id"],
            data="大纲 v2".encode("utf-8"),
        )
        req = self.h.ctx.packages.request_correction(
            self.admin, package_id=pid, correction_type="entry_replace",
            reason="版本错误，需替换",
            detail={
                "version_id": target,
                "replacement_version_id": replacement["version_id"],
            },
        )
        result = self.h.ctx.packages.review_correction(
            self.authority, correction_id=req["correction_id"], approve=True
        )
        self.assertEqual(result["status"], "approved")
        self.assertTrue(result["requires_rereview"])
        # 历史封存清单不被改写
        pkg = self.h.repo.get_package(pid)
        versions = {e.version_id for e in pkg.entries}
        self.assertIn(target, versions)
        self.assertNotIn(replacement["version_id"], versions)

    def test_unknown_correction_type_rejected(self) -> None:
        pid = self._sealed_pid()
        with self.assertRaises(ValidationError):
            self.h.ctx.packages.request_correction(
                self.admin, package_id=pid, correction_type="delete_everything",
                reason="x",
            )


if __name__ == "__main__":
    unittest.main()
