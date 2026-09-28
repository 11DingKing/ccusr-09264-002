"""双人封存：两种角色、两名人员、同一内容校验和、确认顺序与撤回窗口。

规则（封存会议前，评审办公室完成证据包双人封存）：
- 两名【不同角色】（机构管理员 + 质量权威机构）、两名【不同人员】先后确认；
- 两人确认的内容校验和必须一致；校验和由库内清单重算，可与客户端传入值比对；
- SQLite 保存确认校验和与确认顺序（seq=1/2）；
- 第一人确认后清单锁定；第二人确认完成前，第一人可撤回，撤回后恢复可改；
- 封存完成后确认不可撤回，清单指纹（v2）绑定校验和与两人确认顺序。
"""
import unittest

from service_09252_006.domain.enums import PackageStatus, Role
from service_09252_006.domain.errors import (
    ConflictError,
    ImmutabilityError,
    PermissionDeniedError,
    ValidationError,
)
from service_09252_006.domain.fingerprint import seal_content_digest
from tests.flow import upload_material
from tests.support import Harness


class DualSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.admin2 = self.h.user("admin-a2", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.authority2 = self.h.user(
            "auth2", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.item = upload_material(self.h, self.admin, data=b"seal-me")
        pkg = self.h.ctx.packages.create_package(self.admin, title="P")
        self.pid = pkg["package_id"]
        self.h.ctx.packages.add_entry(
            self.admin, package_id=self.pid,
            version_id=self.item.version["version_id"],
        )

    def tearDown(self) -> None:
        self.h.close()

    def _digest(self) -> str:
        pkg = self.h.repo.get_package(self.pid)
        return seal_content_digest(
            [
                {
                    "material_id": e.material_id,
                    "version_id": e.version_id,
                    "sha256": e.sha256,
                    "kind": e.kind,
                    "sensitivity": e.sensitivity,
                }
                for e in pkg.entries
            ]
        )

    # ------------------------------------------------------------ 基本流程
    def test_two_distinct_roles_and_people_seal_in_order(self) -> None:
        digest = self._digest()
        first = self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        self.assertFalse(first["sealed"])
        self.assertEqual(first["active_confirmation_count"], 1)
        self.assertEqual(first["seal_content_digest"], digest)
        self.assertEqual(first["confirmed_roles"], ["institution_admin"])
        self.assertEqual(first["awaiting_role"], ["quality_authority"])
        # 确认顺序与校验和落库
        self.assertEqual(first["confirmations"][0]["seq"], 1)
        self.assertEqual(first["confirmations"][0]["role"], "institution_admin")
        self.assertEqual(first["confirmations"][0]["confirmer_id"], "admin-a")
        self.assertEqual(first["confirmations"][0]["sha256"], digest)

        second = self.h.ctx.packages.confirm_seal(
            self.authority, package_id=self.pid
        )
        self.assertTrue(second["sealed"])
        self.assertEqual(second["status"], PackageStatus.SEALED.value)
        self.assertEqual(second["active_confirmation_count"], 2)
        self.assertEqual(second["awaiting_role"], [])
        seqs = [(c["seq"], c["role"]) for c in second["confirmations"]]
        self.assertEqual(
            seqs,
            [(1, "institution_admin"), (2, "quality_authority")],
        )
        self.assertIsNotNone(second["manifest_fingerprint"])
        # 封存指纹是绑定了校验和与两人确认顺序的 v2 指纹
        from service_09252_006.domain.fingerprint import manifest_fingerprint_v2

        pkg = self.h.repo.get_package(self.pid)
        recomputed = manifest_fingerprint_v2(
            pkg.package_id,
            pkg.institution_id,
            [
                {
                    "material_id": e.material_id,
                    "version_id": e.version_id,
                    "sha256": e.sha256,
                    "kind": e.kind,
                    "sensitivity": e.sensitivity,
                }
                for e in pkg.entries
            ],
            pkg.sealed_at,
            [
                {
                    "seq": c.seq,
                    "role": c.role,
                    "confirmer_id": c.confirmer_id,
                    "sha256": c.sha256,
                    "confirmed_at": c.confirmed_at,
                }
                for c in self.h.repo.list_seal_confirmations(self.pid)
            ],
        )
        self.assertEqual(second["manifest_fingerprint"], recomputed)
        self.assertEqual(pkg.manifest_fingerprint, recomputed)

    def test_seal_status_exposes_digest_before_confirmation(self) -> None:
        status = self.h.ctx.packages.get_seal_status(self.admin, self.pid)
        self.assertFalse(status["sealed"])
        self.assertEqual(status["seal_content_digest"], self._digest())
        self.assertEqual(status["active_confirmation_count"], 0)

    # ------------------------------------------------------- 角色/人员约束
    def test_same_role_cannot_be_second_confirmer(self) -> None:
        self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        with self.assertRaises(ConflictError) as cm:
            self.h.ctx.packages.confirm_seal(self.admin2, package_id=self.pid)
        self.assertIn("另一种角色", cm.exception.message)

    def test_same_person_cannot_confirm_twice(self) -> None:
        self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        # 同一人重复确认只是幂等回放，不会产生第二条
        replay = self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["active_confirmation_count"], 1)

    def test_authority_can_go_first_admin_second(self) -> None:
        # 顺序不固定：权威机构先、管理员后，同样成立
        self.h.ctx.packages.confirm_seal(self.authority, package_id=self.pid)
        sealed = self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        self.assertTrue(sealed["sealed"])
        seqs = [(c["seq"], c["role"]) for c in sealed["confirmations"]]
        self.assertEqual(
            seqs,
            [(1, "quality_authority"), (2, "institution_admin")],
        )

    def test_non_seal_role_cannot_confirm(self) -> None:
        submitter = self.h.user("sub", Role.INSTITUTION_SUBMITTER)
        reviewer = self.h.user("rev", Role.REVIEWER, institution_id="ext")
        for actor in (submitter, reviewer):
            with self.assertRaises(PermissionDeniedError):
                self.h.ctx.packages.confirm_seal(actor, package_id=self.pid)

    # ------------------------------------------------------------- 校验和
    def test_client_checksum_must_match_server_recompute(self) -> None:
        with self.assertRaises(ValidationError) as cm:
            self.h.ctx.packages.confirm_seal(
                self.admin, package_id=self.pid,
                content_sha256="sha256:" + "0" * 64,
            )
        self.assertEqual(cm.exception.details["computed"], self._digest())

        # 传入正确校验和可确认
        ok = self.h.ctx.packages.confirm_seal(
            self.admin, package_id=self.pid, content_sha256=self._digest()
        )
        self.assertEqual(ok["active_confirmation_count"], 1)

    # -------------------------------------------------- 首次确认即锁定清单
    def test_content_locks_after_first_confirmation(self) -> None:
        other = upload_material(self.h, self.admin, data=b"late")
        self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        with self.assertRaises(ConflictError) as cm:
            self.h.ctx.packages.add_entry(
                self.admin, package_id=self.pid,
                version_id=other.version["version_id"],
            )
        self.assertIn("锁定", cm.exception.message)
        # 锁定期间也未真正写入
        pkg = self.h.repo.get_package(self.pid)
        self.assertEqual(len(pkg.entries), 1)

    # --------------------------------------------------------------- 撤回
    def test_first_confirmer_can_withdraw_before_second_then_edit_and_reseal(self) -> None:
        other = upload_material(self.h, self.admin, data=b"added-after-withdraw")
        self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)

        withdrawn = self.h.ctx.packages.withdraw_seal_confirmation(
            self.admin, package_id=self.pid, reason="发现需补材料"
        )
        self.assertEqual(withdrawn["active_confirmation_count"], 0)
        self.assertEqual(withdrawn["confirmed_roles"], [])
        self.assertEqual(withdrawn["awaiting_role"],
                         ["institution_admin", "quality_authority"])
        # 撤回记录保留（追加留痕），但已不计入有效确认
        self.assertEqual(len(withdrawn["confirmations"]), 1)
        self.assertIsNotNone(withdrawn["confirmations"][0]["revoked_at"])
        self.assertEqual(withdrawn["confirmations"][0]["revoked_by"], "admin-a")

        # 撤回后包仍是草稿、恢复可改
        self.assertEqual(
            self.h.repo.get_package(self.pid).status, PackageStatus.DRAFT.value
        )
        self.h.ctx.packages.add_entry(
            self.admin, package_id=self.pid,
            version_id=other.version["version_id"],
        )

        # 重新双人封存成功（seq 重新从 1 开始，被撤回记录不挡路）
        self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        sealed = self.h.ctx.packages.confirm_seal(
            self.authority, package_id=self.pid
        )
        self.assertTrue(sealed["sealed"])
        active = [c for c in sealed["confirmations"] if c["revoked_at"] is None]
        self.assertEqual([c["seq"] for c in active], [1, 2])

    def test_cannot_withdraw_another_persons_confirmation(self) -> None:
        self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.withdraw_seal_confirmation(
                self.authority, package_id=self.pid
            )

    def test_cannot_withdraw_after_seal_completed(self) -> None:
        self.h.ctx.packages.confirm_seal(self.admin, package_id=self.pid)
        self.h.ctx.packages.confirm_seal(self.authority, package_id=self.pid)
        with self.assertRaises(ImmutabilityError):
            self.h.ctx.packages.withdraw_seal_confirmation(
                self.admin, package_id=self.pid
            )
        # 封存完成后确认记录仍在
        confirmations = self.h.repo.list_seal_confirmations(self.pid)
        self.assertEqual(len(confirmations), 2)
        self.assertTrue(all(c.revoked_at is None for c in confirmations))

    def test_withdraw_without_active_confirmation_conflicts(self) -> None:
        with self.assertRaises(ConflictError):
            self.h.ctx.packages.withdraw_seal_confirmation(
                self.admin, package_id=self.pid
            )

    # ----------------------------------------------------------- 幂等重放
    def test_confirm_is_idempotent_under_same_key(self) -> None:
        a = self.h.ctx.packages.confirm_seal(
            self.admin, package_id=self.pid, idempotency_key="confirm-1"
        )
        b = self.h.ctx.packages.confirm_seal(
            self.admin, package_id=self.pid, idempotency_key="confirm-1"
        )
        self.assertTrue(b["replayed"])
        self.assertEqual(
            a["active_confirmation_count"], b["active_confirmation_count"]
        )


if __name__ == "__main__":
    unittest.main()
