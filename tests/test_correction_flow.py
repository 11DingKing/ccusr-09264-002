"""封存后更正流程：任何改动都必须走更正（append-only），由复审包承接。"""
import unittest

from service_09252_006.domain.enums import Decision, Role
from service_09252_006.domain.errors import (
    ConflictError,
    CorrectionRequiredError,
    PermissionDeniedError,
)
from tests.flow import complete_review, seal_new_package, upload_material
from tests.support import Harness


class CorrectionFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.sealed = seal_new_package(self.h, self.admin)
        self.pid = self.sealed.package_id

    def tearDown(self) -> None:
        self.h.close()

    def test_direct_change_after_seal_requires_correction(self) -> None:
        late = upload_material(self.h, self.admin, data=b"late")
        with self.assertRaises(CorrectionRequiredError) as cm:
            self.h.ctx.packages.add_entry(
                self.admin, package_id=self.pid,
                version_id=late.version["version_id"],
            )
        self.assertEqual(cm.exception.code, "correction_required")
        # 清单未被改动
        self.assertEqual(
            len(self.h.repo.get_package(self.pid).entries),
            len(self.sealed.items),
        )

    def test_request_correction_is_append_only_and_persisted(self) -> None:
        c = self.h.ctx.packages.request_correction(
            self.admin, package_id=self.pid,
            reason="企业反馈需替换为最新季度数据",
            material_id=self.sealed.items[1].material["material_id"],
            version_id=self.sealed.items[1].version["version_id"],
            note="会后补正",
        )
        self.assertEqual(c["status"], "requested")
        self.assertEqual(c["requester_id"], "admin-a")
        self.assertIsNone(c["successor_package_id"])

        # 再登记一条更正：两条都保留（append-only）
        c2 = self.h.ctx.packages.request_correction(
            self.authority, package_id=self.pid, reason="大纲版本号修正"
        )
        listed = self.h.ctx.packages.list_corrections(self.admin, self.pid)
        self.assertEqual([x["correction_id"] for x in listed],
                         [c["correction_id"], c2["correction_id"]])
        # 更正登记不改变已封存证据
        pkg = self.h.repo.get_package(self.pid)
        self.assertEqual(pkg.manifest_fingerprint,
                         self.sealed.sealed["manifest_fingerprint"])

    def test_correction_on_draft_rejected(self) -> None:
        item = upload_material(self.h, self.admin, data=b"x")
        pkg = self.h.ctx.packages.create_package(self.admin, title="草稿")
        self.h.ctx.packages.add_entry(
            self.admin, package_id=pkg["package_id"],
            version_id=item.version["version_id"],
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.packages.request_correction(
                self.admin, package_id=pkg["package_id"], reason="草稿无需更正"
            )

    def test_correction_requires_seal_role(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.request_correction(
                self.submitter, package_id=self.pid, reason="无权"
            )

    def test_correction_carried_into_rereview_after_decision(self) -> None:
        # 封存后登记更正
        correction = self.h.ctx.packages.request_correction(
            self.admin, package_id=self.pid, reason="需要补充考核说明"
        )
        # 评审并签发
        complete_review(self.h, self.authority, self.reviewer, self.pid)
        self.h.ctx.reviews.issue_decision(
            self.authority, package_id=self.pid,
            decision=Decision.NEEDS_REVISION.value,
        )
        # 发起复审包：原更正被承接（applied）
        re = self.h.ctx.packages.create_package(
            self.admin, title="复审", supersedes_package_id=self.pid
        )
        updated = self.h.repo.get_correction(correction["correction_id"])
        self.assertEqual(updated.status, "applied")
        self.assertEqual(updated.successor_package_id, re["package_id"])

        # 原包的更正记录仍在，且原包本身未被改动
        self.assertEqual(
            self.h.repo.get_package(self.pid).manifest_fingerprint,
            self.sealed.sealed["manifest_fingerprint"],
        )

    def test_correction_allowed_while_under_review(self) -> None:
        complete_review(self.h, self.authority, self.reviewer, self.pid)
        # 已处于 under_review
        self.assertEqual(
            self.h.repo.get_package(self.pid).status, "under_review"
        )
        c = self.h.ctx.packages.request_correction(
            self.authority, package_id=self.pid, reason="评审中发现问题"
        )
        self.assertEqual(c["status"], "requested")


if __name__ == "__main__":
    unittest.main()
