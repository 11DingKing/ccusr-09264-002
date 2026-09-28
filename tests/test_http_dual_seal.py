"""HTTP 端到端：双人封存、第二人确认前撤回、封存后更正必须走更正流程。"""
import base64
import unittest

from service_09252_006.api.http_api import HttpApiServer
from tests.support import Harness
from tests.test_http_api import ApiClient


class HttpDualSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot-secret")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _user(self, user_id, roles, institution_id=None, token=None):
        status, _ = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        self.assertEqual(status, 201)
        if token:
            status, _ = self.boot.request(
                "POST", "/v1/admin/tokens",
                {"user_id": user_id, "token": token},
            )
            self.assertEqual(status, 201)
        return ApiClient(self.base, token=token)

    def _package_with_one_entry(self, admin):
        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "大纲", "sensitivity": "normal"},
        )
        self.assertEqual(status, 201)
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(b"v1").decode("ascii")},
        )
        self.assertEqual(status, 201)
        status, pkg = admin.request("POST", "/v1/packages", {"title": "P"})
        self.assertEqual(status, 201)
        pid = pkg["package_id"]
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        return pid, ver

    def test_two_role_confirmations_over_http(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        authority = self._user("auth", ["quality_authority"], None, "t-auth")
        pid, _ = self._package_with_one_entry(admin)

        status, first = admin.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        self.assertFalse(first["sealed"])
        self.assertEqual(first["active_confirmation_count"], 1)

        # 第二种角色才能完成封存
        status, second = authority.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        self.assertTrue(second["sealed"])
        self.assertEqual(second["status"], "sealed")
        self.assertEqual(second["active_confirmation_count"], 2)

        # GET 封存状态
        status, view = admin.request("GET", f"/v1/packages/{pid}/seal")
        self.assertEqual(status, 200)
        self.assertTrue(view["sealed"])
        self.assertEqual([c["role"] for c in view["confirmations"]],
                         ["institution_admin", "quality_authority"])

    def test_withdraw_before_second_confirmation_then_reseal(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        authority = self._user("auth", ["quality_authority"], None, "t-auth")
        pid, ver = self._package_with_one_entry(admin)

        status, _ = admin.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)

        # 第二人确认前，第一人撤回
        status, withdrawn = admin.request(
            "POST", f"/v1/packages/{pid}/seal/withdrawal",
            {"reason": "还要补一份材料"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(withdrawn["active_confirmation_count"], 0)
        self.assertFalse(withdrawn["sealed"])

        # 撤回后可追加材料（包恢复 draft）
        status, mat2 = admin.request(
            "POST", "/v1/materials",
            {"kind": "assessment", "title": "考核", "sensitivity": "normal"},
        )
        status, ver2 = admin.request(
            "POST", f"/v1/materials/{mat2['material_id']}/versions",
            {"content_base64": base64.b64encode(b"v2").decode("ascii")},
        )
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver2["version_id"]},
        )
        self.assertEqual(status, 201)

        # 重新双人封存
        status, _ = admin.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        status, sealed = authority.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        self.assertTrue(sealed["sealed"])

    def test_cannot_withdraw_after_sealed(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        authority = self._user("auth", ["quality_authority"], None, "t-auth")
        pid, _ = self._package_with_one_entry(admin)

        admin.request("POST", f"/v1/packages/{pid}/seal", {})
        authority.request("POST", f"/v1/packages/{pid}/seal", {})

        status, body = admin.request(
            "POST", f"/v1/packages/{pid}/seal/withdrawal", {"reason": "x"}
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "immutability_violation")

    def test_post_seal_change_rejected_then_correction_and_rereview(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        authority = self._user("auth", ["quality_authority"], None, "t-auth")
        reviewer = self._user("rev-1", ["reviewer"], "inst-ext", "t-rev")
        pid, ver = self._package_with_one_entry(admin)

        admin.request("POST", f"/v1/packages/{pid}/seal", {})
        status, sealed = authority.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertTrue(sealed["sealed"])

        # 封存后直接追加：409 correction_required
        status, mat2 = admin.request(
            "POST", "/v1/materials",
            {"kind": "assessment", "title": "后补考核", "sensitivity": "normal"},
        )
        status, ver2 = admin.request(
            "POST", f"/v1/materials/{mat2['material_id']}/versions",
            {"content_base64": base64.b64encode(b"late").decode("ascii")},
        )
        status, body = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver2["version_id"]},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "correction_required")

        # 改走更正流程：登记更正
        status, correction = admin.request(
            "POST", f"/v1/packages/{pid}/corrections",
            {"reason": "补充考核材料", "version_id": ver2["version_id"]},
        )
        self.assertEqual(status, 201)
        self.assertEqual(correction["status"], "requested")
        status, listing = admin.request("GET", f"/v1/packages/{pid}/corrections")
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["corrections"]), 1)

        # 评审 → 签发 → 复审包承接更正
        status, req = authority.request(
            "POST", f"/v1/packages/{pid}/assignments",
            {"reviewer_id": "rev-1"},
        )
        rid = req["request_id"]
        reviewer.request("POST", f"/v1/requests/{rid}/respond", {"accept": True})
        reviewer.request(
            "POST", f"/v1/requests/{rid}/verdict",
            {"verdict": "approve", "comment": "通过"},
        )
        status, decision = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "needs_revision", "note": "补正后复审"},
        )
        self.assertEqual(status, 200)

        status, rereview = admin.request(
            "POST", "/v1/packages",
            {"title": "复审", "supersedes_package_id": pid},
        )
        self.assertEqual(status, 201)
        new_pid = rereview["package_id"]

        # 原更正已被复审包承接
        status, listing2 = admin.request("GET", f"/v1/packages/{pid}/corrections")
        self.assertEqual(status, 200)
        self.assertEqual(listing2["corrections"][0]["status"], "applied")
        self.assertEqual(
            listing2["corrections"][0]["successor_package_id"], new_pid
        )

    def test_same_role_second_confirmation_rejected(self) -> None:
        admin = self._user("admin-a", ["institution_admin"], "inst-a", "t-admin")
        admin2 = self._user("admin-b", ["institution_admin"], "inst-a", "t-admin2")
        pid, _ = self._package_with_one_entry(admin)

        admin.request("POST", f"/v1/packages/{pid}/seal", {})
        status, body = admin2.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "conflict")


if __name__ == "__main__":
    unittest.main()
