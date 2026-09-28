"""HTTP API 端到端：真实启动服务，经 HTTP 走完整流程与鉴权。"""
import base64
import json
import unittest
import urllib.error
import urllib.request

from service_09252_006.api.http_api import HttpApiServer
from service_09252_006.application.container import ApplicationContext
from tests.support import Harness


class ApiClient:
    def __init__(self, base_url: str, token: str | None = None,
                 bootstrap: str | None = None) -> None:
        self.base_url = base_url
        self.token = token
        self.bootstrap = bootstrap

    def request(self, method: str, path: str, body=None,
                idempotency_key=None, raw=False):
        url = self.base_url + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.bootstrap:
            headers["X-Bootstrap-Token"] = self.bootstrap
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload, dict(resp.headers)
                return resp.status, json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            if raw:
                return exc.code, payload, dict(exc.headers)
            try:
                return exc.code, json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError:
                return exc.code, {"raw": payload.decode("utf-8")}


class HttpApiTests(unittest.TestCase):
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

    def _create_user(self, user_id, roles, institution_id=None, token=None):
        status, body = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        self.assertEqual(status, 201, body)
        if token:
            status, body = self.boot.request(
                "POST", "/v1/admin/tokens",
                {"user_id": user_id, "token": token},
            )
            self.assertEqual(status, 201, body)
        return ApiClient(self.base, token=token)

    def test_end_to_end_over_http_with_minimal_disclosure(self) -> None:
        admin = self._create_user(
            "admin-a", ["institution_admin"], "inst-a", "tok-admin"
        )
        submitter = self._create_user(
            "sub-a", ["institution_submitter"], "inst-a", "tok-sub"
        )
        authority = self._create_user(
            "auth", ["quality_authority"], None, "tok-auth"
        )
        reviewer = self._create_user(
            "rev-1", ["reviewer"], "inst-ext", "tok-rev"
        )

        # 未认证被拒
        status, body = ApiClient(self.base).request("GET", "/v1/packages")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "permission_denied")

        # 引导端点需要 bootstrap token
        status, body = ApiClient(self.base).request(
            "POST", "/v1/admin/users",
            {"user_id": "x", "roles": [], "institution_id": None},
        )
        self.assertEqual(status, 403)

        # 接收证据
        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "enterprise_feedback", "title": "企业反馈",
             "sensitivity": "sensitive"},
        )
        self.assertEqual(status, 201)
        content = "敏感：企业 X 要求不具名".encode("utf-8")
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii"),
             "media_type": "text/plain"},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        # 幂等重放
        status, ver2 = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii")},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        self.assertEqual(ver["version_id"], ver2["version_id"])
        self.assertTrue(ver2["replayed"])

        # 组包 + 双人封存
        status, pkg = admin.request("POST", "/v1/packages", {"title": "2026秋"})
        pid = pkg["package_id"]
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        # 第一确认人（机构管理员）启动
        status, started = admin.request(
            "POST", f"/v1/packages/{pid}/seal/start", {}
        )
        self.assertEqual(status, 201, started)
        cid = started["confirmation_id"]
        self.assertEqual(started["status"], "pending")
        self.assertTrue(started["content_checksum"].startswith("sha256:"))
        # 同一人不能充当第二确认人
        status, body = admin.request(
            "POST", f"/v1/packages/{pid}/seal/confirm",
            {"confirmation_id": cid},
        )
        self.assertEqual(status, 403)
        # 第二确认人（质量权威机构，另一角色）确认后封存生效
        status, sealed = authority.request(
            "POST", f"/v1/packages/{pid}/seal/confirm",
            {"confirmation_id": cid},
        )
        self.assertEqual(status, 200, sealed)
        self.assertEqual(sealed["status"], "sealed")
        self.assertIn("manifest_fingerprint", sealed)
        self.assertEqual(sealed["confirmation_id"], cid)

        # 提交人看不到敏感反馈内容
        status, view = submitter.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 200)
        self.assertTrue(view["entries"][0]["redacted"])
        status, resp = submitter.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
        )
        self.assertEqual(status, 403)

        # 分配评审后可见可下载
        status, req = authority.request(
            "POST", f"/v1/packages/{pid}/assignments",
            {"reviewer_id": "rev-1",
             "deadline_local_iso": "2026-09-25T18:00",
             "deadline_timezone": "Asia/Shanghai"},
        )
        self.assertEqual(status, 201)
        rid = req["request_id"]
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/respond", {"accept": True}
        )
        self.assertEqual(status, 200)
        status, payload, headers = reviewer.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
            raw=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, content)
        self.assertEqual(headers["X-Content-Sha256"], ver["sha256"])

        # 评审通过并签发
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/verdict",
            {"verdict": "approve", "comment": "材料齐备"},
        )
        self.assertEqual(status, 200)
        status, decision = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "approved", "note": "通过"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        status, decision2 = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "rejected", "note": "重复请求应回放"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(decision2["decision"], "approved")
        self.assertTrue(decision2["replayed"])

    def test_health(self) -> None:
        status, body = ApiClient(self.base).request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])


class HttpDualSealTests(unittest.TestCase):
    """HTTP 层双人封存：第二人确认前撤回、封存后更正全走真实 HTTP。"""

    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot-secret")
        self.admin = self._user("admin-a", ["institution_admin"], "inst-a", "tok-admin")
        self.authority = self._user(
            "auth", ["quality_authority"], None, "tok-auth"
        )
        self.reviewer = self._user(
            "rev-1", ["reviewer"], "inst-ext", "tok-rev"
        )

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _user(self, user_id, roles, institution_id, token):
        status, _ = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        self.assertEqual(status, 201)
        status, _ = self.boot.request(
            "POST", "/v1/admin/tokens",
            {"user_id": user_id, "token": token},
        )
        self.assertEqual(status, 201)
        return ApiClient(self.base, token=token)

    def _draft_package_with_one_entry(self):
        status, mat = self.admin.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "大纲", "sensitivity": "normal"},
        )
        self.assertEqual(status, 201)
        content = b"syllabus-bytes"
        status, ver = self.admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii"),
             "media_type": "text/plain"},
        )
        self.assertEqual(status, 201)
        status, pkg = self.admin.request("POST", "/v1/packages", {"title": "P"})
        self.assertEqual(status, 201)
        pid = pkg["package_id"]
        status, _ = self.admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        return pid, ver

    def test_withdraw_before_second_confirmation_then_reseal(self) -> None:
        pid, _ = self._draft_package_with_one_entry()

        # 第一人启动
        status, started = self.admin.request(
            "POST", f"/v1/packages/{pid}/seal/start", {}
        )
        self.assertEqual(status, 201)
        cid = started["confirmation_id"]
        self.assertEqual(started["status"], "pending")

        # 评审人无权撤回
        status, body = self.reviewer.request(
            "POST", f"/v1/packages/{pid}/seal/withdraw", {"reason": "无权"}
        )
        self.assertEqual(status, 403)

        # 第二人确认前任一封存角色可撤回（此处第一人自己撤回）
        status, withdrawn = self.admin.request(
            "POST", f"/v1/packages/{pid}/seal/withdraw",
            {"confirmation_id": cid, "reason": "发现材料版本待核对"},
        )
        self.assertEqual(status, 200, withdrawn)
        self.assertEqual(withdrawn["status"], "cancelled")
        self.assertEqual(withdrawn["withdraw_reason"], "发现材料版本待核对")

        # 撤回后确认作废：第二人再确认应 409
        status, body = self.authority.request(
            "POST", f"/v1/packages/{pid}/seal/confirm",
            {"confirmation_id": cid},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "conflict")

        # 包仍是 draft
        status, view = self.admin.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 200)
        self.assertEqual(view["status"], "draft")

        # 重新双人封存成功
        status, started2 = self.admin.request(
            "POST", f"/v1/packages/{pid}/seal/start", {}
        )
        self.assertEqual(status, 201)
        status, sealed = self.authority.request(
            "POST", f"/v1/packages/{pid}/seal/confirm",
            {"confirmation_id": started2["confirmation_id"]},
        )
        self.assertEqual(status, 200, sealed)
        self.assertEqual(sealed["status"], "sealed")

        # 留痕包含一次 cancelled、一次 sealed
        status, listing = self.admin.request("GET", f"/v1/packages/{pid}/seal")
        self.assertEqual(status, 200)
        statuses = [c["status"] for c in listing["confirmations"]]
        self.assertEqual(statuses, ["cancelled", "sealed"])

    def test_post_seal_change_requires_correction_flow(self) -> None:
        pid, ver = self._draft_package_with_one_entry()
        status, started = self.admin.request(
            "POST", f"/v1/packages/{pid}/seal/start", {}
        )
        self.assertEqual(status, 201)
        status, sealed = self.authority.request(
            "POST", f"/v1/packages/{pid}/seal/confirm",
            {"confirmation_id": started["confirmation_id"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(sealed["status"], "sealed")

        # 封存后直接追加材料 → 409 immutability_violation
        content2 = b"late-file"
        status, mat2 = self.admin.request(
            "POST", "/v1/materials",
            {"kind": "assessment", "title": "后补", "sensitivity": "normal"},
        )
        self.assertEqual(status, 201)
        status, ver2 = self.admin.request(
            "POST", f"/v1/materials/{mat2['material_id']}/versions",
            {"content_base64": base64.b64encode(content2).decode("ascii")},
        )
        self.assertEqual(status, 201)
        status, body = self.admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver2["version_id"]},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "immutability_violation")

        # 直接改标题没有端点；任何改动须走更正流程
        # 草稿包不允许更正（这里包已封存，允许）
        status, corr = self.admin.request(
            "POST", f"/v1/packages/{pid}/corrections",
            {"correction_type": "metadata", "reason": "标题笔误",
             "detail": {"title": "P（已订正）"}},
            idempotency_key="corr-1",
        )
        self.assertEqual(status, 201, corr)
        cor_id = corr["correction_id"]
        self.assertEqual(corr["status"], "pending")

        # 申请人不能自批
        status, body = self.admin.request(
            "POST", f"/v1/corrections/{cor_id}/review",
            {"approve": True},
        )
        self.assertEqual(status, 403)
        # 评审人不能审批
        status, body = self.reviewer.request(
            "POST", f"/v1/corrections/{cor_id}/review",
            {"approve": True},
        )
        self.assertEqual(status, 403)
        # 另一封存角色批准（带幂等键）
        status, reviewed = self.authority.request(
            "POST", f"/v1/corrections/{cor_id}/review",
            {"approve": True, "note": "同意"},
            idempotency_key="corr-review-1",
        )
        self.assertEqual(status, 200, reviewed)
        self.assertEqual(reviewed["status"], "applied")
        self.assertIsNotNone(reviewed["change_fingerprint"])

        # 审批幂等重放：同键重发回放同一结果，不重复处理
        status, replay = self.authority.request(
            "POST", f"/v1/corrections/{cor_id}/review",
            {"approve": False, "note": "重发应回放"},
            idempotency_key="corr-review-1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["status"], "applied")
        self.assertTrue(replay["replayed"])

        status, view = self.admin.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(view["title"], "P（已订正）")
        # 清单指纹不变
        self.assertEqual(view["manifest_fingerprint"], sealed["manifest_fingerprint"])

        # 更正记录可列
        status, listing = self.admin.request(
            "GET", f"/v1/packages/{pid}/corrections"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["corrections"]), 1)
        self.assertEqual(listing["corrections"][0]["status"], "applied")


if __name__ == "__main__":
    unittest.main()
