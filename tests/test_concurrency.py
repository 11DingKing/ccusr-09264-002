"""并发复审：多个独立连接（模拟多进程/worker）同时分配与签发。

条件状态迁移 + BEGIN IMMEDIATE 必须保证：
- 并发分配全部落库，包状态恰好推进一次到 under_review；
- 并发签发恰好一方成功，另一方回放同一结论。
"""
import concurrent.futures
import threading
import unittest

from service_09252_006.application.container import ApplicationContext
from service_09252_006.application.ports import SystemClock, Uuid4IdGenerator
from service_09252_006.domain.enums import Decision, Role
from service_09252_006.domain.errors import DomainError
from tests.flow import seal_new_package
from tests.support import Harness


class ConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.reviewers = [
            self.h.user(f"rev-{i}", Role.REVIEWER, institution_id=f"inst-ext-{i}")
            for i in range(6)
        ]
        self.sealed = seal_new_package(self.h, self.admin)
        self.pid = self.sealed.package_id

    def tearDown(self) -> None:
        self.h.close()

    def _worker_context(self) -> ApplicationContext:
        # 每个 worker 独立连接，等价于不同进程
        return ApplicationContext(
            self.h.db_path,
            clock=SystemClock(),
            ids=Uuid4IdGenerator(),
        )

    def test_concurrent_assignments_all_persist(self) -> None:
        errors: list[Exception] = []

        def assign(reviewer_id: str) -> None:
            ctx = self._worker_context()
            try:
                authority = ctx.repo.get_user("auth")
                ctx.reviews.assign_reviewer(
                    authority, package_id=self.pid, reviewer_id=reviewer_id
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                ctx.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(assign, [r.user_id for r in self.reviewers]))

        self.assertEqual(errors, [])
        reqs = self.h.repo.list_requests_by_package(self.pid)
        self.assertEqual(len(reqs), 6)
        pkg = self.h.repo.get_package(self.pid)
        self.assertEqual(pkg.status, "under_review")

    def test_concurrent_decisions_only_one_wins(self) -> None:
        # 主连接上完成评审
        reviewer = self.reviewers[0]
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority, package_id=self.pid, reviewer_id=reviewer.user_id
        )
        self.h.ctx.reviews.respond_assignment(
            reviewer, request_id=req["request_id"], accept=True
        )
        self.h.ctx.reviews.submit_verdict(
            reviewer, request_id=req["request_id"], verdict="approve"
        )

        outcomes: list[str] = []
        lock = threading.Lock()

        def issue(decision: str) -> None:
            ctx = self._worker_context()
            try:
                authority = ctx.repo.get_user("auth")
                result = ctx.reviews.issue_decision(
                    authority, package_id=self.pid, decision=decision
                )
                with lock:
                    outcomes.append(result["decision"])
            except DomainError as exc:
                with lock:
                    outcomes.append("error:" + exc.code)
            finally:
                ctx.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futs = [
                pool.submit(issue, Decision.APPROVED.value),
                pool.submit(issue, Decision.REJECTED.value),
            ]
            concurrent.futures.wait(futs)

        self.assertEqual(len(outcomes), 2)
        # 一个真正签发，另一个回放同一结论；二者一致
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertNotIn("error", outcomes[0])
        pkg = self.h.repo.get_package(self.pid)
        self.assertEqual(pkg.status, "decided")
        self.assertEqual(pkg.decision, outcomes[0])

    def test_concurrent_second_confirmation_and_withdraw_only_one_wins(self) -> None:
        # 单独造一个停在“第一人已确认”的草稿包
        from tests.flow import upload_material

        pkg = self.h.ctx.packages.create_package(self.admin, title="竞态封存")
        item = upload_material(self.h, self.admin, data=b"race")
        self.h.ctx.packages.add_entry(
            self.admin, package_id=pkg["package_id"],
            version_id=item.version["version_id"],
        )
        started = self.h.ctx.packages.start_seal_confirmation(
            self.admin, package_id=pkg["package_id"]
        )
        cid = started["confirmation_id"]
        pid = pkg["package_id"]
        outcomes: list[str] = []
        lock = threading.Lock()

        def confirm() -> None:
            ctx = self._worker_context()
            try:
                authority = ctx.repo.get_user("auth")
                ctx.packages.confirm_seal(
                    authority, package_id=pid, confirmation_id=cid
                )
                with lock:
                    outcomes.append("sealed")
            except DomainError:
                with lock:
                    outcomes.append("confirm_lost")
            finally:
                ctx.close()

        def withdraw() -> None:
            ctx = self._worker_context()
            try:
                admin = ctx.repo.get_user("admin-a")
                ctx.packages.withdraw_seal_confirmation(
                    admin, package_id=pid
                )
                with lock:
                    outcomes.append("withdrawn")
            except DomainError:
                with lock:
                    outcomes.append("withdraw_lost")
            finally:
                ctx.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futs = [pool.submit(confirm), pool.submit(withdraw)]
            concurrent.futures.wait(futs)

        self.assertEqual(len(outcomes), 2)
        self.assertEqual(len(set(outcomes)), 2)  # 一胜一负，不会同时成功
        pkg = self.h.repo.get_package(pid)
        if "sealed" in outcomes:
            self.assertEqual(pkg.status, "sealed")
        else:
            self.assertEqual(pkg.status, "draft")


if __name__ == "__main__":
    unittest.main()
