"""离线完整性核验。

不依赖时钟/写事务：打开数据库只读连接，重算所有内容字节摘要与每个
已封存包的清单指纹、已签发包的评审记录指纹，任何不一致或“已封存清单
引用了已撤回版本”都会被报告。CLI 命令与（未来的）在线接口共用本模块。
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from ..domain.fingerprint import (
    digest_bytes,
    manifest_fingerprint,
    manifest_fingerprint_v2,
    review_record_fingerprint,
    seal_content_digest,
)
from ..domain.enums import Role


@dataclass
class VerificationReport:
    ok: bool = True
    blob_count: int = 0
    package_count: int = 0
    sealed_count: int = 0
    decided_count: int = 0
    withdrawn_in_sealed: list[dict] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)

    def fail(self, kind: str, **detail) -> None:
        self.ok = False
        item = {"kind": kind}
        item.update(detail)
        self.failures.append(item)

    def warn(self, kind: str, **detail) -> None:
        item = {"kind": kind}
        item.update(detail)
        self.warnings.append(item)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "blob_count": self.blob_count,
            "package_count": self.package_count,
            "sealed_count": self.sealed_count,
            "decided_count": self.decided_count,
            "withdrawn_in_sealed": self.withdrawn_in_sealed,
            "failures": self.failures,
            "warnings": self.warnings,
        }


def verify_database(path: str) -> VerificationReport:
    """对数据库文件做完整离线核验。只读打开，绝不写入。"""
    report = VerificationReport()
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        _verify_blobs(conn, report)
        _verify_packages(conn, report)
    finally:
        conn.close()
    return report


def _verify_blobs(conn: sqlite3.Connection, report: VerificationReport) -> None:
    rows = conn.execute(
        "SELECT sha256, data, size, media_type FROM blobs"
    ).fetchall()
    report.blob_count = len(rows)
    for row in rows:
        raw = row["data"]
        if not isinstance(raw, bytes):
            report.fail(
                "blob_type_mismatch",
                stored=row["sha256"],
                actual_type=type(raw).__name__,
            )
            continue
        data = raw
        actual = digest_bytes(data)
        if actual != row["sha256"]:
            report.fail(
                "blob_digest_mismatch",
                stored=row["sha256"],
                actual=actual,
            )
        if len(data) != row["size"]:
            report.fail(
                "blob_size_mismatch",
                sha256=row["sha256"],
                stored_size=row["size"],
                actual_size=len(data),
            )


def _verify_packages(conn: sqlite3.Connection, report: VerificationReport) -> None:
    packages = conn.execute("SELECT * FROM packages").fetchall()
    report.package_count = len(packages)

    table_names = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }

    # version_id -> withdrawn，供封存清单引用检查
    withdrawn_versions = {
        r["version_id"]: bool(r["withdrawn"])
        for r in conn.execute("SELECT version_id, withdrawn FROM versions")
    }

    for pkg in packages:
        entries = conn.execute(
            "SELECT * FROM entries WHERE package_id = ?"
            " ORDER BY material_id, version_id",
            (pkg["package_id"],),
        ).fetchall()

        # 条目声明的 sha256 必须与版本表一致，且字节可重算
        for entry in entries:
            version = conn.execute(
                "SELECT sha256, withdrawn FROM versions WHERE version_id = ?",
                (entry["version_id"],),
            ).fetchone()
            if version is None:
                report.fail(
                    "entry_version_missing",
                    package_id=pkg["package_id"],
                    version_id=entry["version_id"],
                )
                continue
            if version["sha256"] != entry["sha256"]:
                report.fail(
                    "entry_digest_drift",
                    package_id=pkg["package_id"],
                    version_id=entry["version_id"],
                    entry_sha256=entry["sha256"],
                    version_sha256=version["sha256"],
                )
            blob = conn.execute(
                "SELECT data FROM blobs WHERE sha256 = ?", (entry["sha256"],)
            ).fetchone()
            if blob is None:
                report.fail(
                    "blob_missing",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )
            elif not isinstance(blob["data"], bytes):
                report.fail(
                    "blob_type_mismatch",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )
            elif digest_bytes(blob["data"]) != entry["sha256"]:
                report.fail(
                    "blob_tampered",
                    package_id=pkg["package_id"],
                    sha256=entry["sha256"],
                )

        entry_payload = [
            {
                "material_id": e["material_id"],
                "version_id": e["version_id"],
                "sha256": e["sha256"],
                "kind": e["kind"],
                "sensitivity": e["sensitivity"],
            }
            for e in entries
        ]

        if pkg["status"] in ("sealed", "under_review", "decided"):
            report.sealed_count += 1

            confirmations = []
            if "seal_confirmations" in table_names:
                confirmations = conn.execute(
                    "SELECT * FROM seal_confirmations WHERE package_id = ?"
                    " AND revoked_at IS NULL ORDER BY seq",
                    (pkg["package_id"],),
                ).fetchall()

            stored = pkg["manifest_fingerprint"]
            if confirmations:
                expected = manifest_fingerprint_v2(
                    pkg["package_id"],
                    pkg["institution_id"],
                    entry_payload,
                    pkg["sealed_at"],
                    [
                        {
                            "seq": c["seq"],
                            "role": c["role"],
                            "confirmer_id": c["confirmer_id"],
                            "sha256": c["sha256"],
                            "confirmed_at": c["confirmed_at"],
                        }
                        for c in confirmations
                    ],
                )
                _verify_dual_seal(conn, pkg, entry_payload, confirmations, report)
            else:
                # 历史库（v1 单人封存）：按 v1 指纹核验
                expected = manifest_fingerprint(
                    pkg["package_id"],
                    pkg["institution_id"],
                    entry_payload,
                    pkg["sealed_at"],
                )
            if stored != expected:
                report.fail(
                    "manifest_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    stored=stored,
                    expected=expected,
                )

            # 撤回不破坏历史指纹，但必须显式标注：该包引用的材料事后被撤回
            for e in entries:
                if withdrawn_versions.get(e["version_id"]):
                    report.withdrawn_in_sealed.append(
                        {
                            "package_id": pkg["package_id"],
                            "version_id": e["version_id"],
                            "material_id": e["material_id"],
                        }
                    )
                    report.warn(
                        "sealed_entry_withdrawn",
                        package_id=pkg["package_id"],
                        version_id=e["version_id"],
                    )

        if pkg["status"] == "decided":
            report.decided_count += 1
            requests = [
                {
                    "request_id": r["request_id"],
                    "reviewer_id": r["reviewer_id"],
                    "status": r["status"],
                    "verdict": r["verdict"],
                    "comment": r["comment"],
                    "assigned_at": r["assigned_at"],
                    "completed_at": r["completed_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM requests WHERE package_id = ? ORDER BY request_id",
                    (pkg["package_id"],),
                )
            ]
            objections = [
                {
                    "objection_id": r["objection_id"],
                    "request_id": r["request_id"],
                    "reviewer_id": r["reviewer_id"],
                    "category": r["category"],
                    "detail": r["detail"],
                    "created_at": r["created_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM objections WHERE package_id = ? ORDER BY objection_id",
                    (pkg["package_id"],),
                )
            ]
            expected_review = review_record_fingerprint(
                pkg["package_id"],
                pkg["manifest_fingerprint"],
                requests,
                objections,
            )
            if pkg["review_fingerprint"] != expected_review:
                report.fail(
                    "review_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    stored=pkg["review_fingerprint"],
                    expected=expected_review,
                )


def _verify_dual_seal(
    conn: sqlite3.Connection,
    pkg: sqlite3.Row,
    entry_payload: list[dict],
    confirmations: list[sqlite3.Row],
    report: VerificationReport,
) -> None:
    """双人封存的离线不变量：两人、两种角色、同校验和、顺序为 1/2。"""
    pid = pkg["package_id"]
    expected_digest = seal_content_digest(entry_payload)
    expected_roles = {Role.INSTITUTION_ADMIN.value, Role.QUALITY_AUTHORITY.value}

    if len(confirmations) != 2:
        report.fail(
            "seal_confirmation_count_invalid",
            package_id=pid, count=len(confirmations), expected=2,
        )
        return

    seqs = sorted(c["seq"] for c in confirmations)
    if seqs != [1, 2]:
        report.fail(
            "seal_confirmation_order_invalid",
            package_id=pid, seqs=seqs, expected=[1, 2],
        )

    roles = {c["role"] for c in confirmations}
    if roles != expected_roles:
        report.fail(
            "seal_confirmation_roles_invalid",
            package_id=pid, roles=sorted(roles), expected=sorted(expected_roles),
        )

    people = [c["confirmer_id"] for c in confirmations]
    if len(set(people)) != 2:
        report.fail(
            "seal_confirmation_same_person",
            package_id=pid, confirmers=people,
        )

    for c in confirmations:
        if c["sha256"] != expected_digest:
            report.fail(
                "seal_confirmation_digest_mismatch",
                package_id=pid, confirmer_id=c["confirmer_id"], seq=c["seq"],
                stored=c["sha256"], expected=expected_digest,
            )

    # 已封存包不应残留“进行中（已撤回）”的确认之外的有效冲突：仅核验
    # 不存在与封存校验和不一致的、被撤回后遗留的不同内容确认（信息性警告）。
    revoked = conn.execute(
        "SELECT COUNT(*) AS n FROM seal_confirmations"
        " WHERE package_id = ? AND revoked_at IS NOT NULL",
        (pid,),
    ).fetchone()["n"]
    if revoked:
        report.warn(
            "seal_confirmation_revoked_history",
            package_id=pid, revoked_count=revoked,
        )
