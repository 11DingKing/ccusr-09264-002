"""离线完整性核验。

不依赖时钟/写事务：打开数据库只读连接，重算所有内容字节摘要与每个
已封存包的清单指纹、已签发包的评审记录指纹，任何不一致或“已封存清单
引用了已撤回版本”都会被报告。CLI 命令与（未来的）在线接口共用本模块。
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from ..domain.fingerprint import (
    correction_fingerprint,
    digest_bytes,
    manifest_content_checksum,
    manifest_fingerprint,
    review_record_fingerprint,
)

_SEAL_ROLES = {"institution_admin", "quality_authority"}


@dataclass
class VerificationReport:
    ok: bool = True
    blob_count: int = 0
    package_count: int = 0
    sealed_count: int = 0
    decided_count: int = 0
    seal_confirmation_count: int = 0
    correction_count: int = 0
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
            "seal_confirmation_count": self.seal_confirmation_count,
            "correction_count": self.correction_count,
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

        if pkg["status"] in ("sealed", "under_review", "decided"):
            report.sealed_count += 1
            expected = manifest_fingerprint(
                pkg["package_id"],
                pkg["institution_id"],
                [
                    {
                        "material_id": e["material_id"],
                        "version_id": e["version_id"],
                        "sha256": e["sha256"],
                        "kind": e["kind"],
                        "sensitivity": e["sensitivity"],
                    }
                    for e in entries
                ],
                pkg["sealed_at"],
            )
            stored = pkg["manifest_fingerprint"]
            if stored != expected:
                report.fail(
                    "manifest_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    stored=stored,
                    expected=expected,
                )

            _verify_seal_confirmations(conn, report, pkg, entries)

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

        _verify_corrections(conn, report, pkg)

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


def _entry_payloads(entries) -> list[dict]:
    return [
        {
            "material_id": e["material_id"],
            "version_id": e["version_id"],
            "sha256": e["sha256"],
            "kind": e["kind"],
            "sensitivity": e["sensitivity"],
        }
        for e in entries
    ]


def _verify_seal_confirmations(conn, report, pkg, entries) -> None:
    """双人封存留痕核验：两人两角色、校验和与封存指纹可复算。"""
    if not _table_exists(conn, "seal_confirmations"):
        rows = []
    else:
        rows = conn.execute(
            "SELECT * FROM seal_confirmations WHERE package_id = ?"
            " ORDER BY first_confirmed_at",
            (pkg["package_id"],),
        ).fetchall()
    report.seal_confirmation_count += len(rows)

    sealed_rows = [r for r in rows if r["status"] == "sealed"]
    if not sealed_rows:
        # 旧库（双人封存上线前封存的包）没有留痕：警告而非失败
        report.warn(
            "seal_confirmation_missing",
            package_id=pkg["package_id"],
        )
        return
    if len(sealed_rows) > 1:
        report.fail(
            "seal_confirmation_multiple_sealed",
            package_id=pkg["package_id"],
            count=len(sealed_rows),
        )

    content_expected = manifest_content_checksum(
        pkg["package_id"], pkg["institution_id"], _entry_payloads(entries)
    )
    for r in sealed_rows:
        if r["content_checksum"] != content_expected:
            report.fail(
                "seal_content_checksum_mismatch",
                package_id=pkg["package_id"],
                confirmation_id=r["confirmation_id"],
                stored=r["content_checksum"],
                expected=content_expected,
            )
        if r["sealed_manifest_fingerprint"] != pkg["manifest_fingerprint"]:
            report.fail(
                "seal_manifest_fingerprint_mismatch",
                package_id=pkg["package_id"],
                confirmation_id=r["confirmation_id"],
                stored=r["sealed_manifest_fingerprint"],
                expected=pkg["manifest_fingerprint"],
            )
        roles = {r["first_confirmer_role"], r["second_confirmer_role"]}
        if roles != _SEAL_ROLES:
            report.fail(
                "seal_confirmation_roles_invalid",
                package_id=pkg["package_id"],
                confirmation_id=r["confirmation_id"],
                roles=sorted(roles),
            )
        if not r["first_confirmer_id"] or r["first_confirmer_id"] == r["second_confirmer_id"]:
            report.fail(
                "seal_confirmation_same_user",
                package_id=pkg["package_id"],
                confirmation_id=r["confirmation_id"],
            )
        if not r["first_confirmed_at"] or not r["second_confirmed_at"]:
            report.fail(
                "seal_confirmation_missing_timestamp",
                package_id=pkg["package_id"],
                confirmation_id=r["confirmation_id"],
            )

    # 已封存包上不应残留 pending 确认（撤回/完成都应终结它）
    for r in rows:
        if r["status"] == "pending":
            report.fail(
                "seal_confirmation_still_pending",
                package_id=pkg["package_id"],
                confirmation_id=r["confirmation_id"],
            )


def _verify_corrections(conn, report, pkg) -> None:
    """封存后更正留痕核验：状态合法、审批角色隔离、变更指纹可复算。"""
    if not _table_exists(conn, "correction_proposals"):
        return
    rows = conn.execute(
        "SELECT * FROM correction_proposals WHERE package_id = ?"
        " ORDER BY requested_at",
        (pkg["package_id"],),
    ).fetchall()
    report.correction_count += len(rows)

    if rows and pkg["status"] == "draft":
        report.fail(
            "correction_on_draft_package",
            package_id=pkg["package_id"],
        )

    for r in rows:
        status = r["status"]
        if status not in ("pending", "approved", "rejected", "applied"):
            report.fail(
                "correction_status_invalid",
                package_id=pkg["package_id"],
                correction_id=r["correction_id"],
                status=status,
            )
        reviewed = status in ("approved", "rejected", "applied")
        if reviewed:
            if not r["reviewed_by"] or r["reviewed_by"] == r["requested_by"]:
                report.fail(
                    "correction_reviewer_invalid",
                    package_id=pkg["package_id"],
                    correction_id=r["correction_id"],
                )
            roles = {r["requested_by_role"], r["reviewed_by_role"]}
            if roles != _SEAL_ROLES:
                report.fail(
                    "correction_roles_invalid",
                    package_id=pkg["package_id"],
                    correction_id=r["correction_id"],
                    roles=sorted(x for x in roles if x),
                )
            expected_fp = correction_fingerprint(
                r["correction_id"],
                r["package_id"],
                pkg["manifest_fingerprint"],
                r["correction_type"],
                r["reason"],
                json.loads(r["detail_json"]),
                r["requested_by"],
                r["reviewed_by"],
                status,
            )
            if r["change_fingerprint"] != expected_fp:
                report.fail(
                    "correction_fingerprint_mismatch",
                    package_id=pkg["package_id"],
                    correction_id=r["correction_id"],
                    stored=r["change_fingerprint"],
                    expected=expected_fp,
                )


def _table_exists(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone() is not None
