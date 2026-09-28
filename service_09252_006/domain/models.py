"""领域实体（贫血数据载体，业务规则在领域服务/应用服务中）。

时间一律以带时区的 UTC ISO-8601 字符串存储；截止时间同时保存原始
IANA 时区用于展示，比较时统一换化为 UTC 时刻，从而正确处理跨时区截止。
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Optional

from .enums import (
    Decision,
    MaterialKind,
    PackageStatus,
    RequestStatus,
    Role,
    Sensitivity,
    Verdict,
)


@dataclass
class User:
    user_id: str
    institution_id: Optional[str]  # 机构用户非空；权威机构/审计可为空
    roles: tuple[str, ...]
    display_name: str = ""

    def has_role(self, role: Role | str) -> bool:
        wanted = role.value if isinstance(role, Role) else role
        return wanted in self.roles


@dataclass
class Material:
    """逻辑材料（课程大纲、师资、考核、企业反馈中的某一份）。"""

    material_id: str
    institution_id: str
    kind: str                      # MaterialKind
    sensitivity: str               # Sensitivity
    title: str
    current_version_id: Optional[str]
    withdrawn: bool
    created_at: str


@dataclass
class MaterialVersion:
    """材料的一次不可变版本。字节内容按 sha256 内容寻址、去重存储。"""

    version_id: str
    material_id: str
    institution_id: str
    sha256: str
    size: int
    media_type: str
    version_no: int
    supersedes_version_id: Optional[str]
    created_by: str
    created_at: str
    withdrawn: bool                # 该版本是否已撤回


@dataclass
class PackageEntry:
    """评审包对材料【具体版本】的固定引用。"""

    entry_id: str
    package_id: str
    material_id: str
    version_id: str
    sha256: str
    kind: str
    sensitivity: str
    added_at: str


@dataclass
class ReviewPackage:
    package_id: str
    institution_id: str
    title: str
    status: str                    # PackageStatus
    created_by: str
    created_at: str
    sealed_at: Optional[str]
    manifest_fingerprint: Optional[str]
    decided_at: Optional[str]
    decision: Optional[str]        # Decision
    decision_note: Optional[str]
    review_fingerprint: Optional[str]
    supersedes_package_id: Optional[str]  # 后补材料触发的复审包指向前序包
    entries: list[PackageEntry] = field(default_factory=list)

    def is_mutable(self) -> bool:
        return self.status == PackageStatus.DRAFT.value


@dataclass
class SealConfirmation:
    """封存前的双人确认留痕：两名不同角色先后确认内容与校验和。

    第二人确认前任一人可撤回（status=cancelled）；两人都确认后封存生效
    （status=sealed），并记录 package 上的封存时刻与清单指纹。

    content_checksum 只覆盖清单内容（不含封存时刻），两名确认人确认的是
    同一个值；sealed_manifest_fingerprint 在第二人确认完成时按封存时刻
    生成，与 packages.manifest_fingerprint 一致，供离线核验复算。
    """

    confirmation_id: str
    package_id: str
    institution_id: str
    status: str                    # SealConfirmationStatus
    content_checksum: str          # 待封存清单的内容校验和（两人确认同一值）
    entry_count: int
    first_confirmer_id: str
    first_confirmer_role: str
    first_confirmed_at: str
    second_confirmer_id: Optional[str]
    second_confirmer_role: Optional[str]
    second_confirmed_at: Optional[str]
    withdrawn_by: Optional[str]
    withdrawn_at: Optional[str]
    withdraw_reason: Optional[str]
    sealed_at: Optional[str]
    sealed_manifest_fingerprint: Optional[str] = None


@dataclass
class CorrectionProposal:
    """封存后更正：任何对已封存证据包的改动只能走更正流程留痕。

    双人角色隔离：申请人（requested_by_role）与批准人（reviewed_by_role）
    必须是封存两角色中的不同角色、不同用户。元数据订正（不进入清单指纹）
    可在批准后原地生效；涉及条目内容的结构性变更不能改写历史清单，只能
    凭批准记录走既有的复审包（supersedes）流程。
    """

    correction_id: str
    package_id: str
    institution_id: str
    correction_type: str           # CorrectionType
    reason: str
    detail: dict
    status: str                    # pending / approved / rejected / applied
    requested_by: str
    requested_by_role: str
    requested_at: str
    reviewed_by: Optional[str]
    reviewed_by_role: Optional[str]
    reviewed_at: Optional[str]
    review_note: Optional[str]
    applied_at: Optional[str]
    change_fingerprint: Optional[str] = None


@dataclass
class ReviewRequest:
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    status: str                    # RequestStatus
    assigned_by: str
    assigned_at: str
    responded_at: Optional[str]
    completed_at: Optional[str]
    verdict: Optional[str]         # Verdict
    comment: Optional[str]
    deadline_at_utc: Optional[str]  # 截止时刻（UTC）
    deadline_timezone: Optional[str]  # 原始 IANA 时区，仅展示用


@dataclass
class Objection:
    objection_id: str
    request_id: str
    package_id: str
    institution_id: str
    reviewer_id: str
    category: str
    detail: str
    created_at: str


@dataclass
class Blob:
    sha256: str
    data: bytes
    media_type: str
    created_at: str


@dataclass
class AuditEntry:
    audit_id: str
    package_id: Optional[str]
    institution_id: Optional[str]
    actor_id: str
    action: str
    at: str
    detail: dict = field(default_factory=dict)


def asdict(obj) -> dict:
    return dataclasses.asdict(obj)
