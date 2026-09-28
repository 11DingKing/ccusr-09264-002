"""领域枚举：角色、材料类型、敏感度、状态机取值。"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    INSTITUTION_ADMIN = "institution_admin"
    INSTITUTION_SUBMITTER = "institution_submitter"
    REVIEWER = "reviewer"
    QUALITY_AUTHORITY = "quality_authority"
    AUDITOR = "auditor"


class MaterialKind(str, Enum):
    SYLLABUS = "syllabus"               # 课程大纲
    FACULTY = "faculty"                 # 师资材料
    ASSESSMENT = "assessment"           # 考核材料
    ENTERPRISE_FEEDBACK = "enterprise_feedback"  # 企业反馈


class Sensitivity(str, Enum):
    NORMAL = "normal"
    SENSITIVE = "sensitive"  # 敏感企业反馈等，按机构与角色最小披露


class PackageStatus(str, Enum):
    DRAFT = "draft"                # 组包中，可追加材料
    SEALED = "sealed"              # 已封存，清单指纹固定
    UNDER_REVIEW = "under_review"  # 已分配评审
    DECIDED = "decided"            # 结论已签发，不可再改
    # 后补材料永远进入新的复审包，旧包不复活


class RequestStatus(str, Enum):
    PENDING = "pending"      # 已分配，等待评审人响应
    ACCEPTED = "accepted"
    DECLINED = "declined"
    COMPLETED = "completed"  # 评审人已提交结论
    CANCELLED = "cancelled"  # 被重新分配


class SealConfirmationStatus(str, Enum):
    PENDING = "pending"      # 第一人已确认，等待第二人（可撤回）
    CANCELLED = "cancelled"  # 第二人确认前被撤回，本轮确认作废
    SEALED = "sealed"        # 双人确认完成，封存生效


class CorrectionType(str, Enum):
    METADATA = "metadata"                  # 元数据订正（标题等）
    ENTRY_REPLACE = "entry_replace"        # 替换条目版本
    ENTRY_WITHDRAW = "entry_withdraw"      # 撤回条目
    OTHER = "other"


class Verdict(str, Enum):
    APPROVE = "approve"
    OBJECT = "object"  # 有异议


class Decision(str, Enum):
    APPROVED = "approved"
    NEEDS_REVISION = "needs_revision"
    REJECTED = "rejected"
