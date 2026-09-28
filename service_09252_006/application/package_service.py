"""评审包服务：组包、双人封存、封存后更正、后补材料触发复审。

核心不变量：
- draft 包只能引用“当前未撤回”的版本；封存必须由两名**不同角色**
  （机构管理员 + 质量权威机构）先后确认：第一人启动确认并固定内容
  校验和，第二人确认前任何人都可撤回本轮确认；第二人复算校验和
  一致后封存才生效，封存清单指纹（含封存时刻）随之固定。
- 第一人确认后、第二人确认前清单发生任何变化（追加/撤回），第二人
  复算的内容校验和都不会匹配，封存被拒绝，必须撤回本轮确认后重来。
- 封存后清单指纹固定，材料撤回/新版本都不改变历史包；任何对已封存
  包的改动只能走“更正流程”（两名封存角色中的另一方审批），内容性
  变更凭批准记录进入新的复审包（supersedes 链），旧包不复活。
"""
from __future__ import annotations

from ..domain.disclosure import DisclosureContext, redact_entry
from ..domain.enums import (
    CorrectionType,
    PackageStatus,
    Role,
    SealConfirmationStatus,
)
from ..domain.errors import (
    ConflictError,
    ImmutabilityError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.fingerprint import (
    correction_fingerprint,
    manifest_content_checksum,
    manifest_fingerprint,
)
from ..domain.models import (
    CorrectionProposal,
    PackageEntry,
    ReviewPackage,
    SealConfirmation,
    User,
)
from .base import Service, require_roles

# 封存需要的两种角色：顺序不限，但两名确认人必须分属不同角色、不同用户
SEAL_ROLE_A = Role.INSTITUTION_ADMIN
SEAL_ROLE_B = Role.QUALITY_AUTHORITY
SEAL_ROLES = (SEAL_ROLE_A, SEAL_ROLE_B)

# 结构性更正（会触及清单内容）不能原地改写历史，批准后须据此发起复审包
_STRUCTURAL_CORRECTIONS = {
    CorrectionType.ENTRY_REPLACE.value,
    CorrectionType.ENTRY_WITHDRAW.value,
}


class PackageService(Service):
    def create_package(
        self,
        actor: User,
        *,
        title: str,
        supersedes_package_id: str | None = None,
        package_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)
        if not title.strip():
            raise ValidationError("评审包标题不能为空")

        def work() -> dict:
            pid = package_id or self.ids.new_id("pkg")
            if self.repo.get_package(pid) is not None:
                return self._package_dict(self.repo.get_package(pid))

            predecessor: ReviewPackage | None = None
            if supersedes_package_id is not None:
                predecessor = self.repo.get_package(supersedes_package_id)
                if predecessor is None:
                    raise NotFoundError(
                        "被复审的原评审包不存在",
                        details={"supersedes_package_id": supersedes_package_id},
                    )
                if predecessor.institution_id != actor.institution_id and not actor.has_role(
                    Role.QUALITY_AUTHORITY
                ):
                    raise PermissionDeniedError("不能为其他机构创建复审包")
                if predecessor.status != PackageStatus.DECIDED.value:
                    raise ConflictError(
                        "仅已签发结论的评审包可发起复审",
                        details={"predecessor_status": predecessor.status},
                    )

            package = ReviewPackage(
                package_id=pid,
                institution_id=actor.institution_id or "",
                title=title.strip(),
                status=PackageStatus.DRAFT.value,
                created_by=actor.user_id,
                created_at=self.clock.now_iso(),
                sealed_at=None,
                manifest_fingerprint=None,
                decided_at=None,
                decision=None,
                decision_note=None,
                review_fingerprint=None,
                supersedes_package_id=supersedes_package_id,
            )
            self.repo.insert_package(package)
            detail = {}
            if predecessor is not None:
                # 复审包默认带上原包中【未撤回】的条目，撤回的条目不复制
                detail["copied_entries"] = self._copy_live_entries(actor, predecessor, pid)
                detail["supersedes_package_id"] = supersedes_package_id
            self.audit(
                actor.user_id, "package.created",
                package_id=pid, institution_id=package.institution_id, detail=detail,
            )
            return self._package_dict(self.repo.get_package(pid))

        return self.idempotent(idempotency_key, work)

    def _copy_live_entries(self, actor: User, predecessor: ReviewPackage, new_pid: str) -> int:
        count = 0
        for entry in predecessor.entries:
            version = self.repo.get_version(entry.version_id)
            if version is None or version.withdrawn:
                continue
            new_entry = PackageEntry(
                entry_id=self.ids.new_id("ent"),
                package_id=new_pid,
                material_id=entry.material_id,
                version_id=entry.version_id,
                sha256=entry.sha256,
                kind=entry.kind,
                sensitivity=entry.sensitivity,
                added_at=self.clock.now_iso(),
            )
            self.repo.insert_entry(new_entry)
            count += 1
        return count

    def add_entry(
        self,
        actor: User,
        *,
        package_id: str,
        version_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.INSTITUTION_SUBMITTER)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            if package.institution_id != actor.institution_id:
                raise PermissionDeniedError("只能向本机构评审包添加材料")
            if not package.is_mutable():
                raise ImmutabilityError(
                    "评审包已封存，后补材料只能发起新的复审请求",
                    details={"package_id": package_id, "status": package.status},
                )
            if self.repo.get_active_seal_confirmation(package_id) is not None:
                raise ConflictError(
                    "双人封存确认进行中，不能改动清单；"
                    "请先由第二角色完成确认，或撤回本轮确认后再添加"
                )
            version = self.repo.get_version(version_id)
            if version is None:
                raise NotFoundError("材料版本不存在")
            if version.institution_id != actor.institution_id:
                raise PermissionDeniedError("不能把其他机构材料加入评审包")
            if version.withdrawn:
                raise ConflictError("该版本已撤回，不能进入评审包")

            if self.repo.entry_exists(package_id, version_id):
                return {"package_id": package_id, "version_id": version_id, "replayed": True}

            entry = PackageEntry(
                entry_id=self.ids.new_id("ent"),
                package_id=package_id,
                material_id=version.material_id,
                version_id=version.version_id,
                sha256=version.sha256,
                kind=self.repo.get_material(version.material_id).kind,
                sensitivity=self.repo.get_material(version.material_id).sensitivity,
                added_at=self.clock.now_iso(),
            )
            self.repo.insert_entry(entry)
            self.audit(
                actor.user_id, "package.entry_added",
                package_id=package_id, institution_id=package.institution_id,
                detail={"version_id": version_id, "entry_id": entry.entry_id},
            )
            return {"package_id": package_id, "version_id": version_id, "entry_id": entry.entry_id}

        return self.idempotent(idempotency_key, work)

    # ----------------------------------------------------- 双人封存确认
    def _assert_seal_access(self, actor: User, package: ReviewPackage) -> None:
        """封存两角色的机构边界：管理员只能封存本机构包，权威机构可跨机构。"""
        if package.institution_id != actor.institution_id and not actor.has_role(
            Role.QUALITY_AUTHORITY
        ):
            raise PermissionDeniedError("只能封存本机构评审包")

    @staticmethod
    def _seal_role_of(actor: User) -> str | None:
        return next((r.value for r in SEAL_ROLES if actor.has_role(r)), None)

    @staticmethod
    def _entry_payloads(package: ReviewPackage) -> list[dict]:
        return [
            {
                "material_id": e.material_id,
                "version_id": e.version_id,
                "sha256": e.sha256,
                "kind": e.kind,
                "sensitivity": e.sensitivity,
            }
            for e in package.entries
        ]

    def _content_checksum(self, package: ReviewPackage) -> str:
        return manifest_content_checksum(
            package.package_id,
            package.institution_id,
            self._entry_payloads(package),
        )

    def _assert_sealable(self, package: ReviewPackage) -> None:
        """封存前的清单校验：非空、无已撤回版本。"""
        if package.status != PackageStatus.DRAFT.value:
            raise ImmutabilityError(
                "评审包当前状态不能封存",
                details={"status": package.status},
            )
        if not package.entries:
            raise ValidationError("评审包没有任何材料，不能封存")
        for entry in package.entries:
            version = self.repo.get_version(entry.version_id)
            if version is None or version.withdrawn:
                raise ConflictError(
                    "清单中存在已撤回版本，请移除后再封存",
                    details={"version_id": entry.version_id},
                )

    def start_seal_confirmation(
        self,
        actor: User,
        *,
        package_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """第一角色启动双人封存：校验角色、固定待封存清单的内容校验和。"""
        require_roles(actor, *SEAL_ROLES)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            self._assert_seal_access(actor, package)
            self._assert_sealable(package)

            active = self.repo.get_active_seal_confirmation(package_id)
            if active is not None:
                if active.first_confirmer_id == actor.user_id:
                    # 同一人重复发起：幂等回放其进行中的确认
                    return self._confirmation_dict(active, replayed=True)
                raise ConflictError(
                    "已有进行中的双人封存确认，须由另一角色完成第二人确认，"
                    "或先撤回本轮确认",
                    details={"confirmation_id": active.confirmation_id},
                )

            confirmation = SealConfirmation(
                confirmation_id=self.ids.new_id("seal"),
                package_id=package_id,
                institution_id=package.institution_id,
                status=SealConfirmationStatus.PENDING.value,
                content_checksum=self._content_checksum(package),
                entry_count=len(package.entries),
                first_confirmer_id=actor.user_id,
                first_confirmer_role=self._seal_role_of(actor),
                first_confirmed_at=self.clock.now_iso(),
                second_confirmer_id=None,
                second_confirmer_role=None,
                second_confirmed_at=None,
                withdrawn_by=None,
                withdrawn_at=None,
                withdraw_reason=None,
                sealed_at=None,
            )
            self.repo.insert_seal_confirmation(confirmation)
            self.audit(
                actor.user_id, "package.seal_confirmation_started",
                package_id=package_id, institution_id=package.institution_id,
                detail={
                    "confirmation_id": confirmation.confirmation_id,
                    "content_checksum": confirmation.content_checksum,
                    "first_confirmer_role": confirmation.first_confirmer_role,
                },
            )
            return self._confirmation_dict(confirmation)

        return self.idempotent(idempotency_key, work)

    def confirm_seal(
        self,
        actor: User,
        *,
        package_id: str,
        confirmation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """第二角色确认：复算内容校验和一致后封存生效。

        第二人必须是与第一人**不同用户、不同封存角色**的另一名确认人；
        第一人确认后清单若被改动，复算校验和不匹配，封存被拒绝。
        """
        require_roles(actor, *SEAL_ROLES)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            self._assert_seal_access(actor, package)

            confirmation = (
                self.repo.get_seal_confirmation(confirmation_id)
                if confirmation_id
                else self.repo.get_active_seal_confirmation(package_id)
            )
            if confirmation is None or confirmation.package_id != package_id:
                raise ConflictError("没有进行中的双人封存确认，须先由第一角色启动")
            if confirmation.status != SealConfirmationStatus.PENDING.value:
                raise ConflictError(
                    "本轮封存确认已结束",
                    details={"status": confirmation.status},
                )

            # 角色隔离：另一名用户、另一种封存角色
            if actor.user_id == confirmation.first_confirmer_id:
                raise PermissionDeniedError(
                    "第二人必须是不同于第一确认人的另一名用户",
                )
            required_role = self._complementary_role(
                confirmation.first_confirmer_role
            )
            if not actor.has_role(required_role):
                raise PermissionDeniedError(
                    "第二确认人必须是另一封存角色",
                    details={
                        "first_confirmer_role": confirmation.first_confirmer_role,
                        "required_role": required_role.value,
                    },
                )

            if package.status != PackageStatus.DRAFT.value:
                raise ImmutabilityError(
                    "评审包当前状态不能封存",
                    details={"status": package.status},
                )
            # 封存前最后一次撤回拦截（与 add_entry 构成双重检查）
            for entry in package.entries:
                version = self.repo.get_version(entry.version_id)
                if version is None or version.withdrawn:
                    raise ConflictError(
                        "清单中存在已撤回版本，请移除后再封存",
                        details={"version_id": entry.version_id},
                    )
            # 复算内容校验和：第一人确认后清单被追加/改动都会在此失配
            current_checksum = self._content_checksum(package)
            if current_checksum != confirmation.content_checksum:
                raise ConflictError(
                    "清单内容校验和与第一人确认时不一致，"
                    "请撤回本轮确认后按最新清单重新封存",
                    details={
                        "confirmed_checksum": confirmation.content_checksum,
                        "current_checksum": current_checksum,
                    },
                )
            if confirmation.entry_count != len(package.entries):
                raise ConflictError("清单条目数在双人确认期间发生变化")

            sealed_at = self.clock.now_iso()
            fingerprint = manifest_fingerprint(
                package.package_id,
                package.institution_id,
                self._entry_payloads(package),
                sealed_at,
            )
            moved = self.repo.transition_package_status(
                package_id,
                PackageStatus.DRAFT.value,
                PackageStatus.SEALED.value,
                sealed_at=sealed_at,
                manifest_fingerprint=fingerprint,
            )
            if not moved:
                fresh = self.repo.get_package(package_id)
                if fresh is not None and fresh.status == PackageStatus.SEALED.value:
                    return self._package_dict(fresh, replayed=True)
                raise ConflictError("评审包状态已被其他操作改变，请重试")
            completed = self.repo.complete_seal_confirmation(
                confirmation.confirmation_id,
                second_confirmer_id=actor.user_id,
                second_confirmer_role=required_role.value,
                second_confirmed_at=sealed_at,
                sealed_at=sealed_at,
                sealed_manifest_fingerprint=fingerprint,
            )
            if not completed:
                # 与撤回并发：条件更新失败，事务回滚，调用方重试
                raise ConflictError("本轮封存确认刚被撤回，请重新发起")

            self.audit(
                actor.user_id, "package.sealed",
                package_id=package_id, institution_id=package.institution_id,
                detail={
                    "confirmation_id": confirmation.confirmation_id,
                    "manifest_fingerprint": fingerprint,
                    "content_checksum": confirmation.content_checksum,
                    "first_confirmer_id": confirmation.first_confirmer_id,
                    "second_confirmer_id": actor.user_id,
                    "entries": len(package.entries),
                },
            )
            sealed = self.repo.get_package(package_id)
            result = self._package_dict(sealed)
            result["confirmation_id"] = confirmation.confirmation_id
            result["content_checksum"] = confirmation.content_checksum
            return result

        return self.idempotent(idempotency_key, work)

    def withdraw_seal_confirmation(
        self,
        actor: User,
        *,
        package_id: str,
        reason: str = "",
        confirmation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """第二人确认前撤回本轮封存确认；包保持 draft，可重新发起。"""
        require_roles(actor, *SEAL_ROLES)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            self._assert_seal_access(actor, package)
            confirmation = (
                self.repo.get_seal_confirmation(confirmation_id)
                if confirmation_id
                else self.repo.get_active_seal_confirmation(package_id)
            )
            if confirmation is None or confirmation.package_id != package_id:
                raise ConflictError("没有进行中的双人封存确认可撤回")
            ok = self.repo.mark_seal_confirmation_withdrawn(
                confirmation.confirmation_id,
                withdrawn_by=actor.user_id,
                withdrawn_at=self.clock.now_iso(),
                reason=reason.strip() or None,
            )
            if not ok:
                # 与第二人确认并发：对方可能刚好完成封存
                fresh = self.repo.get_package(package_id)
                if fresh is not None and not fresh.is_mutable():
                    raise ImmutabilityError("评审包已封存，不能撤回确认")
                raise ConflictError("本轮封存确认已结束，撤回失败")
            self.audit(
                actor.user_id, "package.seal_confirmation_withdrawn",
                package_id=package_id, institution_id=package.institution_id,
                detail={
                    "confirmation_id": confirmation.confirmation_id,
                    "reason": reason,
                },
            )
            cancelled = self.repo.get_seal_confirmation(confirmation.confirmation_id)
            return self._confirmation_dict(cancelled)

        return self.idempotent(idempotency_key, work)

    def list_seal_confirmations(self, actor: User, package_id: str) -> list[dict]:
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        self._assert_seal_access(actor, package)
        return [
            self._confirmation_dict(c)
            for c in self.repo.list_seal_confirmations(package_id)
        ]

    @staticmethod
    def _complementary_role(role_value: str) -> Role:
        return SEAL_ROLE_B if role_value == SEAL_ROLE_A.value else SEAL_ROLE_A

    # --------------------------------------------------------- 封存后更正
    def request_correction(
        self,
        actor: User,
        *,
        package_id: str,
        correction_type: str,
        reason: str,
        detail: dict | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """封存后任何改动都必须先提更正申请，等待另一封存角色审批。"""
        require_roles(actor, *SEAL_ROLES)
        if correction_type not in {t.value for t in CorrectionType}:
            raise ValidationError(
                "未知更正类型", details={"correction_type": correction_type}
            )
        if not reason.strip():
            raise ValidationError("更正原因不能为空")
        detail = dict(detail or {})

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            self._assert_seal_access(actor, package)
            if package.status == PackageStatus.DRAFT.value:
                raise ConflictError("草稿包可直接修改，无需走更正流程")
            self._validate_correction_detail(package, correction_type, detail)

            correction = CorrectionProposal(
                correction_id=self.ids.new_id("cor"),
                package_id=package_id,
                institution_id=package.institution_id,
                correction_type=correction_type,
                reason=reason.strip(),
                detail=detail,
                status="pending",
                requested_by=actor.user_id,
                requested_by_role=self._seal_role_of(actor),
                requested_at=self.clock.now_iso(),
                reviewed_by=None,
                reviewed_by_role=None,
                reviewed_at=None,
                review_note=None,
                applied_at=None,
            )
            self.repo.insert_correction(correction)
            self.audit(
                actor.user_id, "package.correction_requested",
                package_id=package_id, institution_id=package.institution_id,
                detail={
                    "correction_id": correction.correction_id,
                    "correction_type": correction_type,
                },
            )
            return self._correction_dict(correction)

        return self.idempotent(idempotency_key, work)

    def review_correction(
        self,
        actor: User,
        *,
        correction_id: str,
        approve: bool,
        note: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        """审批更正：批准人必须是与申请人不同用户、不同封存角色的另一方。"""
        require_roles(actor, *SEAL_ROLES)

        def work() -> dict:
            correction = self.repo.get_correction(correction_id)
            if correction is None:
                raise NotFoundError("更正申请不存在")
            package = self.repo.get_package(correction.package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            self._assert_seal_access(actor, package)
            if correction.status != "pending":
                return self._correction_dict(correction, replayed=True)
            if actor.user_id == correction.requested_by:
                raise PermissionDeniedError("更正必须由申请人之外的另一方审批")
            required_role = self._complementary_role(correction.requested_by_role)
            if not actor.has_role(required_role):
                raise PermissionDeniedError(
                    "更正审批人必须是另一封存角色",
                    details={
                        "requested_by_role": correction.requested_by_role,
                        "required_role": required_role.value,
                    },
                )

            now = self.clock.now_iso()
            correction.reviewed_by = actor.user_id
            correction.reviewed_by_role = required_role.value
            correction.reviewed_at = now
            correction.review_note = note.strip() or None

            if not approve:
                correction.status = "rejected"
            else:
                requires_rereview = correction.correction_type in _STRUCTURAL_CORRECTIONS
                if requires_rereview:
                    # 结构性变更不能改写已封存清单：批准即授权，实际替换/撤回
                    # 必须在签发后通过复审包（supersedes 链）落地，旧包不复活。
                    correction.status = "approved"
                else:
                    correction = self._apply_metadata_correction(package, correction, now)

            correction.change_fingerprint = self._correction_fingerprint(
                package, correction
            )
            ok = self.repo.update_correction(correction)
            if not ok:
                # 并发下另一方已审批：条件更新失败，连同已做的元数据改动
                # 一起回滚；调用方重试时会在开头的状态检查处回放结果。
                raise ConflictError("更正申请已被另一方处理，请重试")
            self.audit(
                actor.user_id,
                "package.correction_" + correction.status,
                package_id=package.package_id,
                institution_id=package.institution_id,
                detail={
                    "correction_id": correction.correction_id,
                    "correction_type": correction.correction_type,
                    "change_fingerprint": correction.change_fingerprint,
                },
            )
            return self._correction_dict(
                self.repo.get_correction(correction_id)
            )

        return self.idempotent(idempotency_key, work)

    def _apply_metadata_correction(
        self, package: ReviewPackage, correction: CorrectionProposal, now: str
    ) -> CorrectionProposal:
        if correction.correction_type == CorrectionType.METADATA.value:
            new_title = (correction.detail.get("title") or "").strip()
            if new_title:
                correction.detail["previous_title"] = package.title
                self.repo.rename_package_title(package.package_id, new_title)
        # 元数据订正不进入清单指纹，manifest_fingerprint 保持不变
        correction.status = "applied"
        correction.applied_at = now
        return correction

    def _validate_correction_detail(
        self, package: ReviewPackage, correction_type: str, detail: dict
    ) -> None:
        if correction_type == CorrectionType.METADATA.value:
            if not str(detail.get("title") or "").strip():
                raise ValidationError("元数据更正必须提供新的标题 title")
        elif correction_type in _STRUCTURAL_CORRECTIONS:
            version_id = detail.get("version_id")
            if not version_id:
                raise ValidationError("条目更正必须提供 version_id")
            if not any(e.version_id == version_id for e in package.entries):
                raise ValidationError(
                    "指定版本不在已封存清单中",
                    details={"version_id": version_id},
                )
            if correction_type == CorrectionType.ENTRY_REPLACE.value:
                replacement = detail.get("replacement_version_id")
                if replacement is None:
                    raise ValidationError("条目替换必须提供 replacement_version_id")
                new_version = self.repo.get_version(replacement)
                if new_version is None:
                    raise NotFoundError("替换用的新版本不存在")
                if new_version.institution_id != package.institution_id:
                    raise PermissionDeniedError("不能用其他机构材料替换条目")
                if new_version.withdrawn:
                    raise ConflictError("替换用的新版本已撤回")

    @staticmethod
    def _correction_fingerprint(
        package: ReviewPackage, correction: CorrectionProposal
    ) -> str:
        return correction_fingerprint(
            correction.correction_id,
            package.package_id,
            package.manifest_fingerprint,
            correction.correction_type,
            correction.reason,
            correction.detail,
            correction.requested_by,
            correction.reviewed_by,
            correction.status,
        )

    def list_corrections(self, actor: User, package_id: str) -> list[dict]:
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        self._assert_seal_access(actor, package)
        return [
            self._correction_dict(c)
            for c in self.repo.list_corrections(package_id)
        ]

    @staticmethod
    def _confirmation_dict(
        c: SealConfirmation, *, replayed: bool = False
    ) -> dict:
        return {
            "confirmation_id": c.confirmation_id,
            "package_id": c.package_id,
            "status": c.status,
            "content_checksum": c.content_checksum,
            "entry_count": c.entry_count,
            "first_confirmer_id": c.first_confirmer_id,
            "first_confirmer_role": c.first_confirmer_role,
            "first_confirmed_at": c.first_confirmed_at,
            "second_confirmer_id": c.second_confirmer_id,
            "second_confirmer_role": c.second_confirmer_role,
            "second_confirmed_at": c.second_confirmed_at,
            "withdrawn_by": c.withdrawn_by,
            "withdrawn_at": c.withdrawn_at,
            "withdraw_reason": c.withdraw_reason,
            "sealed_at": c.sealed_at,
            "sealed_manifest_fingerprint": c.sealed_manifest_fingerprint,
            "replayed": replayed,
        }

    @staticmethod
    def _correction_dict(
        c: CorrectionProposal | None, *, replayed: bool = False
    ) -> dict:
        if c is None:
            raise NotFoundError("更正申请不存在")
        requires_rereview = c.correction_type in _STRUCTURAL_CORRECTIONS
        return {
            "correction_id": c.correction_id,
            "package_id": c.package_id,
            "correction_type": c.correction_type,
            "reason": c.reason,
            "detail": c.detail,
            "status": c.status,
            "requested_by": c.requested_by,
            "requested_by_role": c.requested_by_role,
            "requested_at": c.requested_at,
            "reviewed_by": c.reviewed_by,
            "reviewed_by_role": c.reviewed_by_role,
            "reviewed_at": c.reviewed_at,
            "review_note": c.review_note,
            "applied_at": c.applied_at,
            "change_fingerprint": c.change_fingerprint,
            "requires_rereview": c.status == "approved" and requires_rereview,
            "replayed": replayed,
        }

    # -------------------------------------------------------------- 视图
    def build_package_view(self, actor: User, package_id: str) -> dict:
        """按最小披露返回包视图；敏感条目对无权用户做遮蔽。

        曾被分配到该包的评审人（即使请求已取消/拒绝）可打开视图看到
        非敏感条目与“存在敏感条目”的事实，但敏感内容按当前有效分配遮蔽；
        与该包毫无关系的外部机构用户直接拒绝。
        """
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        is_assigned = (
            actor.has_role(Role.REVIEWER)
            and any(
                r.reviewer_id == actor.user_id
                for r in self.repo.list_requests_by_package(package_id)
            )
        )
        if (
            actor.institution_id != package.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
            and not is_assigned
        ):
            raise PermissionDeniedError("不能查看其他机构评审包")

        active = {
            r.package_id
            for r in self.repo.list_active_requests_by_reviewer(actor.user_id)
        }
        ctx = DisclosureContext(actor, active)

        visible_entries = []
        hidden_count = 0
        for entry in package.entries:
            can_see = ctx.can_see_entry(entry, package)
            if not can_see:
                hidden_count += 1
            visible_entries.append(redact_entry(entry, can_see))

        view = self._package_dict(package)
        view["entries"] = visible_entries
        view["redacted_entries"] = hidden_count
        view["viewer"] = actor.user_id
        return view

    def download_entry(
        self, actor: User, *, package_id: str, version_id: str
    ) -> tuple[dict, bytes, str]:
        """通过评审包条目下载内容字节，强制走最小披露授权。

        返回 (版本描述, 字节, media_type)。评审人只可下载其仍有效分配
        所在包的敏感反馈；请求一旦取消，授权即时消失。
        """
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        entry = next(
            (e for e in package.entries if e.version_id == version_id), None
        )
        if entry is None:
            raise NotFoundError("该材料版本不在评审包中")
        active = {
            r.package_id
            for r in self.repo.list_active_requests_by_reviewer(actor.user_id)
        }
        ctx = DisclosureContext(actor, active)
        if not ctx.can_see_entry(entry, package):
            raise PermissionDeniedError("无权下载该材料（最小披露限制）")
        version = self.repo.get_version(version_id)
        blob = self.repo.get_blob(entry.sha256)
        if version is None or blob is None:
            raise NotFoundError("内容缺失，无法提供")
        return {
            "version_id": version.version_id,
            "material_id": version.material_id,
            "sha256": "sha256:" + version.sha256,
            "media_type": version.media_type,
            "size": version.size,
        }, blob.data, version.media_type

    def list_packages(self, actor: User) -> list[dict]:
        if actor.has_role(Role.AUDITOR) or actor.has_role(Role.QUALITY_AUTHORITY):
            packages = self.repo.list_packages(None)
        else:
            packages = self.repo.list_packages(actor.institution_id)
        return [self._package_dict(p) for p in packages]

    @staticmethod
    def _package_dict(p: ReviewPackage, *, replayed: bool = False) -> dict:
        return {
            "package_id": p.package_id,
            "institution_id": p.institution_id,
            "title": p.title,
            "status": p.status,
            "created_by": p.created_by,
            "created_at": p.created_at,
            "sealed_at": p.sealed_at,
            "manifest_fingerprint": p.manifest_fingerprint,
            "decided_at": p.decided_at,
            "decision": p.decision,
            "decision_note": p.decision_note,
            "review_fingerprint": p.review_fingerprint,
            "supersedes_package_id": p.supersedes_package_id,
            "entry_count": len(p.entries),
            "replayed": replayed,
        }
