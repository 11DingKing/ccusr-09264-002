"""评审包服务：组包、双人封存、封存后更正与复审。

核心不变量：
- draft 包只能引用“当前未撤回”的版本；封存需【两名不同角色、两名不同
  人员】先后确认同一内容校验和，封存时把校验和与确认顺序固定进
  manifest_fingerprint(v2)；
- 第一人确认后清单即锁定（不能再追加/移除）；第二人确认完成前，
  第一人可撤回自己的确认，撤回后恢复草稿可改；
- 封存（sealed/under_review/decided）后任何直接改动都被拒绝，必须先
  登记更正（append-only），待签发后由复审包（supersedes）承接；
- 后补（新上传/恢复）的材料不能塞进已封存或已决定的包，
  只能基于旧包创建新的复审包（supersedes 链）。
"""
from __future__ import annotations

from ..domain.disclosure import DisclosureContext, redact_entry
from ..domain.enums import PackageStatus, Role
from ..domain.errors import (
    ConflictError,
    CorrectionRequiredError,
    ImmutabilityError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.fingerprint import (
    manifest_fingerprint_v2,
    seal_content_digest,
)
from ..domain.models import (
    PackageCorrection,
    PackageEntry,
    ReviewPackage,
    SealConfirmation,
    User,
)
from .base import Service, require_roles

# 允许参与双人封存的两种角色（机构管理员、质量权威机构）。
SEAL_ROLES = (Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)
SEAL_REQUIRED_CONFIRMATIONS = 2


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
                # 闭环：原包登记的更正由本复审包承接
                applied = self._apply_predecessor_corrections(predecessor.package_id, pid)
                if applied:
                    detail["corrections_applied"] = applied
            self.audit(
                actor.user_id, "package.created",
                package_id=pid, institution_id=package.institution_id, detail=detail,
            )
            return self._package_dict(self.repo.get_package(pid))

        return self.idempotent(idempotency_key, work)

    def _apply_predecessor_corrections(self, predecessor_id: str, successor_id: str) -> int:
        count = 0
        for correction in self.repo.list_corrections(predecessor_id):
            if correction.status == "requested" and self.repo.mark_correction_applied(
                correction.correction_id, successor_id
            ):
                count += 1
        return count

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
                raise CorrectionRequiredError(
                    "评审包已封存，不能直接改动；请先登记更正，待签发后发起复审",
                    details={"package_id": package_id, "status": package.status},
                )
            active_confirmations = self._active_confirmations(package_id)
            if active_confirmations:
                raise ConflictError(
                    "封存确认进行中，清单已锁定；请先撤回确认再追加材料",
                    details={
                        "package_id": package_id,
                        "confirmed_roles": [c.role for c in active_confirmations],
                    },
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

    # ----------------------------------------------------------- 双人封存
    def _active_confirmations(self, package_id: str) -> list[SealConfirmation]:
        return self.repo.list_seal_confirmations(package_id, include_revoked=False)

    @staticmethod
    def _seal_role(actor: User, taken_roles: set[str]) -> str:
        """确定本次确认使用的封存角色：优先补位尚未确认的那种角色。"""
        held = [r.value for r in SEAL_ROLES if actor.has_role(r)]
        if not held:
            # 调用方已 require_roles，正常不会到这里
            raise PermissionDeniedError("当前角色无权参与封存")
        free = [r for r in held if r not in taken_roles]
        return sorted(free or held)[0]

    @staticmethod
    def _entry_digests(package: ReviewPackage) -> list[dict]:
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

    def confirm_seal(
        self,
        actor: User,
        *,
        package_id: str,
        content_sha256: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """两名不同角色先后确认同一内容校验和；第二人确认即完成封存。

        content_sha256 可由客户端传入做端到端比对；服务端始终以库内清单
        重算为准。第一人确认后清单锁定；两人校验和不一致或缺角色均拒绝。
        """
        require_roles(actor, *SEAL_ROLES)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            if package.institution_id != actor.institution_id and not actor.has_role(
                Role.QUALITY_AUTHORITY
            ):
                raise PermissionDeniedError("只能封存本机构评审包")
            if package.status == PackageStatus.SEALED.value:
                return self._seal_state_dict(package, replayed=True)
            if package.status != PackageStatus.DRAFT.value:
                raise ImmutabilityError(
                    "评审包当前状态不能封存",
                    details={"status": package.status},
                )
            if not package.entries:
                raise ValidationError("评审包没有任何材料，不能封存")

            # 封存前最后一次撤回拦截（与 add_entry 构成双重检查）
            for entry in package.entries:
                version = self.repo.get_version(entry.version_id)
                if version is None or version.withdrawn:
                    raise ConflictError(
                        "清单中存在已撤回版本，请移除后再封存",
                        details={"version_id": entry.version_id},
                    )

            digest = seal_content_digest(self._entry_digests(package))
            if content_sha256 and content_sha256 != digest:
                raise ValidationError(
                    "提交的内容校验和与服务端重算不一致，请核对清单",
                    details={"submitted": content_sha256, "computed": digest},
                )

            active = self._active_confirmations(package_id)

            # 同一人重复确认：幂等回放（不改变确认顺序）
            mine = next((c for c in active if c.confirmer_id == actor.user_id), None)
            if mine is not None:
                if mine.sha256 != digest:
                    raise ConflictError(
                        "清单自您确认后已变化，请先撤回确认再重新确认",
                        details={"prior_sha256": mine.sha256, "computed": digest},
                    )
                return self._seal_state_dict(package, confirmations=active, replayed=True)

            if len(active) >= SEAL_REQUIRED_CONFIRMATIONS:
                # 并发：两人确认已齐、封存应已完成
                fresh = self.repo.get_package(package_id)
                return self._seal_state_dict(fresh, replayed=True)

            taken_roles = {c.role for c in active}
            role = self._seal_role(actor, taken_roles)
            if role in taken_roles:
                raise ConflictError(
                    "该角色已完成封存确认，必须由另一种角色的第二人确认",
                    details={"required_role": [r.value for r in SEAL_ROLES if r.value not in taken_roles]},
                )

            # 第二人：校验和必须与第一人一致（内容在首次确认后即锁定）
            if active:
                first = active[0]
                if digest != first.sha256:
                    raise ConflictError(
                        "内容校验和与第一确认人不一致，不能完成封存",
                        details={
                            "first_confirmer": first.confirmer_id,
                            "first_sha256": first.sha256,
                            "computed_sha256": digest,
                        },
                    )

            seq = len(active) + 1
            confirmation = SealConfirmation(
                confirmation_id=self.ids.new_id("seal"),
                package_id=package_id,
                role=role,
                confirmer_id=actor.user_id,
                confirmer_name=actor.display_name or actor.user_id,
                seq=seq,
                sha256=digest,
                confirmed_at=self.clock.now_iso(),
            )
            self.repo.insert_seal_confirmation(confirmation)
            active_after = active + [confirmation]

            if len(active_after) == SEAL_REQUIRED_CONFIRMATIONS:
                self._complete_seal(actor, package, active_after, digest)
                sealed = self.repo.get_package(package_id)
                return self._seal_state_dict(
                    sealed, confirmations=self._active_confirmations(package_id)
                )

            self.audit(
                actor.user_id, "package.seal_confirmed",
                package_id=package_id, institution_id=package.institution_id,
                detail={
                    "seq": seq, "role": role, "seal_content_digest": digest,
                    "awaiting_role": [
                        r.value for r in SEAL_ROLES if r.value not in {c.role for c in active_after}
                    ],
                },
            )
            return self._seal_state_dict(package, confirmations=active_after)

        return self.idempotent(idempotency_key, work)

    def _complete_seal(
        self,
        actor: User,
        package: ReviewPackage,
        confirmations: list[SealConfirmation],
        digest: str,
    ) -> None:
        """两人确认齐备：校验两种角色、两名人员后条件迁移到 sealed。"""
        roles = {c.role for c in confirmations}
        people = {c.confirmer_id for c in confirmations}
        if roles != {r.value for r in SEAL_ROLES}:
            raise ConflictError("封存必须由两种不同角色共同确认", details={"roles": sorted(roles)})
        if len(people) != SEAL_REQUIRED_CONFIRMATIONS:
            raise ConflictError("封存必须由两名不同人员确认", details={"confirmers": sorted(people)})

        sealed_at = self.clock.now_iso()
        fingerprint = manifest_fingerprint_v2(
            package.package_id,
            package.institution_id,
            self._entry_digests(package),
            sealed_at,
            [
                {
                    "seq": c.seq,
                    "role": c.role,
                    "confirmer_id": c.confirmer_id,
                    "sha256": c.sha256,
                    "confirmed_at": c.confirmed_at,
                }
                for c in confirmations
            ],
        )
        ok = self.repo.transition_package_status(
            package.package_id,
            PackageStatus.DRAFT.value,
            PackageStatus.SEALED.value,
            sealed_at=sealed_at,
            manifest_fingerprint=fingerprint,
        )
        if not ok:
            fresh = self.repo.get_package(package.package_id)
            if fresh is not None and fresh.status == PackageStatus.SEALED.value:
                return
            raise ConflictError("评审包状态已被其他操作改变，请重试")

        self.audit(
            actor.user_id, "package.sealed",
            package_id=package.package_id, institution_id=package.institution_id,
            detail={
                "manifest_fingerprint": fingerprint,
                "seal_content_digest": digest,
                "entries": len(package.entries),
                "confirmers": [
                    {"seq": c.seq, "role": c.role, "confirmer_id": c.confirmer_id}
                    for c in sorted(confirmations, key=lambda c: c.seq)
                ],
            },
        )

    def withdraw_seal_confirmation(
        self,
        actor: User,
        *,
        package_id: str,
        reason: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        """第二人确认完成前撤回自己的封存确认，撤回后清单恢复可改。

        封存一旦完成（包不再是 draft），确认记录永久保留、不可撤回。
        """
        require_roles(actor, *SEAL_ROLES)

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            if package.status != PackageStatus.DRAFT.value:
                raise ImmutabilityError(
                    "评审包已封存，封存确认不可撤回；如需改动请走更正流程",
                    details={"status": package.status},
                )
            active = self._active_confirmations(package_id)
            if not active:
                raise ConflictError("当前没有进行中的封存确认可撤回")
            mine = next((c for c in active if c.confirmer_id == actor.user_id), None)
            if mine is None:
                raise PermissionDeniedError(
                    "只能撤回本人的封存确认",
                    details={"active_confirmer": [c.confirmer_id for c in active]},
                )

            at = self.clock.now_iso()
            revoked = self.repo.mark_seal_confirmation_revoked(
                mine.confirmation_id, revoked_at=at, revoked_by=actor.user_id,
                reason=reason.strip(),
            )
            if not revoked:
                raise ConflictError("封存确认已被撤回或封存已完成，请刷新后重试")
            self.audit(
                actor.user_id, "package.seal_confirmation_withdrawn",
                package_id=package_id, institution_id=package.institution_id,
                detail={"confirmation_id": mine.confirmation_id, "seq": mine.seq,
                        "reason": reason.strip()},
            )
            return self._seal_state_dict(
                self.repo.get_package(package_id),
                confirmations=self.repo.list_seal_confirmations(package_id),
            )

        return self.idempotent(idempotency_key, work)

    def get_seal_status(self, actor: User, package_id: str) -> dict:
        """返回封存进度：内容校验和、各角色确认情况、确认顺序。"""
        require_roles(actor, *SEAL_ROLES, Role.AUDITOR)
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        if (
            package.institution_id != actor.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("只能查看本机构评审包的封存状态")
        confirmations = self.repo.list_seal_confirmations(package_id)
        return self._seal_state_dict(package, confirmations=confirmations)

    # ----------------------------------------------------------- 封存后更正
    def request_correction(
        self,
        actor: User,
        *,
        package_id: str,
        reason: str,
        material_id: str | None = None,
        version_id: str | None = None,
        note: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        """对已封存（含评审中/已决定）的包登记更正；不改动已封存证据。

        更正为追加记录；在包签发后，可创建复审包承接，承接后标记 applied。
        """
        require_roles(actor, *SEAL_ROLES)
        if not reason.strip():
            raise ValidationError("更正原因不能为空")

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            if package.institution_id != actor.institution_id and not actor.has_role(
                Role.QUALITY_AUTHORITY
            ):
                raise PermissionDeniedError("只能对本机构评审包登记更正")
            if package.status == PackageStatus.DRAFT.value:
                raise ConflictError(
                    "草稿包可直接修改，无需登记更正",
                    details={"status": package.status},
                )
            correction = PackageCorrection(
                correction_id=self.ids.new_id("cor"),
                package_id=package_id,
                institution_id=package.institution_id,
                requester_id=actor.user_id,
                reason=reason.strip(),
                material_id=material_id,
                version_id=version_id,
                note=note.strip() or None,
                status="requested",
                successor_package_id=None,
                created_at=self.clock.now_iso(),
            )
            self.repo.insert_correction(correction)
            self.audit(
                actor.user_id, "package.correction_requested",
                package_id=package_id, institution_id=package.institution_id,
                detail={"correction_id": correction.correction_id,
                        "reason": correction.reason,
                        "material_id": material_id, "version_id": version_id},
            )
            return self._correction_dict(correction)

        return self.idempotent(idempotency_key, work)

    def list_corrections(self, actor: User, package_id: str) -> list[dict]:
        require_roles(actor, *SEAL_ROLES, Role.AUDITOR)
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        if (
            package.institution_id != actor.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("只能查看本机构评审包的更正记录")
        return [self._correction_dict(c) for c in self.repo.list_corrections(package_id)]

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

    def _seal_state_dict(
        self,
        package: ReviewPackage,
        *,
        confirmations: list[SealConfirmation] | None = None,
        replayed: bool = False,
    ) -> dict:
        if confirmations is None:
            confirmations = self.repo.list_seal_confirmations(package.package_id)
        digest = (
            seal_content_digest(self._entry_digests(package))
            if package.entries
            else None
        )
        active = [c for c in confirmations if c.revoked_at is None]
        sealed = package.status != PackageStatus.DRAFT.value
        confirmed_roles = sorted({c.role for c in active})
        return {
            "package_id": package.package_id,
            "status": package.status,
            "sealed": sealed,
            "seal_content_digest": digest,
            "manifest_fingerprint": package.manifest_fingerprint,
            "required_confirmations": SEAL_REQUIRED_CONFIRMATIONS,
            "active_confirmation_count": len(active),
            "confirmed_roles": confirmed_roles,
            "awaiting_role": [
                r.value for r in SEAL_ROLES if r.value not in confirmed_roles
            ] if not sealed else [],
            "confirmations": [
                {
                    "seq": c.seq,
                    "role": c.role,
                    "confirmer_id": c.confirmer_id,
                    "confirmer_name": c.confirmer_name,
                    "sha256": c.sha256,
                    "confirmed_at": c.confirmed_at,
                    "revoked_at": c.revoked_at,
                    "revoked_by": c.revoked_by,
                    "revoke_reason": c.revoke_reason,
                }
                for c in sorted(confirmations, key=lambda c: c.seq)
            ],
            "replayed": replayed,
        }

    @staticmethod
    def _correction_dict(c: PackageCorrection) -> dict:
        return {
            "correction_id": c.correction_id,
            "package_id": c.package_id,
            "institution_id": c.institution_id,
            "requester_id": c.requester_id,
            "reason": c.reason,
            "material_id": c.material_id,
            "version_id": c.version_id,
            "note": c.note,
            "status": c.status,
            "successor_package_id": c.successor_package_id,
            "created_at": c.created_at,
        }
