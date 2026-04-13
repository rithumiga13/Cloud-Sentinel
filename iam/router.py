"""
IAM API router.

Endpoints:
  Role & policy
    GET  /iam/policy                       — effective role permissions for caller
    PUT  /iam/policy/{user_id}             — update user role (Admin)
    GET  /iam/check                        — ad-hoc RBAC check
    GET  /iam/roles                        — list roles + hierarchy + permission counts
    POST /iam/evaluate                     — full evaluation with ABAC trace (sandbox)
    GET  /iam/users/{user_id}/effective    — full effective permission set for a user

  Groups
    GET    /iam/groups                     — list all groups
    POST   /iam/groups                     — create group (Admin)
    GET    /iam/groups/{id}                — group detail + members + permissions
    DELETE /iam/groups/{id}                — delete group (Admin)
    POST   /iam/groups/{id}/members        — add user to group (Admin)
    DELETE /iam/groups/{id}/members/{uid}  — remove user from group (Admin)
    POST   /iam/groups/{id}/permissions    — add group permission (Admin)
    DELETE /iam/groups/{id}/permissions/{pid} — remove group permission (Admin)

  Permission boundary
    GET  /iam/users/{user_id}/boundary     — get user boundary
    PUT  /iam/users/{user_id}/boundary     — set/replace user boundary (Admin)
    DELETE /iam/users/{user_id}/boundary   — clear user boundary (Admin)
"""

from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from database import get_db
from schemas import (
    APIResponse, PermissionOut, PolicyUpdateRequest,
    GroupCreateRequest, GroupMemberRequest, GroupPermissionRequest,
    GroupOut, GroupDetailOut, GroupMemberOut, GroupPermissionOut,
    BoundarySetRequest, BoundaryOut, BoundaryPair,
    EvaluateRequest, EvaluationResult,
)
from auth.dependencies import get_current_user, require_role
from models import User, Group, GroupMembership, GroupPermission, UserPermissionBoundary, RoleEnum
from iam.service import (
    ROLE_HIERARCHY,
    get_effective_permissions,
    get_user_effective_permissions,
    update_user_policy,
    check_permission,
    evaluate_access,
    AccessContext,
    create_group,
    add_group_member,
    remove_group_member,
    add_group_permission,
    remove_group_permission,
    set_permission_boundary,
)
from audit.service import write_audit_log

router = APIRouter(prefix="/iam", tags=["IAM"])

_admin_dep = require_role(RoleEnum.admin)


# ---------------------------------------------------------------------------
# Role & policy endpoints
# ---------------------------------------------------------------------------

@router.get("/roles", response_model=APIResponse)
async def list_roles(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Return all roles with hierarchy, parent info, and permission counts."""
    from models import Permission
    roles_out = []
    for role in RoleEnum:
        inherited = ROLE_HIERARCHY.get(role.value, [role.value])
        count = db.query(Permission).filter(Permission.role == role.value).count()
        roles_out.append({
            "role": role.value,
            "inherits_from": inherited[1:],  # exclude self
            "direct_permission_count": count,
            "total_permission_count": db.query(Permission)
                .filter(Permission.role.in_(inherited)).count(),
        })
    return APIResponse(success=True, data=roles_out)


@router.get("/policy", response_model=APIResponse)
async def get_my_policy(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Return effective role permissions for the authenticated caller."""
    perms = get_effective_permissions(db, current_user.role)
    return APIResponse(
        success=True,
        data=[PermissionOut.model_validate(p).model_dump() for p in perms],
    )


@router.put("/policy/{user_id}", response_model=APIResponse)
async def update_policy(
    user_id: int,
    body: PolicyUpdateRequest,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Update the role for a user. Admin only."""
    target: Optional[User] = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    action_label = "self_role_change" if current_user.id == user_id else "role_change"
    updated = update_user_policy(db, target, body.role, current_user.id)
    write_audit_log(db, user_id=current_user.id, action=action_label, resource="iam",
                    status="safe", ip="0.0.0.0",
                    details=f"Changed user {user_id} role to {body.role}")
    return APIResponse(success=True, data={"user_id": user_id, "new_role": updated.role})


@router.get("/check", response_model=APIResponse)
async def check_access(
    resource: str,
    action: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Quick RBAC check for caller's role (no ABAC context)."""
    allowed, reason = check_permission(db, current_user.role, resource, action)
    return APIResponse(success=True, data={"allowed": allowed, "reason": reason})


@router.post("/evaluate", response_model=APIResponse)
async def evaluate_policy(
    body: EvaluateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """
    Full policy evaluation sandbox — RBAC + group + ABAC + boundary.

    Accepts a hypothetical request context and returns a detailed trace.
    """
    ctx = AccessContext(
        ip=body.ip,
        mfa_verified=body.mfa_verified,
        env_tag=body.env_tag,
        utc_now=__import__("datetime").datetime.utcnow(),
    )
    trace = evaluate_access(db, body.user_id, body.resource, body.action, ctx)
    return APIResponse(success=True, data=EvaluationResult(
        allowed=trace.allowed,
        decision=trace.decision,
        matched_source=trace.matched_source,
        role_checked=trace.role_checked,
        inherited_roles=trace.inherited_roles,
        groups_checked=trace.groups_checked,
        abac_trace=trace.abac_trace,
        boundary_applied=trace.boundary_applied,
        deny_source=trace.deny_source,
    ).model_dump())


@router.get("/users/{user_id}/effective", response_model=APIResponse)
async def get_effective(
    user_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """
    Return the complete effective permission set for a user:
    role perms (with inheritance) + group perms + boundary cap + merged effective list.
    """
    # Non-admins can only view their own effective permissions
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Can only view your own effective permissions")
    result = get_user_effective_permissions(db, user_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return APIResponse(success=True, data=result)


# ---------------------------------------------------------------------------
# Group endpoints
# ---------------------------------------------------------------------------

@router.get("/groups", response_model=APIResponse)
async def list_groups(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """List all groups with member and permission counts."""
    groups = db.query(Group).order_by(Group.name).all()
    out = []
    for g in groups:
        out.append({
            "id": g.id,
            "name": g.name,
            "description": g.description,
            "created_at": g.created_at.isoformat(),
            "member_count": len(g.members),
            "permission_count": len(g.permissions),
        })
    return APIResponse(success=True, data=out)


@router.post("/groups", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_new_group(
    body: GroupCreateRequest,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Create a new group. Admin only."""
    try:
        grp = create_group(db, body.name, body.description or "", current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    write_audit_log(db, user_id=current_user.id, action="create_group", resource="iam",
                    status="safe", ip="0.0.0.0", details=f"Created group '{body.name}'")
    return APIResponse(success=True, data=GroupOut.model_validate(grp).model_dump())


@router.get("/groups/{group_id}", response_model=APIResponse)
async def get_group(
    group_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Return group detail including members and permissions."""
    grp: Optional[Group] = db.query(Group).filter(Group.id == group_id).first()
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    data = {
        "id": grp.id,
        "name": grp.name,
        "description": grp.description,
        "created_at": grp.created_at.isoformat(),
        "created_by": grp.created_by,
        "members": [
            {
                "membership_id": m.id,
                "user_id": m.user_id,
                "assigned_by": m.assigned_by,
                "assigned_at": m.assigned_at.isoformat(),
                "user_email": m.user.email if m.user else None,
                "user_role": m.user.role if m.user else None,
            }
            for m in grp.members
        ],
        "permissions": [
            {"id": p.id, "resource": p.resource, "action": p.action, "effect": p.effect}
            for p in grp.permissions
        ],
    }
    return APIResponse(success=True, data=data)


@router.delete("/groups/{group_id}", response_model=APIResponse)
async def delete_group(
    group_id: int,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Delete a group and all its memberships/permissions. Admin only."""
    grp: Optional[Group] = db.query(Group).filter(Group.id == group_id).first()
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    name = grp.name
    db.delete(grp)
    db.commit()
    write_audit_log(db, user_id=current_user.id, action="delete_group", resource="iam",
                    status="safe", ip="0.0.0.0", details=f"Deleted group '{name}'")
    return APIResponse(success=True, data={"message": f"Group '{name}' deleted"})


@router.post("/groups/{group_id}/members", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def add_member(
    group_id: int,
    body: GroupMemberRequest,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Add a user to a group. Admin only."""
    grp: Optional[Group] = db.query(Group).filter(Group.id == group_id).first()
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    target: Optional[User] = db.query(User).filter(User.id == body.user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    try:
        m = add_group_member(db, group_id, body.user_id, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    write_audit_log(db, user_id=current_user.id, action="group_add_member", resource="iam",
                    status="safe", ip="0.0.0.0",
                    details=f"Added user {body.user_id} to group '{grp.name}'")
    return APIResponse(success=True, data=GroupMemberOut.model_validate(m).model_dump())


@router.delete("/groups/{group_id}/members/{user_id}", response_model=APIResponse)
async def remove_member(
    group_id: int,
    user_id: int,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Remove a user from a group. Admin only."""
    grp: Optional[Group] = db.query(Group).filter(Group.id == group_id).first()
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    remove_group_member(db, group_id, user_id)
    write_audit_log(db, user_id=current_user.id, action="group_remove_member", resource="iam",
                    status="safe", ip="0.0.0.0",
                    details=f"Removed user {user_id} from group '{grp.name}'")
    return APIResponse(success=True, data={"message": f"User {user_id} removed from group"})


@router.post("/groups/{group_id}/permissions", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def add_permission_to_group(
    group_id: int,
    body: GroupPermissionRequest,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Assign a (resource, action, effect) permission to a group. Admin only."""
    grp: Optional[Group] = db.query(Group).filter(Group.id == group_id).first()
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    gp = add_group_permission(db, group_id, body.resource, body.action, body.effect)
    write_audit_log(db, user_id=current_user.id, action="group_add_permission", resource="iam",
                    status="safe", ip="0.0.0.0",
                    details=f"Added {body.effect} {body.resource}:{body.action} to group '{grp.name}'")
    return APIResponse(success=True, data=GroupPermissionOut.model_validate(gp).model_dump())


@router.delete("/groups/{group_id}/permissions/{perm_id}", response_model=APIResponse)
async def remove_permission_from_group(
    group_id: int,
    perm_id: int,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Remove a permission from a group. Admin only."""
    remove_group_permission(db, perm_id)
    return APIResponse(success=True, data={"message": f"Permission {perm_id} removed"})


# ---------------------------------------------------------------------------
# Permission boundary endpoints
# ---------------------------------------------------------------------------

@router.get("/users/{user_id}/boundary", response_model=APIResponse)
async def get_boundary(
    user_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Return the permission boundary for a user (admin or self)."""
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Can only view your own boundary")
    b = db.query(UserPermissionBoundary).filter(UserPermissionBoundary.user_id == user_id).first()
    if not b:
        return APIResponse(success=True, data={"user_id": user_id, "boundary_pairs": [], "updated_at": None})
    import json as _json
    pairs = _json.loads(b.boundary_json) if b.boundary_json else []
    return APIResponse(success=True, data={
        "user_id": user_id,
        "boundary_pairs": pairs,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
    })


@router.put("/users/{user_id}/boundary", response_model=APIResponse)
async def set_boundary(
    user_id: int,
    body: BoundarySetRequest,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Set or replace the permission boundary for a user. Admin only."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    pairs = [{"resource": p.resource, "action": p.action} for p in body.pairs]
    b = set_permission_boundary(db, user_id, pairs, current_user.id)
    write_audit_log(db, user_id=current_user.id, action="set_boundary", resource="iam",
                    status="safe", ip="0.0.0.0",
                    details=f"Set permission boundary for user {user_id}: {len(pairs)} pairs")
    return APIResponse(success=True, data={"user_id": user_id, "boundary_pairs": pairs})


@router.delete("/users/{user_id}/boundary", response_model=APIResponse)
async def clear_boundary(
    user_id: int,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Clear the permission boundary for a user (removes all caps). Admin only."""
    db.query(UserPermissionBoundary).filter(UserPermissionBoundary.user_id == user_id).delete()
    db.commit()
    write_audit_log(db, user_id=current_user.id, action="clear_boundary", resource="iam",
                    status="safe", ip="0.0.0.0",
                    details=f"Cleared permission boundary for user {user_id}")
    return APIResponse(success=True, data={"message": f"Boundary cleared for user {user_id}"})
