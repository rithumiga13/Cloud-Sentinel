"""
IAM service — full RBAC + ABAC + Groups + Permission Boundary engine.

Evaluation order (deny wins):
  1. Collect role permissions  (including inherited roles up the hierarchy)
  2. Collect group permissions (from all groups the user belongs to)
  3. If any source yields an explicit DENY  → denied
  4. If any source yields an ALLOW          → evaluate ABAC conditions
  5. Check permission boundary (user-level cap)
  6. Otherwise                              → no permission
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, time
from typing import Optional, List, Dict, Any

from sqlalchemy.orm import Session

from models import (
    Permission, GroupPermission, GroupMembership, Group,
    PolicyCondition, UserPermissionBoundary, User, RoleEnum, EffectEnum,
)

# ---------------------------------------------------------------------------
# Role hierarchy
# ---------------------------------------------------------------------------

# Each role inherits the permissions of the roles listed after it.
ROLE_HIERARCHY: Dict[str, List[str]] = {
    "admin":          ["admin", "power_user", "normal_user", "read_only"],
    "power_user":     ["power_user", "normal_user", "read_only"],
    "normal_user":    ["normal_user", "read_only"],
    "read_only":      ["read_only"],
    "service_account": ["service_account"],
}

# ---------------------------------------------------------------------------
# Default permission matrix (includes ABAC conditions)
# ---------------------------------------------------------------------------

DEFAULT_PERMISSIONS: List[dict] = [
    # Admin — full access (no conditions)
    *[{"role": "admin", "resource": r, "action": a, "effect": "allow"}
      for r in ("s3", "ec2", "lambda", "rds", "iam", "vpc")
      for a in ("list", "get", "put", "delete", "describe", "start", "stop",
                "terminate", "invoke", "connect", "modify", "attach-policy",
                "list-users", "create", "update")],

    # Power user
    {"role": "power_user", "resource": "s3",     "action": "list",    "effect": "allow"},
    {"role": "power_user", "resource": "s3",     "action": "get",     "effect": "allow"},
    {"role": "power_user", "resource": "s3",     "action": "put",     "effect": "allow",
     "conditions": [{"type": "require_mfa", "value": "true",
                     "description": "S3 writes require MFA"}]},
    {"role": "power_user", "resource": "s3",     "action": "delete",  "effect": "allow",
     "conditions": [{"type": "require_mfa", "value": "true",
                     "description": "S3 deletes require MFA"}]},
    {"role": "power_user", "resource": "ec2",    "action": "describe","effect": "allow"},
    {"role": "power_user", "resource": "ec2",    "action": "start",   "effect": "allow",
     "conditions": [{"type": "time_window", "value": "06:00-22:00",
                     "description": "EC2 start only during business hours"}]},
    {"role": "power_user", "resource": "ec2",    "action": "stop",    "effect": "allow"},
    {"role": "power_user", "resource": "lambda", "action": "list",    "effect": "allow"},
    {"role": "power_user", "resource": "lambda", "action": "invoke",  "effect": "allow"},
    {"role": "power_user", "resource": "rds",    "action": "describe","effect": "allow"},
    {"role": "power_user", "resource": "rds",    "action": "connect", "effect": "allow",
     "conditions": [{"type": "require_mfa", "value": "true",
                     "description": "RDS connect requires MFA"},
                    {"type": "ip_allowlist", "value": "10.0.0.0/8,192.168.0.0/16",
                     "description": "RDS only from internal networks"}]},
    {"role": "power_user", "resource": "vpc",    "action": "describe","effect": "allow"},

    # Normal user
    {"role": "normal_user", "resource": "s3",     "action": "list",    "effect": "allow"},
    {"role": "normal_user", "resource": "s3",     "action": "get",     "effect": "allow"},
    {"role": "normal_user", "resource": "ec2",    "action": "describe","effect": "allow"},
    {"role": "normal_user", "resource": "lambda", "action": "list",    "effect": "allow"},
    {"role": "normal_user", "resource": "rds",    "action": "describe","effect": "allow"},

    # Read-only
    {"role": "read_only", "resource": "s3",     "action": "list",    "effect": "allow"},
    {"role": "read_only", "resource": "ec2",    "action": "describe","effect": "allow"},
    {"role": "read_only", "resource": "lambda", "action": "list",    "effect": "allow"},
    {"role": "read_only", "resource": "rds",    "action": "describe","effect": "allow"},
    {"role": "read_only", "resource": "vpc",    "action": "describe","effect": "allow"},

    # Service account (no EC2/RDS — triggers R7 alert if attempted)
    {"role": "service_account", "resource": "s3",     "action": "list",    "effect": "allow"},
    {"role": "service_account", "resource": "s3",     "action": "get",     "effect": "allow"},
    {"role": "service_account", "resource": "s3",     "action": "put",     "effect": "allow"},
    {"role": "service_account", "resource": "lambda", "action": "list",    "effect": "allow"},
    {"role": "service_account", "resource": "lambda", "action": "invoke",  "effect": "allow"},
]

# Default groups seeded on startup
DEFAULT_GROUPS: List[dict] = [
    {
        "name": "data-engineers",
        "description": "Data engineering team — extra S3 and RDS access",
        "permissions": [
            {"resource": "s3",  "action": "put",     "effect": "allow"},
            {"resource": "s3",  "action": "delete",  "effect": "allow"},
            {"resource": "rds", "action": "connect", "effect": "allow"},
        ],
    },
    {
        "name": "ops-team",
        "description": "Operations team — EC2 lifecycle control",
        "permissions": [
            {"resource": "ec2", "action": "start",     "effect": "allow"},
            {"resource": "ec2", "action": "stop",      "effect": "allow"},
            {"resource": "ec2", "action": "terminate", "effect": "allow"},
        ],
    },
    {
        "name": "security-review",
        "description": "Security reviewers — read-only IAM inspection",
        "permissions": [
            {"resource": "iam", "action": "list-users", "effect": "allow"},
        ],
    },
]


def seed_permissions(db: Session) -> None:
    """Insert the default permission matrix and starter groups if tables are empty."""
    if db.query(Permission).count() > 0:
        return

    for p in DEFAULT_PERMISSIONS:
        perm = Permission(
            role=p["role"],
            resource=p["resource"],
            action=p["action"],
            effect=p["effect"],
        )
        db.add(perm)
        db.flush()
        for cond in p.get("conditions", []):
            db.add(PolicyCondition(
                permission_id=perm.id,
                condition_type=cond["type"],
                condition_value=cond["value"],
                description=cond.get("description"),
            ))

    # Seed default groups (no creator — system groups)
    for g in DEFAULT_GROUPS:
        grp = Group(name=g["name"], description=g["description"])
        db.add(grp)
        db.flush()
        for gp in g["permissions"]:
            db.add(GroupPermission(
                group_id=grp.id,
                resource=gp["resource"],
                action=gp["action"],
                effect=gp["effect"],
            ))

    db.commit()


# ---------------------------------------------------------------------------
# ABAC condition evaluator
# ---------------------------------------------------------------------------

@dataclass
class AccessContext:
    """Runtime context passed to the ABAC evaluator."""
    ip: str = "0.0.0.0"
    mfa_verified: bool = False
    utc_now: datetime = field(default_factory=datetime.utcnow)
    env_tag: str = "dev"          # resource environment tag
    owner_id: Optional[int] = None
    requester_id: Optional[int] = None


def _eval_condition(cond: PolicyCondition, ctx: AccessContext) -> tuple[bool, str]:
    """
    Evaluate a single PolicyCondition against the current AccessContext.

    Returns (passes, explanation).
    """
    ct = cond.condition_type
    cv = cond.condition_value.strip()

    if ct == "require_mfa":
        if not ctx.mfa_verified:
            return False, f"ABAC: MFA required but session is not MFA-verified"
        return True, "ABAC: MFA check passed"

    if ct == "ip_allowlist":
        allowed_networks = [n.strip() for n in cv.split(",")]
        try:
            req_ip = ipaddress.ip_address(ctx.ip)
            for net_str in allowed_networks:
                try:
                    if req_ip in ipaddress.ip_network(net_str, strict=False):
                        return True, f"ABAC: IP {ctx.ip} in allowlist"
                except ValueError:
                    if ctx.ip == net_str:
                        return True, f"ABAC: IP exact match"
            return False, f"ABAC: IP {ctx.ip} not in allowlist {cv}"
        except ValueError:
            return False, f"ABAC: unparseable IP '{ctx.ip}'"

    if ct == "time_window":
        # Format: "HH:MM-HH:MM"
        try:
            start_str, end_str = cv.split("-")
            sh, sm = map(int, start_str.strip().split(":"))
            eh, em = map(int, end_str.strip().split(":"))
            now_minutes = ctx.utc_now.hour * 60 + ctx.utc_now.minute
            start_minutes = sh * 60 + sm
            end_minutes = eh * 60 + em
            if start_minutes <= now_minutes <= end_minutes:
                return True, f"ABAC: time {ctx.utc_now.strftime('%H:%M')} UTC in window {cv}"
            return False, f"ABAC: time {ctx.utc_now.strftime('%H:%M')} UTC outside window {cv}"
        except Exception:
            return False, f"ABAC: invalid time_window format '{cv}'"

    if ct == "env_tag":
        if ctx.env_tag.lower() == cv.lower():
            return True, f"ABAC: env tag '{ctx.env_tag}' matches"
        return False, f"ABAC: env tag '{ctx.env_tag}' != required '{cv}'"

    return True, f"ABAC: unknown condition type '{ct}' — skipped"


def _eval_conditions(conditions: List[PolicyCondition], ctx: AccessContext) -> tuple[bool, List[str]]:
    """
    Evaluate all conditions on a permission (ALL must pass).

    Returns (all_pass, [explanation_strings]).
    """
    explanations: List[str] = []
    for cond in conditions:
        passed, explanation = _eval_condition(cond, ctx)
        explanations.append(explanation)
        if not passed:
            return False, explanations
    return True, explanations


# ---------------------------------------------------------------------------
# Core evaluation engine
# ---------------------------------------------------------------------------

@dataclass
class EvaluationTrace:
    """Detailed explanation of why a permission was granted or denied."""
    allowed: bool
    decision: str            # short human-readable verdict
    matched_source: str      # "role", "group:<name>", "boundary", "no_match"
    role_checked: str
    inherited_roles: List[str]
    groups_checked: List[str]
    abac_trace: List[str]
    boundary_applied: bool
    deny_source: str         # non-empty if an explicit deny was found


def evaluate_access(
    db: Session,
    user_id: int,
    resource: str,
    action: str,
    ctx: Optional[AccessContext] = None,
) -> EvaluationTrace:
    """
    Full IAM policy evaluation for a user requesting (resource, action).

    Algorithm:
      1. Expand user's role to inherited roles (hierarchy)
      2. Collect matching role-level permissions
      3. Collect matching group-level permissions (from user's groups)
      4. Deny wins: if any deny found → denied with source annotation
      5. Check ABAC conditions on all matching allow permissions
      6. Apply permission boundary (user-level cap)
      7. Return trace with full explanation

    Returns EvaluationTrace.
    """
    if ctx is None:
        ctx = AccessContext()

    user: Optional[User] = db.query(User).filter(User.id == user_id).first()
    if not user:
        return EvaluationTrace(
            allowed=False, decision="User not found",
            matched_source="no_match", role_checked="", inherited_roles=[],
            groups_checked=[], abac_trace=[], boundary_applied=False, deny_source="",
        )

    role = user.role
    inherited = ROLE_HIERARCHY.get(role, [role])

    # -- Step 1: Role-level permissions (including inherited roles) ----------
    role_perms = (
        db.query(Permission)
        .filter(
            Permission.role.in_(inherited),
            Permission.resource == resource,
            Permission.action == action,
        )
        .all()
    )

    role_denies   = [p for p in role_perms if p.effect == "deny"]
    role_allows   = [p for p in role_perms if p.effect == "allow"]

    if role_denies:
        return EvaluationTrace(
            allowed=False,
            decision=f"Explicit role deny for '{action}' on '{resource}'",
            matched_source="role",
            role_checked=role,
            inherited_roles=inherited,
            groups_checked=[],
            abac_trace=[],
            boundary_applied=False,
            deny_source=f"role:{role_denies[0].role}",
        )

    # -- Step 2: Group-level permissions ------------------------------------
    memberships = (
        db.query(GroupMembership)
        .filter(GroupMembership.user_id == user_id)
        .all()
    )
    group_ids = [m.group_id for m in memberships]
    group_names: List[str] = []

    group_denies: List[GroupPermission] = []
    group_allows: List[GroupPermission] = []

    if group_ids:
        groups = db.query(Group).filter(Group.id.in_(group_ids)).all()
        group_names = [g.name for g in groups]

        grp_perms = (
            db.query(GroupPermission)
            .filter(
                GroupPermission.group_id.in_(group_ids),
                GroupPermission.resource == resource,
                GroupPermission.action == action,
            )
            .all()
        )
        group_denies = [p for p in grp_perms if p.effect == "deny"]
        group_allows = [p for p in grp_perms if p.effect == "allow"]

    if group_denies:
        # Find the group name for the deny
        deny_group_id = group_denies[0].group_id
        deny_group = db.query(Group).filter(Group.id == deny_group_id).first()
        deny_name = deny_group.name if deny_group else str(deny_group_id)
        return EvaluationTrace(
            allowed=False,
            decision=f"Explicit group deny from '{deny_name}' for '{action}' on '{resource}'",
            matched_source=f"group:{deny_name}",
            role_checked=role,
            inherited_roles=inherited,
            groups_checked=group_names,
            abac_trace=[],
            boundary_applied=False,
            deny_source=f"group:{deny_name}",
        )

    # -- Step 3: Resolve allow source (role or group) -----------------------
    allow_source: str = ""
    abac_trace: List[str] = []
    allow_perm_conditions: List[PolicyCondition] = []

    if role_allows:
        allow_source = f"role:{role}"
        # Use conditions from the most-specific role (first in inheritance list)
        allow_perm_conditions = role_allows[0].conditions

    elif group_allows:
        # Find which group name contributed the allow
        grp = db.query(Group).filter(Group.id == group_allows[0].group_id).first()
        allow_source = f"group:{grp.name if grp else group_allows[0].group_id}"
        # Group permissions have no ABAC conditions (by design — simpler model)

    else:
        # Fallback: owner-only ABAC shortcut for admin role on any resource
        if role == "admin":
            allow_source = "role:admin"
        else:
            return EvaluationTrace(
                allowed=False,
                decision=f"No permission: role '{role}' (+ {len(group_names)} groups) lacks '{action}' on '{resource}'",
                matched_source="no_match",
                role_checked=role,
                inherited_roles=inherited,
                groups_checked=group_names,
                abac_trace=[],
                boundary_applied=False,
                deny_source="",
            )

    # -- Step 4: ABAC conditions --------------------------------------------
    if allow_perm_conditions:
        passed, abac_trace = _eval_conditions(allow_perm_conditions, ctx)
        if not passed:
            return EvaluationTrace(
                allowed=False,
                decision=f"ABAC condition failed for '{action}' on '{resource}'",
                matched_source=allow_source,
                role_checked=role,
                inherited_roles=inherited,
                groups_checked=group_names,
                abac_trace=abac_trace,
                boundary_applied=False,
                deny_source=f"abac:{abac_trace[-1]}",
            )

    # Owner-only ABAC (resource.owner != requester && not admin)
    if ctx.owner_id and ctx.requester_id:
        if action in ("put", "delete", "modify", "update") and ctx.owner_id != ctx.requester_id and role != "admin":
            return EvaluationTrace(
                allowed=False,
                decision=f"ABAC owner check: resource owned by {ctx.owner_id}, requester is {ctx.requester_id}",
                matched_source=allow_source,
                role_checked=role,
                inherited_roles=inherited,
                groups_checked=group_names,
                abac_trace=abac_trace + ["ABAC owner mismatch"],
                boundary_applied=False,
                deny_source="abac:owner",
            )

    # -- Step 5: Permission boundary ----------------------------------------
    boundary: Optional[UserPermissionBoundary] = (
        db.query(UserPermissionBoundary)
        .filter(UserPermissionBoundary.user_id == user_id)
        .first()
    )
    boundary_applied = False
    if boundary and boundary.boundary_json:
        try:
            allowed_pairs = json.loads(boundary.boundary_json)
            if allowed_pairs:  # empty list = no cap
                boundary_applied = True
                in_boundary = any(
                    p.get("resource") == resource and p.get("action") == action
                    for p in allowed_pairs
                )
                if not in_boundary:
                    return EvaluationTrace(
                        allowed=False,
                        decision=f"Permission boundary: '{action}' on '{resource}' not in user's boundary",
                        matched_source="boundary",
                        role_checked=role,
                        inherited_roles=inherited,
                        groups_checked=group_names,
                        abac_trace=abac_trace,
                        boundary_applied=True,
                        deny_source="boundary",
                    )
        except (json.JSONDecodeError, TypeError):
            pass

    # -- Allowed -------------------------------------------------------------
    return EvaluationTrace(
        allowed=True,
        decision=f"Allowed via {allow_source}: '{action}' on '{resource}'",
        matched_source=allow_source,
        role_checked=role,
        inherited_roles=inherited,
        groups_checked=group_names,
        abac_trace=abac_trace,
        boundary_applied=boundary_applied,
        deny_source="",
    )


def check_permission(
    db: Session,
    role: str,
    resource: str,
    action: str,
    owner_id: Optional[int] = None,
    requester_id: Optional[int] = None,
) -> tuple[bool, str]:
    """
    Lightweight RBAC-only check (no user_id / group context).

    Used by the simulation engine for fast path evaluation.
    Returns (is_allowed, reason).
    """
    inherited = ROLE_HIERARCHY.get(role, [role])
    deny = (
        db.query(Permission)
        .filter(
            Permission.role.in_(inherited),
            Permission.resource == resource,
            Permission.action == action,
            Permission.effect == "deny",
        )
        .first()
    )
    if deny:
        return False, f"Explicit deny: role '{deny.role}' denied '{action}' on '{resource}'"

    allow = (
        db.query(Permission)
        .filter(
            Permission.role.in_(inherited),
            Permission.resource == resource,
            Permission.action == action,
            Permission.effect == "allow",
        )
        .first()
    )
    if allow:
        if owner_id and requester_id and action in ("put", "delete", "modify", "update"):
            if owner_id != requester_id and role != "admin":
                return False, f"ABAC deny: resource owned by {owner_id}, not {requester_id}"
        return True, f"Allowed: role '{allow.role}' (via hierarchy) grants '{action}' on '{resource}'"

    return False, f"No permission: role '{role}' hierarchy lacks '{action}' on '{resource}'"


# ---------------------------------------------------------------------------
# Effective permissions: all (resource, action) pairs accessible to a user
# ---------------------------------------------------------------------------

def get_effective_permissions(db: Session, role: str) -> List[Permission]:
    """Return all role-level Permission rows for the role (including inherited)."""
    inherited = ROLE_HIERARCHY.get(role, [role])
    return db.query(Permission).filter(Permission.role.in_(inherited)).all()


def get_user_effective_permissions(
    db: Session, user_id: int
) -> dict:
    """
    Compute the full effective permission set for a user.

    Returns a dict:
      {
        "role": str,
        "inherited_roles": [...],
        "groups": [{"name": str, "permissions": [...]}],
        "role_permissions": [...],
        "group_permissions": [...],
        "boundary_cap": [...] | null,
        "effective": [{"resource": str, "action": str, "effect": str, "source": str}]
      }
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {}

    inherited = ROLE_HIERARCHY.get(user.role, [user.role])
    role_perms = (
        db.query(Permission)
        .filter(Permission.role.in_(inherited))
        .all()
    )

    # Group memberships
    memberships = db.query(GroupMembership).filter(GroupMembership.user_id == user_id).all()
    groups_data = []
    all_group_perms: List[GroupPermission] = []
    for m in memberships:
        grp = db.query(Group).filter(Group.id == m.group_id).first()
        if not grp:
            continue
        g_perms = grp.permissions
        all_group_perms.extend(g_perms)
        groups_data.append({
            "id": grp.id,
            "name": grp.name,
            "permissions": [
                {"resource": gp.resource, "action": gp.action, "effect": gp.effect}
                for gp in g_perms
            ],
        })

    # Boundary
    boundary = db.query(UserPermissionBoundary).filter(UserPermissionBoundary.user_id == user_id).first()
    boundary_cap = None
    if boundary and boundary.boundary_json:
        try:
            bc = json.loads(boundary.boundary_json)
            boundary_cap = bc if bc else None
        except Exception:
            pass

    # Build effective set (deny wins, then boundary cap)
    effective_map: dict[tuple[str, str], dict] = {}

    for rp in role_perms:
        key = (rp.resource, rp.action)
        existing = effective_map.get(key)
        if not existing or rp.effect == "deny":
            effective_map[key] = {
                "resource": rp.resource,
                "action": rp.action,
                "effect": rp.effect,
                "source": f"role:{rp.role}",
                "conditions": [
                    {"type": c.condition_type, "value": c.condition_value, "description": c.description}
                    for c in rp.conditions
                ],
            }

    for gp in all_group_perms:
        key = (gp.resource, gp.action)
        existing = effective_map.get(key)
        grp = db.query(Group).filter(Group.id == gp.group_id).first()
        gname = grp.name if grp else str(gp.group_id)
        if not existing:
            effective_map[key] = {
                "resource": gp.resource,
                "action": gp.action,
                "effect": gp.effect,
                "source": f"group:{gname}",
                "conditions": [],
            }
        elif gp.effect == "deny":
            effective_map[key] = {
                "resource": gp.resource,
                "action": gp.action,
                "effect": "deny",
                "source": f"group:{gname}",
                "conditions": [],
            }

    # Apply boundary cap
    if boundary_cap:
        allowed_keys = {(p["resource"], p["action"]) for p in boundary_cap}
        for key in list(effective_map.keys()):
            if effective_map[key]["effect"] == "allow" and key not in allowed_keys:
                effective_map[key]["effect"] = "deny(boundary)"
                effective_map[key]["source"] += "+boundary_cap"

    effective_list = sorted(effective_map.values(), key=lambda x: (x["resource"], x["action"]))

    return {
        "role": user.role,
        "inherited_roles": inherited,
        "groups": groups_data,
        "role_permissions": [
            {"resource": p.resource, "action": p.action, "effect": p.effect,
             "role": p.role, "conditions": [
                {"type": c.condition_type, "value": c.condition_value}
                for c in p.conditions
             ]}
            for p in role_perms
        ],
        "group_permissions": [
            {"resource": gp.resource, "action": gp.action, "effect": gp.effect,
             "group_id": gp.group_id}
            for gp in all_group_perms
        ],
        "boundary_cap": boundary_cap,
        "effective": effective_list,
    }


# ---------------------------------------------------------------------------
# Policy update helpers
# ---------------------------------------------------------------------------

def update_user_policy(
    db: Session,
    target_user: User,
    new_role: str,
    acting_user_id: int,
) -> User:
    """Change the role of target_user. Admin-only. Returns updated User."""
    target_user.role = new_role
    db.commit()
    db.refresh(target_user)
    return target_user


# ---------------------------------------------------------------------------
# Group management
# ---------------------------------------------------------------------------

def create_group(db: Session, name: str, description: str, creator_id: int) -> Group:
    """Create a new group. Raises ValueError if name already exists."""
    if db.query(Group).filter(Group.name == name).first():
        raise ValueError(f"Group '{name}' already exists")
    grp = Group(name=name, description=description, created_by=creator_id)
    db.add(grp)
    db.commit()
    db.refresh(grp)
    return grp


def add_group_member(db: Session, group_id: int, user_id: int, assigner_id: int) -> GroupMembership:
    """Add a user to a group. Raises ValueError on duplicate membership."""
    existing = (
        db.query(GroupMembership)
        .filter(GroupMembership.group_id == group_id, GroupMembership.user_id == user_id)
        .first()
    )
    if existing:
        raise ValueError("User is already a member of this group")
    m = GroupMembership(group_id=group_id, user_id=user_id, assigned_by=assigner_id)
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def remove_group_member(db: Session, group_id: int, user_id: int) -> None:
    """Remove a user from a group. Silent no-op if not a member."""
    db.query(GroupMembership).filter(
        GroupMembership.group_id == group_id,
        GroupMembership.user_id == user_id,
    ).delete()
    db.commit()


def add_group_permission(
    db: Session, group_id: int, resource: str, action: str, effect: str
) -> GroupPermission:
    """Add a permission to a group."""
    gp = GroupPermission(group_id=group_id, resource=resource, action=action, effect=effect)
    db.add(gp)
    db.commit()
    db.refresh(gp)
    return gp


def remove_group_permission(db: Session, group_permission_id: int) -> None:
    """Remove a group permission by id."""
    db.query(GroupPermission).filter(GroupPermission.id == group_permission_id).delete()
    db.commit()


# ---------------------------------------------------------------------------
# Permission boundary management
# ---------------------------------------------------------------------------

def set_permission_boundary(
    db: Session,
    user_id: int,
    boundary_pairs: List[dict],
    updater_id: int,
) -> UserPermissionBoundary:
    """
    Set or replace the permission boundary for a user.

    boundary_pairs: [{"resource": "s3", "action": "list"}, ...]
    An empty list removes the cap.
    """
    existing = db.query(UserPermissionBoundary).filter(
        UserPermissionBoundary.user_id == user_id
    ).first()
    if existing:
        existing.boundary_json = json.dumps(boundary_pairs)
        existing.updated_at = datetime.utcnow()
        existing.updated_by = updater_id
        db.commit()
        db.refresh(existing)
        return existing
    boundary = UserPermissionBoundary(
        user_id=user_id,
        boundary_json=json.dumps(boundary_pairs),
        updated_by=updater_id,
    )
    db.add(boundary)
    db.commit()
    db.refresh(boundary)
    return boundary
