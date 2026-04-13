"""Audit log API router: paginated query, CSV/JSON export."""

from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse, JSONResponse
from sqlalchemy.orm import Session

from database import get_db
from schemas import APIResponse, AuditLogPage, AuditLogOut
from auth.dependencies import get_current_user
from audit.service import query_audit_logs, export_logs_csv, export_logs_json
from models import User

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/logs", response_model=APIResponse)
async def get_logs(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    user_id: Optional[int] = Query(None),
    resource: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Return paginated audit logs with optional filters."""
    total, items = query_audit_logs(
        db,
        user_id=user_id,
        resource=resource,
        status=status,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
    )
    page_data = AuditLogPage(
        total=total,
        page=page,
        page_size=page_size,
        items=[AuditLogOut.model_validate(item) for item in items],
    )
    return APIResponse(success=True, data=page_data.model_dump())


@router.get("/export")
async def export_logs(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    format: str = Query("json", pattern="^(csv|json)$"),
):
    """Download full audit log in CSV or JSON format."""
    if format == "csv":
        content = export_logs_csv(db)
        return PlainTextResponse(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
        )
    data = export_logs_json(db)
    return JSONResponse(
        content={"success": True, "data": data},
        headers={"Content-Disposition": "attachment; filename=audit_logs.json"},
    )
