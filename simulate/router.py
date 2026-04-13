"""Simulation API router: single action endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from schemas import APIResponse, SimulateActionRequest, SimulateActionResponse
from auth.dependencies import get_current_user, get_current_session
from models import User, Session as UserSession
from simulate.engine import handle_action, RESOURCE_ACTIONS

router = APIRouter(prefix="/simulate", tags=["Simulation"])


@router.post("/action", response_model=APIResponse)
async def simulate_action(
    body: SimulateActionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[UserSession, Depends(get_current_session)],
    db: Annotated[Session, Depends(get_db)],
):
    """
    Simulate a cloud resource action for a given user.

    Checks authorization, logs the event, and runs threat detection.
    """
    # Validate resource and action
    if body.resource not in RESOURCE_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown resource '{body.resource}'. Valid: {list(RESOURCE_ACTIONS.keys())}",
        )
    if body.action not in RESOURCE_ACTIONS[body.resource]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid action '{body.action}' for resource '{body.resource}'. "
                   f"Valid: {RESOURCE_ACTIONS[body.resource]}",
        )

    result = await handle_action(
        db,
        user_id=body.user_id,
        resource=body.resource,
        action=body.action,
        session_mfa_verified=session.mfa_verified,
        session_id=session.id,
    )
    return APIResponse(
        success=True,
        data=SimulateActionResponse(
            allowed=result["allowed"],
            reason=result["reason"],
            risk_delta=result["risk_delta"],
        ).model_dump(),
    )


@router.get("/resources", response_model=APIResponse)
async def list_resources(current_user: Annotated[User, Depends(get_current_user)]):
    """Return the available simulated resources and their valid actions."""
    return APIResponse(success=True, data=RESOURCE_ACTIONS)
