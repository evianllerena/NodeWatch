from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException

from app.ui.preferences import public_state, set_preferences

router = APIRouter(prefix="/api/ui", tags=["ui"])


@router.get("")
def ui_state():
    return public_state()


def _save(**changes):
    try:
        set_preferences(**changes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return public_state()


@router.post("/theme")
def choose_theme(payload: dict = Body(...)):
    return _save(theme=str(payload.get("theme") or ""))


@router.post("/preferences")
def save_preferences(payload: dict = Body(...)):
    """Any of: theme, night (off / on / system), menu (shown / hidden), layout (object, see preferences.py)."""
    allowed = {"theme", "night", "menu", "layout"}
    unknown = set(payload) - allowed
    if unknown or not payload:
        raise HTTPException(status_code=400, detail=f"Send one or more of: {', '.join(sorted(allowed))}")
    return _save(**{k: (v if k == "layout" else str(v)) for k, v in payload.items()})
