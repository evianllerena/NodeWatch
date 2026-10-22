from fastapi import APIRouter, Body, HTTPException
from app.core.security import redact_text
from app.services.validation_service import run_validation, list_reports

router = APIRouter(prefix='/api/v1/validator', tags=['validator'])


@router.post('/run')
def run(payload: dict = Body(...)):
    try:
        return run_validation(
            str(payload.get('site_id') or ''),
            str(payload.get('device_id') or ''),
            expected=payload.get('expected') if isinstance(payload.get('expected'), dict) else None,
            label=str(payload.get('label') or 'manual'),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=redact_text(exc)) from exc


@router.get('/reports')
def reports():
    return {'reports': list_reports()}
