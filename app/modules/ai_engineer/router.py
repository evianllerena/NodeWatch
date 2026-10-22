import logging

from fastapi import APIRouter, Body

from app.services.ai_engineer_service import Answer, answer_help, ask, tool

router = APIRouter(prefix='/api/v1/ai-engineer', tags=['ai-engineer'])
log = logging.getLogger(__name__)


@router.post('/ask')
def ask_q(payload: dict = Body(...)):
    question = str(payload.get('question') or '')
    try:
        return ask(question)
    except Exception as exc:  # the chat must always get an answer card, never a stack trace
        log.exception("Operations Assistant failed")
        answer = Answer(
            intent="error",
            headline="Something went wrong while working that out.",
            tone="warning",
            interpreted_as="Internal error",
        )
        answer.fact(f"{type(exc).__name__}: {str(exc)[:200]}", "warning")
        answer.fact("Try again, or open Command Center for the full picture.")
        answer.chip("Open Command Center", tool("dashboard"))
        answer.suggestions = ["What's broken?", "Help"]
        out = answer.to_dict(mode="live")
        out["question"] = question
        return out


@router.get('/help')
def help_card():
    return answer_help().to_dict(mode="live")
