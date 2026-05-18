from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.services.swap_agent import run_swap_agent

router = APIRouter()


class Message(BaseModel):
    role: str
    content: str


class MatchRequest(BaseModel):
    user_id: int
    message: str
    history: Optional[list[Message]] = []


@router.post("/match")
async def match_swap(payload: MatchRequest):
    try:
        response = await run_swap_agent(payload.user_id, payload.message, payload.history)
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))