from fastapi import APIRouter
from pydantic import BaseModel
from app.services.ai_handler import handle_ai_request

router = APIRouter()


class AIRequest(BaseModel):
    prompt: str
    context: dict = {}


class AIResponse(BaseModel):
    result: str
    status: str


@router.post("/process", response_model=AIResponse)
async def process(request: AIRequest):
    result = await handle_ai_request(request.prompt, request.context)
    return AIResponse(result=result, status="success")