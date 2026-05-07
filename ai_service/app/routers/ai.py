from fastapi import APIRouter
from pydantic import BaseModel
from app.services.ai_handler import handle_ai_request
from app.services.rag_handler import ask_book, ingest_book

router = APIRouter()


class AIRequest(BaseModel):
    prompt: str
    context: dict = {}


class AIResponse(BaseModel):
    result: str
    status: str


class AskRequest(BaseModel):
    book_id: int
    question: str


class AskResponse(BaseModel):
    answer: str
    status: str

class IngestRequest(BaseModel):
    book_id: int
    title: str
    author: str
    text: str

class IngestResponse(BaseModel):
    chunks: int
    status: str

@router.post("/process", response_model=AIResponse)
async def process(request: AIRequest):
    result = await handle_ai_request(request.prompt, request.context)
    return AIResponse(result=result, status="success")


@router.post("/ask", response_model=AskResponse)
async def ask(request: AskRequest):
    answer = ask_book(request.book_id, request.question)
    return AskResponse(answer=answer, status="success")

@router.post("/ingest", response_model=IngestResponse)
async def ingest(request: IngestRequest):
    count = ingest_book(
        request.book_id,
        request.title,
        request.author,
        request.text
    )
    return IngestResponse(chunks=count, status="success")