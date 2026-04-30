from fastapi import FastAPI
from app.routers import ai

app = FastAPI(
    title="AI Service",
    version="1.0.0",
    description="AI microservice for the platform",
)

app.include_router(ai.router, prefix="/api/ai", tags=["AI"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "ai_service"}