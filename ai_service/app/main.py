from fastapi import FastAPI
from app.routers import ai,agent

app = FastAPI(
    title="AI Service",
    version="1.0.0",
    description="AI microservice for the platform",
)

app.include_router(ai.router, prefix="/api/ai", tags=["AI"])
app.include_router(agent.router, prefix="/api/agent", tags=["Agent"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "ai_service"}