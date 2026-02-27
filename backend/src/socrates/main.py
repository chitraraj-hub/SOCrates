# backend/src/socrates/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from socrates.api.auth     import router as auth_router
from socrates.api.analysis import router as analysis_router

app = FastAPI(
    title="SOCrates",
    description="Know your threats.",
    version="0.1.0",
)

# CORS — allow Next.js frontend on port 3000
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(analysis_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "SOCrates"}