from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import create_db_schema
from app.routers import agent, aspm, dast, findings, modules, projects, sandbox, scans, sast, sca

app = FastAPI(
    title="AI Native Application Security Platform",
    description="MVP API for project, scan, finding, and governance workflows.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router, prefix="/api/projects", tags=["projects"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(modules.router, prefix="/api/modules", tags=["modules"])
app.include_router(sca.router, prefix="/api/sca", tags=["sca"])
app.include_router(sast.router, prefix="/api/sast", tags=["sast"])
app.include_router(agent.router, prefix="/api/agent", tags=["agent"])
app.include_router(dast.router, prefix="/api/dast", tags=["dast"])
app.include_router(sandbox.router, prefix="/api/sandbox", tags=["sandbox"])
app.include_router(aspm.router, prefix="/api/aspm", tags=["aspm"])


@app.on_event("startup")
def on_startup() -> None:
    create_db_schema()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}



