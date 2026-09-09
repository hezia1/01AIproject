from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ProjectGraphSnapshotRecord, ProjectRecord
from app.project_graph_models import ProjectGraphSnapshot
from app.services.audit import record_audit
from app.services.auth import current_identity
from app.services.project_graphs import GENERATOR_VERSION, build_business_graph, build_code_graph

router = APIRouter()
GRAPH_TYPES = {"code", "business"}


def require_project(db: Session, project_id: UUID, tenant_id: str) -> ProjectRecord:
    project = db.get(ProjectRecord, str(project_id))
    if project is None or str(project.tenant_id) != tenant_id:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def latest_snapshot(db: Session, project_id: UUID, graph_type: str) -> ProjectGraphSnapshotRecord | None:
    return db.scalar(select(ProjectGraphSnapshotRecord).where(
        ProjectGraphSnapshotRecord.project_id == str(project_id),
        ProjectGraphSnapshotRecord.graph_type == graph_type,
    ).order_by(ProjectGraphSnapshotRecord.version.desc()))


def snapshot_response(record: ProjectGraphSnapshotRecord, *, kind: str | None = None,
                      relation: str | None = None, query: str | None = None) -> ProjectGraphSnapshot:
    nodes = list(record.nodes or [])
    edges = list(record.edges or [])
    if kind:
        nodes = [item for item in nodes if item.get("kind") == kind]
    if query:
        needle = query.casefold()
        nodes = [item for item in nodes if needle in str(item.get("label", "")).casefold()
                 or needle in str(item.get("file_path", "")).casefold()]
    if kind or query:
        node_ids = {str(item.get("id")) for item in nodes}
        edges = [item for item in edges if item.get("source") in node_ids and item.get("target") in node_ids]
    if relation:
        edges = [item for item in edges if item.get("relation") == relation]
        if not kind and not query:
            related = {str(item.get("source")) for item in edges} | {str(item.get("target")) for item in edges}
            nodes = [item for item in nodes if item.get("id") in related]
    return ProjectGraphSnapshot(
        id=UUID(str(record.id)), project_id=UUID(str(record.project_id)), graph_type=record.graph_type,
        version=record.version, source_fingerprint=record.source_fingerprint,
        generator_version=record.generator_version, status=record.status, nodes=nodes, edges=edges,
        summary={**dict(record.summary or {}), "returned_node_count": len(nodes), "returned_edge_count": len(edges)},
        limitations=list(record.limitations or []), created_by=record.created_by, created_at=record.created_at,
    )


@router.get("/projects/{project_id}/{graph_type}", response_model=ProjectGraphSnapshot)
def get_graph(project_id: UUID, graph_type: str, request: Request,
              kind: str | None = Query(default=None, max_length=80),
              relation: str | None = Query(default=None, max_length=80),
              q: str | None = Query(default=None, max_length=200), db: Session = Depends(get_db)):
    if graph_type not in GRAPH_TYPES:
        raise HTTPException(status_code=404, detail="Graph type not found")
    identity = current_identity(request)
    require_project(db, project_id, identity.tenant_id)
    record = latest_snapshot(db, project_id, graph_type)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{graph_type.title()} graph has not been built")
    return snapshot_response(record, kind=kind, relation=relation, query=q)


@router.post("/projects/{project_id}/{graph_type}/rebuild", response_model=ProjectGraphSnapshot)
def rebuild_graph(project_id: UUID, graph_type: str, request: Request, db: Session = Depends(get_db)):
    if graph_type not in GRAPH_TYPES:
        raise HTTPException(status_code=404, detail="Graph type not found")
    identity = current_identity(request)
    project = require_project(db, project_id, identity.tenant_id)
    try:
        if graph_type == "code":
            result = build_code_graph(project.source_path)
        else:
            result = build_business_graph(db, project, latest_snapshot(db, project_id, "code"))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    version = int(db.scalar(select(func.coalesce(func.max(ProjectGraphSnapshotRecord.version), 0)).where(
        ProjectGraphSnapshotRecord.project_id == str(project_id),
        ProjectGraphSnapshotRecord.graph_type == graph_type,
    )) or 0) + 1
    record = ProjectGraphSnapshotRecord(
        project_id=str(project_id), graph_type=graph_type, version=version,
        source_fingerprint=result["source_fingerprint"], generator_version=GENERATOR_VERSION,
        status="completed", nodes=result["nodes"], edges=result["edges"],
        summary=result["summary"], limitations=result["limitations"], created_by=identity.username,
        created_at=datetime.utcnow(),
    )
    db.add(record)
    db.flush()
    record_audit(db, tenant_id=identity.tenant_id,
                 user_id=None if identity.user_id == "00000000-0000-0000-0000-000000000000" else identity.user_id,
                 project_id=str(project_id), action=f"project_graph.{graph_type}.rebuilt", outcome="completed",
                 detail={"snapshot_id": str(record.id), "version": version,
                         "node_count": len(record.nodes), "edge_count": len(record.edges)})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Graph version changed concurrently; rebuild again") from exc
    db.refresh(record)
    return snapshot_response(record)
