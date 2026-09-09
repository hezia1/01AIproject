from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ProjectGraphNode(BaseModel):
    id: str
    kind: str
    label: str
    file_path: str | None = None
    line: int | None = None
    attributes: dict[str, object] = Field(default_factory=dict)


class ProjectGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    confidence: int = Field(ge=0, le=100)
    basis: str


class ProjectGraphSnapshot(BaseModel):
    id: UUID
    project_id: UUID
    graph_type: Literal["code", "business"]
    version: int
    source_fingerprint: str
    generator_version: str
    status: str
    nodes: list[ProjectGraphNode]
    edges: list[ProjectGraphEdge]
    summary: dict[str, object]
    limitations: list[str]
    created_by: str
    created_at: datetime
