from uuid import UUID

from app.models import Finding, ModuleKey, Project, ProjectModule, ScanTask


class InMemoryStore:
    def __init__(self) -> None:
        self.projects: dict[UUID, Project] = {}
        self.scans: dict[UUID, ScanTask] = {}
        self.findings: dict[UUID, Finding] = {}
        self.project_modules: dict[tuple[UUID, ModuleKey], ProjectModule] = {}


store = InMemoryStore()
