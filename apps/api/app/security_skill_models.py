from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SecuritySkillSelectors(BaseModel):
    sources: list[Literal["SCA", "SAST", "AGENT"]] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list, max_length=100)
    categories: list[str] = Field(default_factory=list, max_length=100)
    severities: list[Literal["critical", "high", "medium", "low", "info"]] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("rule_ids", "categories", "statuses")
    @classmethod
    def clean_values(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            item = value.strip()
            if not item or len(item) > 300:
                raise ValueError("selector values must contain 1 to 300 characters")
            if item not in cleaned:
                cleaned.append(item)
        return cleaned


class SecuritySkillManifest(BaseModel):
    action: Literal["review_existing_findings"] = "review_existing_findings"
    selectors: SecuritySkillSelectors
    evidence_required: list[Literal["finding_location", "finding_evidence", "ai_review"]] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_selector(self):
        if not any((self.selectors.sources, self.selectors.rule_ids, self.selectors.categories,
                    self.selectors.severities, self.selectors.statuses)):
            raise ValueError("at least one finding selector is required")
        return self


class SecuritySkillCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,118}[a-z0-9]$", max_length=120)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    module: Literal["sca", "sast", "agent", "cross"]
    manifest: SecuritySkillManifest
    change_note: str | None = Field(default=None, max_length=2000)


class SecuritySkillVersionCreate(BaseModel):
    manifest: SecuritySkillManifest
    change_note: str = Field(min_length=1, max_length=2000)


class SecuritySkillVersion(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version: int
    manifest: SecuritySkillManifest
    status: str
    change_note: str | None
    created_by: str
    created_at: datetime
    published_at: datetime | None


class SecuritySkill(BaseModel):
    id: UUID
    slug: str
    name: str
    description: str
    module: str
    status: str
    active_version: int | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    versions: list[SecuritySkillVersion]


class SecuritySkillRun(BaseModel):
    id: UUID
    skill_id: UUID
    skill_version: int
    project_id: UUID
    status: str
    matched_finding_ids: list[UUID]
    result_summary: dict[str, object]
    requested_by: str
    started_at: datetime
    finished_at: datetime
