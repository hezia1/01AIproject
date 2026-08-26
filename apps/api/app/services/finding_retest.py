from collections import defaultdict
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import FindingRecord, ScanTaskRecord
from app.models import FindingRetestComparison, FindingRetestItem, ScanStatus, Severity


SOURCE_SCAN_TYPES = {"SCA": "sca", "SAST": "sast", "AGENT": "agent"}


def current_finding_records(
    db: Session,
    project_id: UUID,
    records: list[FindingRecord] | None = None,
) -> list[FindingRecord]:
    all_records = records if records is not None else list(
        db.scalars(
            select(FindingRecord)
            .where(FindingRecord.project_id == str(project_id))
            .order_by(FindingRecord.created_at.desc())
        ).all()
    )
    latest_scan_ids = {
        source: latest_scan.id
        for source, scan_type in SOURCE_SCAN_TYPES.items()
        if (latest_scan := latest_completed_scan(db, project_id, scan_type)) is not None
    }
    return [
        record
        for record in all_records
        if record.source not in SOURCE_SCAN_TYPES
        or record.scan_task_id is None
        or str(record.scan_task_id) == str(latest_scan_ids.get(record.source))
    ]


def build_finding_retest_comparison(
    db: Session,
    project_id: UUID,
    source: str,
) -> FindingRetestComparison:
    normalized_source = source.upper()
    scan_type = SOURCE_SCAN_TYPES.get(normalized_source)
    if scan_type is None:
        raise ValueError("source must be one of SCA, SAST, or AGENT")

    scans = list(
        db.scalars(
            select(ScanTaskRecord)
            .where(
                ScanTaskRecord.project_id == str(project_id),
                ScanTaskRecord.scan_type == scan_type,
                ScanTaskRecord.status == ScanStatus.completed.value,
            )
            .order_by(
                ScanTaskRecord.finished_at.desc().nullslast(),
                ScanTaskRecord.created_at.desc(),
            )
        ).all()
    )
    if len(scans) < 2:
        current = scans[0] if scans else None
        return FindingRetestComparison(
            project_id=project_id,
            source=normalized_source,
            current_scan_id=UUID(str(current.id)) if current else None,
            current_scan_at=(current.finished_at or current.created_at) if current else None,
        )

    current_scan, previous_scan = scans[0], scans[1]
    current_records = findings_for_scan(db, project_id, normalized_source, current_scan.id)
    previous_records = findings_for_scan(db, project_id, normalized_source, previous_scan.id)
    items = compare_finding_records(previous_records, current_records)
    return FindingRetestComparison(
        project_id=project_id,
        source=normalized_source,
        has_comparison=True,
        previous_scan_id=UUID(str(previous_scan.id)),
        current_scan_id=UUID(str(current_scan.id)),
        previous_scan_at=previous_scan.finished_at or previous_scan.created_at,
        current_scan_at=current_scan.finished_at or current_scan.created_at,
        still_present_count=sum(item.result == "still_present" for item in items),
        resolved_count=sum(item.result == "resolved" for item in items),
        new_count=sum(item.result == "new" for item in items),
        changed_count=sum(item.result == "changed" for item in items),
        items=items,
    )


def compare_finding_records(
    previous_records: list[FindingRecord],
    current_records: list[FindingRecord],
) -> list[FindingRetestItem]:
    previous: dict[str, list[FindingRecord]] = defaultdict(list)
    current: dict[str, list[FindingRecord]] = defaultdict(list)
    for record in previous_records:
        previous[finding_identity(record)].append(record)
    for record in current_records:
        current[finding_identity(record)].append(record)

    items: list[FindingRetestItem] = []
    for base_identity in sorted(previous.keys() | current.keys()):
        pairs = pair_finding_occurrences(previous.get(base_identity, []), current.get(base_identity, []))
        for index, (old, new) in enumerate(pairs):
            if old and new:
                result = "changed" if finding_changed(old, new) else "still_present"
            elif old:
                result = "resolved"
            else:
                result = "new"
            record = new or old
            items.append(
                FindingRetestItem(
                    identity=f"{base_identity}|{old.id if old else '-'}|{new.id if new else '-'}|{index}",
                    result=result,
                    title=record.title,
                    file_path=record.file_path,
                    previous_line_start=old.line_start if old else None,
                    current_line_start=new.line_start if new else None,
                    previous_severity=severity(old.severity) if old else None,
                    current_severity=severity(new.severity) if new else None,
                    previous_finding_id=UUID(str(old.id)) if old else None,
                    current_finding_id=UUID(str(new.id)) if new else None,
                )
            )
    return sorted(items, key=retest_rank)


def pair_finding_occurrences(
    previous: list[FindingRecord],
    current: list[FindingRecord],
) -> list[tuple[FindingRecord | None, FindingRecord | None]]:
    """Match repeated findings one-to-one without collapsing occurrences in the same file."""
    old_remaining = sorted(previous, key=finding_occurrence_sort_key)
    new_remaining = sorted(current, key=finding_occurrence_sort_key)
    pairs: list[tuple[FindingRecord | None, FindingRecord | None]] = []

    # Exact locations are the strongest match. Pair these first so an inserted line does not
    # make every later occurrence look changed.
    unmatched_old: list[FindingRecord] = []
    for old in old_remaining:
        location = finding_location(old)
        match_index = next((index for index, new in enumerate(new_remaining) if finding_location(new) == location), None)
        if match_index is None:
            unmatched_old.append(old)
        else:
            pairs.append((old, new_remaining.pop(match_index)))

    # Remaining records share the same rule/title/file identity. Pair them deterministically
    # as moved/changed occurrences, then retain any cardinality difference as resolved/new.
    pair_count = min(len(unmatched_old), len(new_remaining))
    pairs.extend(zip(unmatched_old[:pair_count], new_remaining[:pair_count]))
    pairs.extend((old, None) for old in unmatched_old[pair_count:])
    pairs.extend((None, new) for new in new_remaining[pair_count:])
    return pairs


def latest_completed_scan(
    db: Session,
    project_id: UUID,
    scan_type: str,
) -> ScanTaskRecord | None:
    return db.scalar(
        select(ScanTaskRecord)
        .where(
            ScanTaskRecord.project_id == str(project_id),
            ScanTaskRecord.scan_type == scan_type,
            ScanTaskRecord.status == ScanStatus.completed.value,
        )
        .order_by(
            ScanTaskRecord.finished_at.desc().nullslast(),
            ScanTaskRecord.created_at.desc(),
        )
    )


def findings_for_scan(
    db: Session,
    project_id: UUID,
    source: str,
    scan_id: str,
) -> list[FindingRecord]:
    return list(
        db.scalars(
            select(FindingRecord).where(
                FindingRecord.project_id == str(project_id),
                FindingRecord.source == source,
                FindingRecord.scan_task_id == str(scan_id),
            )
        ).all()
    )


def finding_identity(record: FindingRecord) -> str:
    path = (record.file_path or "").replace("\\", "/").lower()
    return "|".join((record.source.upper(), record.rule_id.lower(), path, record.title.lower()))


def finding_location(record: FindingRecord) -> tuple[int | None, int | None]:
    return record.line_start, record.line_end


def finding_occurrence_sort_key(record: FindingRecord) -> tuple[int, int, str]:
    return record.line_start or -1, record.line_end or -1, str(record.id)


def finding_changed(old: FindingRecord, new: FindingRecord) -> bool:
    return (
        old.severity != new.severity
        or old.line_start != new.line_start
        or old.line_end != new.line_end
    )


def severity(value: str) -> Severity | None:
    try:
        return Severity(value)
    except ValueError:
        return None


def retest_rank(item: FindingRetestItem) -> tuple[int, str]:
    order = {"still_present": 4, "changed": 3, "new": 2, "resolved": 1}
    return -order[item.result], item.title.lower()
