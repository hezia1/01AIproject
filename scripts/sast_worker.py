"""Run queued SAST jobs from the local PostgreSQL task table.

Start one or more workers explicitly; no service starts this worker implicitly.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import func, select


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.db import SessionLocal  # noqa: E402
from app.db_models import ScanTaskRecord  # noqa: E402
from app.models import ScanStatus  # noqa: E402
from app.routers.sast import execute_queued_sast_job  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Process queued local SAST jobs")
    parser.add_argument("--once", action="store_true", help="Process at most one job and exit")
    parser.add_argument("--max-jobs", type=int, default=0, help="Process no more than this many jobs (0 means unlimited)")
    parser.add_argument("--concurrency", type=int, default=int(os.getenv("AI_SECURITY_SAST_WORKER_CONCURRENCY", "1")), help="Maximum simultaneously running SAST jobs")
    parser.add_argument("--poll-seconds", type=float, default=float(os.getenv("AI_SECURITY_SAST_WORKER_POLL_SECONDS", "3")), help="Idle polling interval for the long-running worker")
    args = parser.parse_args()
    if args.poll_seconds <= 0 or args.poll_seconds > 60:
        parser.error("--poll-seconds must be greater than 0 and at most 60")
    processed = 0
    while not args.max_jobs or processed < args.max_jobs:
        with SessionLocal() as db:
            running = db.scalar(select(func.count()).select_from(ScanTaskRecord).where(ScanTaskRecord.scan_type == "sast_job", ScanTaskRecord.status == ScanStatus.running.value))
            if int(running or 0) >= max(1, args.concurrency):
                if args.once:
                    return 0
                time.sleep(args.poll_seconds)
                continue
            job = db.scalar(select(ScanTaskRecord).where(ScanTaskRecord.scan_type == "sast_job", ScanTaskRecord.status == ScanStatus.queued.value).order_by(ScanTaskRecord.created_at.asc()).with_for_update(skip_locked=True).limit(1))
            if job is None:
                if args.once:
                    return 0
                time.sleep(args.poll_seconds)
                continue
            request = SimpleNamespace(state=SimpleNamespace(identity=None))
            try:
                execute_queued_sast_job(db, job, request)
            except Exception as exc:  # failure is persisted by the executor
                print(f"SAST job {job.id} failed: {exc}", file=sys.stderr)
        processed += 1
        if args.once:
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
