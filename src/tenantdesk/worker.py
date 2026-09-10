import asyncio
import json
import logging
import signal
from contextlib import suppress

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from .config import settings
from .service import audit
from .tenancy import set_context

worker_engine = create_async_engine(settings.worker_database_url, poolclass=NullPool)
logger = logging.getLogger("exporter")


async def process_job(candidate):
    async with worker_engine.begin() as conn:
        await set_context(conn, candidate["tenant_id"])
        # Same order as API mutations prevents a job-delete vs. worker deadlock.
        tenant = await conn.scalar(
            text("SELECT id FROM tenants WHERE id=:id FOR UPDATE SKIP LOCKED"),
            {"id": candidate["tenant_id"]},
        )
        if tenant is None:
            return False
        queued = await conn.scalar(
            text("SELECT job_id FROM export_outbox WHERE job_id=:id FOR UPDATE SKIP LOCKED"),
            {"id": candidate["job_id"]},
        )
        if queued is None:
            return False
        job = (
            (
                await conn.execute(
                    text("SELECT * FROM export_jobs WHERE id=:id FOR UPDATE"),
                    {"id": candidate["job_id"]},
                )
            )
            .mappings()
            .one()
        )
        allowed = await conn.scalar(
            text("SELECT role FROM memberships WHERE tenant_id=:tenant AND user_id=:actor"),
            {"tenant": job["tenant_id"], "actor": job["actor_id"]},
        )
        now = await conn.scalar(text("SELECT clock_timestamp()"))
        result = None
        error = None
        if not allowed:
            error = "membership_revoked"
        else:
            # No WHERE tenant_id: the worker's database role is subject to the same RLS.
            docs = [
                dict(r)
                for r in (
                    await conn.execute(
                        text(
                            "SELECT id,title,body,version FROM documents WHERE deleted_at IS NULL ORDER BY id"
                        )
                    )
                ).mappings()
            ]
            result = {
                "tenant_id": str(job["tenant_id"]),
                "snapshot_at": now.isoformat(),
                "documents": docs,
            }
            if len(json.dumps(result, default=str, ensure_ascii=False).encode()) > 2_097_152:
                result = None
                error = "export_exceeds_2_mib"
        status = "rejected" if error else "done"
        await conn.execute(
            text(
                "UPDATE export_jobs SET status=:status,result=CAST(:result AS jsonb),error=:error,finished_at=:now WHERE id=:id"
            ),
            {
                "status": status,
                "result": json.dumps(result, default=str, ensure_ascii=False),
                "error": error,
                "now": now,
                "id": job["id"],
            },
        )
        await audit(conn, job["tenant_id"], job["actor_id"], "export." + status, job["id"])
        await conn.execute(text("DELETE FROM export_outbox WHERE job_id=:id"), {"id": job["id"]})
        return True


async def run_batch():
    async with worker_engine.connect() as conn:
        candidates = (
            (
                await conn.execute(
                    text(
                        "SELECT job_id,tenant_id FROM export_outbox ORDER BY created_at,job_id LIMIT 20"
                    )
                )
            )
            .mappings()
            .all()
        )
    processed = 0
    for candidate in candidates:
        processed += await process_job(candidate)
    async with worker_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO worker_heartbeats(name) VALUES ('exporter') ON CONFLICT(name) DO UPDATE SET seen_at=clock_timestamp()"
            )
        )
    return processed


async def main():
    logging.basicConfig(level=logging.INFO)
    async with worker_engine.connect() as conn:
        role = (
            await conn.execute(
                text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
        ).one()
        if role.rolsuper or role.rolbypassrls:
            raise RuntimeError("Exporter requires a role without RLS bypass")
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, stop.set)
    try:
        while not stop.is_set():
            try:
                count = await run_batch()
                if count:
                    logger.info("exports_processed=%s", count)
            except Exception:
                logger.exception("export transaction rolled back; durable outbox permits retry")
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=settings.worker_interval)
    finally:
        await worker_engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
