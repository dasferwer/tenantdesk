import hashlib
import json
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text

from .auth import User, current_user
from .auth import router as auth_router
from .db import engine
from .observability import instrument
from .service import audit, create_document, get_document, mutate_document, usage
from .tenancy import TenantContext, lock_tenant, set_context, tenant_context


@asynccontextmanager
async def lifespan(app):
    async with engine.connect() as conn:
        role = (
            await conn.execute(
                text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
        ).one()
        owner = await conn.scalar(
            text(
                "SELECT tableowner=current_user FROM pg_tables WHERE tablename='documents' AND schemaname='public'"
            )
        )
        if role.rolsuper or role.rolbypassrls or owner:
            raise RuntimeError("API must use a non-owner role without SUPERUSER or BYPASSRLS")
    yield
    await engine.dispose()


app = FastAPI(
    title="TenantDesk",
    version="0.1.0",
    lifespan=lifespan,
    description="Organizations, document revisions, quotas and exports protected by PostgreSQL RLS. Supply X-Tenant-ID for organization operations.",
)
app.include_router(auth_router)
instrument(app)
Context = Annotated[TenantContext, Depends(tenant_context, scope="function")]


async def expected_version(
    if_match: Annotated[
        str,
        Header(
            alias="If-Match",
            pattern=r'^(?:[1-9][0-9]*|"[1-9][0-9]*")$',
            description='Document ETag, e.g. "1"',
        ),
    ],
) -> int:
    return int(if_match.strip('"'))


Version = Annotated[int, Depends(expected_version)]


class TenantInput(BaseModel):
    name: str = Field(min_length=1, max_length=120, pattern=r"\S")


class InvitationInput(BaseModel):
    email: EmailStr
    role: Literal["editor", "viewer"] = "viewer"
    ttl_seconds: int = Field(default=86400, ge=60, le=604800)


class InvitationAccept(BaseModel):
    tenant_id: UUID
    token: str = Field(min_length=20, max_length=200)


class DocumentInput(BaseModel):
    title: str = Field(min_length=1, max_length=200, pattern=r"\S")
    body: str = Field(default="", max_length=100000)


@app.get("/health", tags=["Operations"])
async def health():
    async with engine.connect() as conn:
        role = (
            (
                await conn.execute(
                    text(
                        "SELECT current_user AS name,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user"
                    )
                )
            )
            .mappings()
            .one()
        )
        age = await conn.scalar(
            text(
                "SELECT extract(epoch FROM clock_timestamp()-seen_at) FROM worker_heartbeats WHERE name='exporter'"
            )
        )
    return {
        "status": "ok",
        "database_role": role["name"],
        "rls_enforced": not role["rolsuper"] and not role["rolbypassrls"],
        "exporter_age_seconds": float(age) if age is not None else None,
    }


@app.post("/tenants", status_code=201, tags=["Organizations"])
async def create_tenant(data: TenantInput, user: User = Depends(current_user)):
    tenant_id = uuid4()
    async with engine.begin() as conn:
        await set_context(conn, tenant_id, user.id)
        await conn.execute(text("SELECT id FROM users WHERE id=:id FOR UPDATE"), {"id": user.id})
        owned = await conn.scalar(
            text("SELECT count(*) FROM memberships WHERE user_id=:user AND role='owner'"),
            {"user": user.id},
        )
        if owned >= 10:
            raise HTTPException(409, "Organization limit exceeded (10 per owner)")
        row = (
            (
                await conn.execute(
                    text(
                        "INSERT INTO tenants(id,name,created_by) VALUES (:id,:name,:actor) RETURNING *"
                    ),
                    {"id": tenant_id, "name": data.name, "actor": user.id},
                )
            )
            .mappings()
            .one()
        )
        await conn.execute(
            text("INSERT INTO memberships(tenant_id,user_id,role) VALUES (:tenant,:user,'owner')"),
            {"tenant": tenant_id, "user": user.id},
        )
        await audit(conn, tenant_id, user.id, "organization.created", tenant_id)
        return dict(row)


@app.get("/tenants", tags=["Organizations"])
async def tenants(user: User = Depends(current_user)):
    async with engine.begin() as conn:
        await set_context(conn, actor_id=user.id)
        return [
            dict(r)
            for r in (
                await conn.execute(
                    text(
                        "SELECT t.id,t.name,m.role FROM tenants t JOIN memberships m ON m.tenant_id=t.id WHERE m.user_id=:user ORDER BY t.created_at"
                    ),
                    {"user": user.id},
                )
            ).mappings()
        ]


@app.get("/organization", tags=["Organizations"])
async def organization(ctx: Context):
    row = (
        (await ctx.conn.execute(text("SELECT * FROM tenants WHERE id=:id"), {"id": ctx.tenant_id}))
        .mappings()
        .one()
    )
    return {**dict(row), "usage": await usage(ctx.conn), "role": ctx.role}


@app.get("/members", tags=["Membership"])
async def members(ctx: Context):
    return [
        dict(r)
        for r in (
            await ctx.conn.execute(
                text(
                    "SELECT m.user_id,u.email,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=:tenant ORDER BY m.created_at"
                ),
                {"tenant": ctx.tenant_id},
            )
        ).mappings()
    ]


@app.delete("/members/{user_id}", status_code=204, tags=["Membership"])
async def revoke_member(user_id: UUID, ctx: Context):
    ctx.require("owner")
    await lock_tenant(ctx)
    role = await ctx.conn.scalar(
        text("SELECT role FROM memberships WHERE tenant_id=:tenant AND user_id=:user"),
        {"tenant": ctx.tenant_id, "user": user_id},
    )
    if role is None:
        raise HTTPException(404, "Member not found")
    if role == "owner":
        raise HTTPException(409, "Organization owner cannot be removed")
    await ctx.conn.execute(
        text("DELETE FROM memberships WHERE tenant_id=:tenant AND user_id=:user"),
        {"tenant": ctx.tenant_id, "user": user_id},
    )
    await audit(ctx.conn, ctx.tenant_id, ctx.user.id, "member.revoked", user_id)


@app.post("/invitations", status_code=201, tags=["Membership"])
async def invite(data: InvitationInput, ctx: Context):
    ctx.require("owner")
    tenant = await lock_tenant(ctx)
    members = await ctx.conn.scalar(
        text("SELECT count(*) FROM memberships WHERE tenant_id=:tenant"), {"tenant": ctx.tenant_id}
    )
    if members >= tenant["max_members"]:
        raise HTTPException(409, "Member quota exceeded")
    token = secrets.token_urlsafe(32)
    now = await ctx.conn.scalar(text("SELECT clock_timestamp()"))
    row = (
        (
            await ctx.conn.execute(
                text("""INSERT INTO invitations(id,tenant_id,email,role,token_hash,expires_at)
        VALUES (:id,:tenant,:email,:role,:hash,:expires) RETURNING id,email,role,expires_at"""),
                {
                    "id": uuid4(),
                    "tenant": ctx.tenant_id,
                    "email": str(data.email).lower(),
                    "role": data.role,
                    "hash": hashlib.sha256(token.encode()).hexdigest(),
                    "expires": now + timedelta(seconds=data.ttl_seconds),
                },
            )
        )
        .mappings()
        .one()
    )
    await audit(
        ctx.conn, ctx.tenant_id, ctx.user.id, "invitation.created", row["id"], {"role": data.role}
    )
    return {**dict(row), "tenant_id": ctx.tenant_id, "token": token}


@app.post("/invitations/accept", tags=["Membership"])
async def accept(data: InvitationAccept, user: User = Depends(current_user)):
    async with engine.begin() as conn:
        await set_context(conn, data.tenant_id, user.id)
        # Как и в остальных операциях, сначала блокируем компанию, затем её записи.
        tenant = (
            (
                await conn.execute(
                    text("SELECT * FROM tenants WHERE id=:id FOR UPDATE"), {"id": data.tenant_id}
                )
            )
            .mappings()
            .first()
        )
        invitation = (
            (
                await conn.execute(
                    text(
                        "SELECT * FROM invitations WHERE token_hash=:hash AND tenant_id=:tenant FOR UPDATE"
                    ),
                    {
                        "hash": hashlib.sha256(data.token.encode()).hexdigest(),
                        "tenant": data.tenant_id,
                    },
                )
            )
            .mappings()
            .first()
        )
        if tenant is None or invitation is None or invitation["email"] != user.email:
            raise HTTPException(404, "Invitation not found")
        if invitation["used_by"] is not None:
            raise HTTPException(409, "Invitation already used")
        now = await conn.scalar(text("SELECT clock_timestamp()"))
        if invitation["expires_at"] <= now:
            raise HTTPException(410, "Invitation expired")
        existing = await conn.scalar(
            text("SELECT role FROM memberships WHERE tenant_id=:tenant AND user_id=:user"),
            {"tenant": data.tenant_id, "user": user.id},
        )
        if existing:
            raise HTTPException(409, "Already a member")
        count = await conn.scalar(
            text("SELECT count(*) FROM memberships WHERE tenant_id=:tenant"),
            {"tenant": data.tenant_id},
        )
        if count >= tenant["max_members"]:
            raise HTTPException(409, "Member quota exceeded")
        await conn.execute(
            text("INSERT INTO memberships(tenant_id,user_id,role) VALUES (:tenant,:user,:role)"),
            {"tenant": data.tenant_id, "user": user.id, "role": invitation["role"]},
        )
        await conn.execute(
            text("UPDATE invitations SET used_by=:user WHERE id=:id"),
            {"user": user.id, "id": invitation["id"]},
        )
        await audit(conn, data.tenant_id, user.id, "invitation.accepted", invitation["id"])
        return {"tenant_id": data.tenant_id, "role": invitation["role"]}


@app.post("/documents", status_code=201, tags=["Documents"])
async def create(data: DocumentInput, ctx: Context):
    return await create_document(ctx, data.title, data.body)


@app.get("/documents", tags=["Documents"])
async def documents(
    ctx: Context,
    deleted: bool = False,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    return [
        dict(r)
        for r in (
            await ctx.conn.execute(
                text("""SELECT id,title,version,deleted_at,updated_at FROM documents
        WHERE (deleted_at IS NOT NULL)=:deleted ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset"""),
                {"deleted": deleted, "limit": limit, "offset": offset},
            )
        ).mappings()
    ]


@app.get("/documents/{document_id}", tags=["Documents"])
async def document(document_id: UUID, ctx: Context, response: Response):
    row = await get_document(ctx, document_id)
    response.headers["ETag"] = f'"{row["version"]}"'
    return dict(row)


@app.put("/documents/{document_id}", tags=["Documents"])
async def edit(document_id: UUID, data: DocumentInput, ctx: Context, if_match: Version):
    return await mutate_document(ctx, document_id, if_match, "edit", data.title, data.body)


@app.delete("/documents/{document_id}", tags=["Documents"])
async def delete(document_id: UUID, ctx: Context, if_match: Version):
    return await mutate_document(ctx, document_id, if_match, "delete")


@app.post("/documents/{document_id}/restore", tags=["Documents"])
async def restore(document_id: UUID, ctx: Context, if_match: Version):
    return await mutate_document(ctx, document_id, if_match, "restore")


@app.get("/documents/{document_id}/revisions", tags=["Documents"])
async def revisions(
    document_id: UUID,
    ctx: Context,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    await get_document(ctx, document_id)
    return [
        dict(r)
        for r in (
            await ctx.conn.execute(
                text(
                    "SELECT version,title,body,storage_bytes,created_at FROM revisions WHERE document_id=:id ORDER BY version DESC LIMIT :limit OFFSET :offset"
                ),
                {"id": document_id, "limit": limit, "offset": offset},
            )
        ).mappings()
    ]


@app.get("/audit", tags=["Audit"])
async def audit_list(
    ctx: Context, limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0)
):
    ctx.require("owner")
    return [
        dict(r)
        for r in (
            await ctx.conn.execute(
                text(
                    "SELECT * FROM audit_log ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset"
                ),
                {"limit": limit, "offset": offset},
            )
        ).mappings()
    ]


@app.post("/exports", status_code=202, tags=["Exports"])
async def export(
    ctx: Context,
    idempotency_key: Annotated[
        str, Header(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    ],
):
    await lock_tenant(ctx)
    previous = (
        (
            await ctx.conn.execute(
                text(
                    "SELECT id,status FROM export_jobs WHERE actor_id=:actor AND idempotency_key=:key"
                ),
                {"actor": ctx.user.id, "key": idempotency_key},
            )
        )
        .mappings()
        .first()
    )
    if previous:
        return dict(previous)
    count = await ctx.conn.scalar(text("SELECT count(*) FROM export_jobs"))
    if count >= 20:
        raise HTTPException(409, "Export quota exceeded; delete old exports")
    job_id = uuid4()
    await ctx.conn.execute(
        text(
            "INSERT INTO export_jobs(id,tenant_id,actor_id,idempotency_key) VALUES (:id,:tenant,:actor,:key)"
        ),
        {"id": job_id, "tenant": ctx.tenant_id, "actor": ctx.user.id, "key": idempotency_key},
    )
    await ctx.conn.execute(
        text("INSERT INTO export_outbox(job_id,tenant_id) VALUES (:id,:tenant)"),
        {"id": job_id, "tenant": ctx.tenant_id},
    )
    await audit(ctx.conn, ctx.tenant_id, ctx.user.id, "export.requested", job_id)
    return {"id": job_id, "status": "queued"}


async def owned_export(ctx, job_id):
    row = (
        (await ctx.conn.execute(text("SELECT * FROM export_jobs WHERE id=:id"), {"id": job_id}))
        .mappings()
        .first()
    )
    if row is None or (row["actor_id"] != ctx.user.id and ctx.role != "owner"):
        raise HTTPException(404, "Export not found")
    return row


@app.get("/exports/{job_id}", tags=["Exports"])
async def export_status(job_id: UUID, ctx: Context):
    row = await owned_export(ctx, job_id)
    return {k: row[k] for k in ("id", "status", "error", "created_at", "finished_at")}


@app.get("/exports/{job_id}/download", tags=["Exports"])
async def download(job_id: UUID, ctx: Context):
    row = await owned_export(ctx, job_id)
    if row["status"] != "done":
        raise HTTPException(409, "Export is not ready")
    return Response(
        json.dumps(row["result"], ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="documents-{job_id}.json"'},
    )


@app.delete("/exports/{job_id}", status_code=204, tags=["Exports"])
async def delete_export(job_id: UUID, ctx: Context):
    await lock_tenant(ctx)
    await owned_export(ctx, job_id)
    await ctx.conn.execute(text("DELETE FROM export_jobs WHERE id=:id"), {"id": job_id})
    await audit(ctx.conn, ctx.tenant_id, ctx.user.id, "export.deleted", job_id)
