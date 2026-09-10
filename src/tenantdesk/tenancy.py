from dataclasses import dataclass
from uuid import UUID

from fastapi import Depends, Header, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from .auth import User, current_user
from .db import engine


async def set_context(conn, tenant_id=None, actor_id=None):
    # SET LOCAL сбросится при commit или rollback, прежде чем соединение вернётся в пул.
    await conn.execute(
        text(
            "SELECT set_config('app.tenant_id',:tenant,true),set_config('app.actor_id',:actor,true)"
        ),
        {"tenant": str(tenant_id) if tenant_id else "", "actor": str(actor_id) if actor_id else ""},
    )


@dataclass
class TenantContext:
    conn: AsyncConnection
    tenant_id: UUID
    user: User
    role: str

    def require(self, *roles):
        if self.role not in roles:
            raise HTTPException(403, "Insufficient organization role")


async def tenant_context(x_tenant_id: UUID = Header(), user: User = Depends(current_user)):
    async with engine.begin() as conn:
        await set_context(conn, x_tenant_id, user.id)
        role = await conn.scalar(
            text("SELECT role FROM memberships WHERE tenant_id=:tenant AND user_id=:user"),
            {"tenant": x_tenant_id, "user": user.id},
        )
        if role is None:
            raise HTTPException(403, "Not a member of this organization")
        yield TenantContext(conn, x_tenant_id, user, role)


async def lock_tenant(context):
    row = (
        (
            await context.conn.execute(
                text("SELECT * FROM tenants WHERE id=:id FOR UPDATE"), {"id": context.tenant_id}
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(404, "Organization not found")
    current_role = await context.conn.scalar(
        text("SELECT role FROM memberships WHERE tenant_id=:tenant AND user_id=:user"),
        {"tenant": context.tenant_id, "user": context.user.id},
    )
    if current_role != context.role:
        raise HTTPException(403, "Membership changed; retry the request")
    return row
