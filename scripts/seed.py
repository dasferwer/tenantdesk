import asyncio
from uuid import UUID

from sqlalchemy import text

from tenantdesk.auth import User, hasher
from tenantdesk.db import engine
from tenantdesk.service import audit, create_document
from tenantdesk.tenancy import TenantContext, set_context

TENANT = UUID("12000000-0000-0000-0000-000000000010")
USER = UUID("12000000-0000-0000-0000-000000000001")


async def seed():
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO users(id,email,password_hash) VALUES (:id,'owner@example.com',:hash) ON CONFLICT(email) DO NOTHING"
            ),
            {"id": USER, "hash": hasher.hash("TenantDeskDemo123!")},
        )
        user = (
            (
                await conn.execute(
                    text("SELECT id,email,role FROM users WHERE email='owner@example.com'")
                )
            )
            .mappings()
            .one()
        )
        await set_context(conn, TENANT, user["id"])
        created = await conn.scalar(
            text(
                "INSERT INTO tenants(id,name,created_by) VALUES (:id,'Demo organization',:user) ON CONFLICT(id) DO NOTHING RETURNING id"
            ),
            {"id": TENANT, "user": user["id"]},
        )
        if created:
            await conn.execute(
                text(
                    "INSERT INTO memberships(tenant_id,user_id,role) VALUES (:tenant,:user,'owner')"
                ),
                {"tenant": TENANT, "user": user["id"]},
            )
            await audit(conn, TENANT, user["id"], "organization.created", TENANT)
            await create_document(
                TenantContext(conn, TENANT, User(**user), "owner"),
                "Welcome",
                "TenantDesk stores revisions and isolates organization data with PostgreSQL RLS.",
            )
    await engine.dispose()
    print(f"Seed ready: owner@example.com / TenantDeskDemo123!; tenant={TENANT}")


if __name__ == "__main__":
    asyncio.run(seed())
