import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import jwt
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from tenantdesk.config import settings
from tenantdesk.db import engine
from tenantdesk.main import app

assert settings.testing and settings.database_url.endswith("_test"), (
    "Tests require an isolated *_test database"
)
admin_engine = create_async_engine(os.environ["MIGRATION_DATABASE_URL"], poolclass=NullPool)


@pytest.fixture(autouse=True)
async def clean():
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE users,tenants,memberships,invitations,documents,revisions,audit_log,export_jobs,export_outbox,worker_heartbeats CASCADE"
            )
        )
    yield


@pytest.fixture
async def client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest.fixture
async def identities():
    users = {}
    async with admin_engine.begin() as conn:
        for name in ("alice", "bob", "carol", "dave"):
            uid = uuid4()
            await conn.execute(
                text("INSERT INTO users(id,email,password_hash) VALUES (:id,:email,:hash)"),
                {"id": uid, "email": f"{name}@example.com", "hash": "unused"},
            )
            now = datetime.now(UTC)
            token = jwt.encode(
                {
                    "sub": str(uid),
                    "iat": now,
                    "exp": now + timedelta(hours=1),
                    "iss": "tenantdesk",
                    "aud": "tenantdesk",
                },
                settings.jwt_secret,
                algorithm="HS256",
            )
            users[name] = {
                "id": uid,
                "headers": {"Authorization": f"Bearer {token}"},
                "email": f"{name}@example.com",
            }
    return users


@pytest.fixture
async def organizations(client, identities):
    tenants = {}
    for user in ("alice", "bob"):
        response = await client.post(
            "/tenants", json={"name": user + " organization"}, headers=identities[user]["headers"]
        )
        assert response.status_code == 201, response.text
        tenants[user] = response.json()
    return tenants


@pytest.fixture(scope="session", autouse=True)
async def dispose_pool():
    yield
    await engine.dispose()
