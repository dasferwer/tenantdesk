import asyncio
from uuid import UUID, uuid4

import pytest
from conftest import admin_engine
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine

from tenantdesk.config import settings
from tenantdesk.db import engine
from tenantdesk.tenancy import set_context
from tenantdesk.worker import run_batch, worker_engine


def headers(identities, organizations, user="alice", tenant=None, version=None, key=None):
    result = {**identities[user]["headers"], "X-Tenant-ID": organizations[tenant or user]["id"]}
    if version is not None:
        result["If-Match"] = str(version)
    if key is not None:
        result["Idempotency-Key"] = key
    return result


async def document(client, h, title="Alpha", body="Secret alpha data"):
    response = await client.post("/documents", json={"title": title, "body": body}, headers=h)
    assert response.status_code == 201, response.text
    return response.json()


async def invite_member(client, identities, organizations, name="carol", role="viewer"):
    invitation = (
        await client.post(
            "/invitations",
            json={"email": identities[name]["email"], "role": role},
            headers=headers(identities, organizations),
        )
    ).json()
    response = await client.post(
        "/invitations/accept",
        json={"tenant_id": organizations["alice"]["id"], "token": invitation["token"]},
        headers=identities[name]["headers"],
    )
    assert response.status_code == 200, response.text
    return {**identities[name]["headers"], "X-Tenant-ID": organizations["alice"]["id"]}


async def quota(organizations, **changes):
    async with admin_engine.begin() as conn:
        for column, value in changes.items():
            assert column in ("max_documents", "max_storage_bytes", "max_members")
            await conn.execute(
                text(f"UPDATE tenants SET {column}=:value WHERE id=:id"),
                {"value": value, "id": UUID(organizations["alice"]["id"])},
            )


async def test_organization_discovery_only_lists_memberships(client, identities, organizations):
    for user in ("alice", "bob"):
        listing = (await client.get("/tenants", headers=identities[user]["headers"])).json()
        assert [row["id"] for row in listing] == [organizations[user]["id"]]
    assert (await client.get("/tenants", headers=identities["carol"]["headers"])).json() == []


async def test_cross_tenant_requests_are_denied_for_all_document_paths(
    client, identities, organizations
):
    bob = await document(
        client, headers(identities, organizations, "bob"), "Beta", "Secret beta data"
    )
    alice_headers = headers(identities, organizations, version=1)
    assert (await client.get("/documents", headers=alice_headers)).json() == []
    for method, suffix, data in [
        ("GET", "", None),
        ("GET", "/revisions", None),
        ("PUT", "", {"title": "attack", "body": "bad"}),
        ("DELETE", "", None),
        ("POST", "/restore", None),
    ]:
        response = await client.request(
            method, f"/documents/{bob['id']}{suffix}", json=data, headers=alice_headers
        )
        assert response.status_code == 404, response.text
    forged = headers(identities, organizations, "alice", tenant="bob")
    assert (await client.get("/documents", headers=forged)).status_code == 403
    assert (await client.get("/documents")).status_code == 401


async def test_rls_filters_unscoped_sql_and_blocks_cross_tenant_insert(
    client, identities, organizations
):
    a = await document(client, headers(identities, organizations), "A", "data-A")
    b = await document(client, headers(identities, organizations, "bob"), "B", "data-B")
    async with engine.begin() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM documents")) == 0
        await set_context(conn, UUID(organizations["alice"]["id"]), identities["alice"]["id"])
        ids = (await conn.execute(text("SELECT id FROM documents"))).scalars().all()
        assert ids == [UUID(a["id"])]
        changed = await conn.execute(
            text("UPDATE documents SET title='bad' WHERE id=:id"), {"id": UUID(b["id"])}
        )
        assert changed.rowcount == 0
    with pytest.raises(DBAPIError):
        async with engine.begin() as conn:
            await set_context(conn, UUID(organizations["alice"]["id"]))
            await conn.execute(
                text(
                    "INSERT INTO documents(id,tenant_id,title,body,created_by) VALUES (:id,:tenant,'bad','bad',:user)"
                ),
                {
                    "id": uuid4(),
                    "tenant": UUID(organizations["bob"]["id"]),
                    "user": identities["alice"]["id"],
                },
            )


async def test_context_is_reset_on_real_connection_pool_reuse(client, identities, organizations):
    await document(client, headers(identities, organizations))
    pooled = create_async_engine(settings.database_url, pool_size=1, max_overflow=0)
    try:
        async with pooled.begin() as conn:
            pid = await conn.scalar(text("SELECT pg_backend_pid()"))
            await set_context(conn, UUID(organizations["alice"]["id"]), identities["alice"]["id"])
            assert await conn.scalar(text("SELECT count(*) FROM documents")) == 1
        async with pooled.begin() as conn:
            assert await conn.scalar(text("SELECT pg_backend_pid()")) == pid
            assert await conn.scalar(text("SELECT count(*) FROM documents")) == 0
        with pytest.raises(RuntimeError):
            async with pooled.begin() as conn:
                await set_context(conn, UUID(organizations["alice"]["id"]))
                raise RuntimeError("Simulated request failure")
        async with pooled.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM documents")) == 0
    finally:
        await pooled.dispose()


async def test_runtime_roles_cannot_bypass_rls_or_mutate_history(client, identities, organizations):
    await document(client, headers(identities, organizations))
    for active_engine in (engine, worker_engine):
        async with active_engine.connect() as conn:
            flags = (
                await conn.execute(
                    text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")
                )
            ).one()
            assert tuple(flags) == (False, False)
    async with engine.connect() as conn:
        flags = (
            await conn.execute(
                text(
                    "SELECT relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner)=current_user FROM pg_class WHERE relname='documents'"
                )
            )
        ).one()
        assert tuple(flags) == (True, True, False)
    for statement in (
        "UPDATE audit_log SET action='tampered'",
        "DELETE FROM revisions",
        "SELECT * FROM export_outbox",
    ):
        with pytest.raises(DBAPIError):
            async with engine.begin() as conn:
                await set_context(conn, UUID(organizations["alice"]["id"]))
                await conn.execute(text(statement))
    with pytest.raises(DBAPIError):
        async with worker_engine.connect() as conn:
            await conn.execute(text("SELECT * FROM users"))


async def test_viewer_can_read_but_cannot_write_or_invite(client, identities, organizations):
    doc = await document(client, headers(identities, organizations))
    viewer = await invite_member(client, identities, organizations)
    assert (await client.get("/documents", headers=viewer)).status_code == 200
    assert (
        await client.post("/documents", json={"title": "bad"}, headers=viewer)
    ).status_code == 403
    assert (
        await client.delete(f"/documents/{doc['id']}", headers={**viewer, "If-Match": "1"})
    ).status_code == 403
    assert (
        await client.post("/invitations", json={"email": "x@example.com"}, headers=viewer)
    ).status_code == 403
    assert (await client.get("/audit", headers=viewer)).status_code == 403


async def test_invitation_email_binding_single_use_and_expiration(
    client, identities, organizations
):
    own = headers(identities, organizations)
    inv = (
        await client.post(
            "/invitations", json={"email": "carol@example.com", "role": "editor"}, headers=own
        )
    ).json()
    data = {"tenant_id": organizations["alice"]["id"], "token": inv["token"]}
    assert (
        await client.post("/invitations/accept", json=data, headers=identities["dave"]["headers"])
    ).status_code == 404
    assert (
        await client.post("/invitations/accept", json=data, headers=identities["carol"]["headers"])
    ).status_code == 200
    assert (
        await client.post("/invitations/accept", json=data, headers=identities["carol"]["headers"])
    ).status_code == 409
    inv = (
        await client.post("/invitations", json={"email": "dave@example.com"}, headers=own)
    ).json()
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE invitations SET expires_at=clock_timestamp()-interval '1 second' WHERE id=:id"
            ),
            {"id": UUID(inv["id"])},
        )
    assert (
        await client.post(
            "/invitations/accept",
            json={"tenant_id": organizations["alice"]["id"], "token": inv["token"]},
            headers=identities["dave"]["headers"],
        )
    ).status_code == 410


async def test_concurrent_document_creation_obeys_quota(client, identities, organizations):
    await quota(organizations, max_documents=3)
    results = await asyncio.gather(
        *[
            client.post(
                "/documents", json={"title": f"Doc {i}"}, headers=headers(identities, organizations)
            )
            for i in range(30)
        ]
    )
    assert sum(r.status_code == 201 for r in results) == 3
    assert sum(r.status_code == 409 for r in results) == 27


async def test_storage_quota_counts_utf8_bytes_and_retained_revisions(
    client, identities, organizations
):
    await quota(organizations, max_storage_bytes=12)
    h = headers(identities, organizations)
    doc = await document(client, h, "A", "тест")  # 1 + 8 UTF-8 bytes
    response = await client.put(
        f"/documents/{doc['id']}", json={"title": "B", "body": "x"}, headers={**h, "If-Match": "1"}
    )
    assert response.status_code == 200
    response = await client.put(
        f"/documents/{doc['id']}", json={"title": "C", "body": "x"}, headers={**h, "If-Match": "2"}
    )
    assert response.status_code == 409
    usage = (await client.get("/organization", headers=h)).json()["usage"]
    assert usage["storage_bytes"] == 11


async def test_optimistic_versions_prevent_lost_updates(client, identities, organizations):
    h = headers(identities, organizations)
    doc = await document(client, h)
    results = await asyncio.gather(
        *[
            client.put(
                f"/documents/{doc['id']}",
                json={"title": name, "body": name},
                headers={**h, "If-Match": "1"},
            )
            for name in ("first", "second")
        ]
    )
    assert sorted(r.status_code for r in results) == [200, 409]
    revisions = (await client.get(f"/documents/{doc['id']}/revisions", headers=h)).json()
    assert [r["version"] for r in revisions] == [2, 1]


async def test_delete_restore_preserve_content_and_audit(client, identities, organizations):
    h = headers(identities, organizations)
    doc = await document(client, h)
    deleted = await client.delete(f"/documents/{doc['id']}", headers={**h, "If-Match": "1"})
    assert deleted.status_code == 200 and deleted.json()["version"] == 2
    assert (await client.get("/documents", headers=h)).json() == []
    assert len((await client.get("/documents?deleted=true", headers=h)).json()) == 1
    restored = await client.post(f"/documents/{doc['id']}/restore", headers={**h, "If-Match": "2"})
    assert restored.status_code == 200 and restored.json()["body"] == doc["body"]
    assert restored.json()["version"] == 3 and restored.json()["deleted_at"] is None
    actions = {row["action"] for row in (await client.get("/audit", headers=h)).json()}
    assert {"document.created", "document.delete", "document.restore"} <= actions


async def test_restore_checks_active_document_quota(client, identities, organizations):
    await quota(organizations, max_documents=1)
    h = headers(identities, organizations)
    first = await document(client, h)
    await client.delete(f"/documents/{first['id']}", headers={**h, "If-Match": "1"})
    await document(client, h, "Second", "Second body")
    assert (
        await client.post(f"/documents/{first['id']}/restore", headers={**h, "If-Match": "2"})
    ).status_code == 409


async def test_exports_are_rls_isolated_for_real_worker_role(client, identities, organizations):
    a = await document(client, headers(identities, organizations), "A", "ALPHA PRIVATE")
    b = await document(client, headers(identities, organizations, "bob"), "B", "BETA PRIVATE")
    jobs = {}
    for user in ("alice", "bob"):
        jobs[user] = (
            await client.post(
                "/exports", headers=headers(identities, organizations, user, key="snapshot")
            )
        ).json()["id"]
    assert await run_batch() == 2
    for user, doc in [("alice", a), ("bob", b)]:
        result = (
            await client.get(
                f"/exports/{jobs[user]}/download", headers=headers(identities, organizations, user)
            )
        ).json()
        assert result["tenant_id"] == organizations[user]["id"]
        assert [row["id"] for row in result["documents"]] == [doc["id"]]
    assert (
        await client.get(
            f"/exports/{jobs['bob']}/download", headers=headers(identities, organizations)
        )
    ).status_code == 404


async def test_export_rechecks_revoked_membership(client, identities, organizations):
    await document(client, headers(identities, organizations))
    viewer = await invite_member(client, identities, organizations)
    job = (await client.post("/exports", headers={**viewer, "Idempotency-Key": "export"})).json()[
        "id"
    ]
    assert (
        await client.delete(
            f"/members/{identities['carol']['id']}", headers=headers(identities, organizations)
        )
    ).status_code == 204
    assert await run_batch() == 1
    status = (
        await client.get(f"/exports/{job}", headers=headers(identities, organizations))
    ).json()
    assert status["status"] == "rejected" and status["error"] == "membership_revoked"
    assert (await client.get(f"/exports/{job}/download", headers=viewer)).status_code == 403


async def test_export_retry_key_creates_one_outbox_record(client, identities, organizations):
    h = headers(identities, organizations, key="same")
    results = await asyncio.gather(*[client.post("/exports", headers=h) for _ in range(10)])
    assert all(r.status_code == 202 for r in results)
    assert len({r.json()["id"] for r in results}) == 1
    async with admin_engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM export_outbox")) == 1


async def test_export_transaction_rollback_is_recoverable(
    client, identities, organizations, monkeypatch
):
    import tenantdesk.worker as worker

    await document(client, headers(identities, organizations))
    job = (
        await client.post("/exports", headers=headers(identities, organizations, key="failure"))
    ).json()["id"]
    original = worker.audit

    async def fail(*args, **kwargs):
        raise RuntimeError("Injected failure before commit")

    monkeypatch.setattr(worker, "audit", fail)
    with pytest.raises(RuntimeError, match="Injected"):
        await worker.run_batch()
    async with admin_engine.connect() as conn:
        assert await conn.scalar(text("SELECT status FROM export_jobs")) == "queued"
        assert await conn.scalar(text("SELECT count(*) FROM export_outbox")) == 1
    monkeypatch.setattr(worker, "audit", original)
    assert await worker.run_batch() == 1
    assert (await client.get(f"/exports/{job}", headers=headers(identities, organizations))).json()[
        "status"
    ] == "done"


async def test_owner_cannot_be_revoked(client, identities, organizations):
    assert (
        await client.delete(
            f"/members/{identities['alice']['id']}", headers=headers(identities, organizations)
        )
    ).status_code == 409


async def test_concurrent_invitation_acceptance_obeys_member_quota(
    client, identities, organizations
):
    await quota(organizations, max_members=2)
    invitations = {}
    for user in ("carol", "dave"):
        invitations[user] = (
            await client.post(
                "/invitations",
                json={"email": identities[user]["email"]},
                headers=headers(identities, organizations),
            )
        ).json()
    responses = await asyncio.gather(
        *[
            client.post(
                "/invitations/accept",
                json={
                    "tenant_id": organizations["alice"]["id"],
                    "token": invitations[user]["token"],
                },
                headers=identities[user]["headers"],
            )
            for user in ("carol", "dave")
        ]
    )
    assert sorted(r.status_code for r in responses) == [200, 409]


async def test_quoted_etag_is_accepted_and_stale_tag_rejected(client, identities, organizations):
    h = headers(identities, organizations)
    doc = await document(client, h)
    fetched = await client.get(f"/documents/{doc['id']}", headers=h)
    etag = fetched.headers["ETag"]
    assert etag == '"1"'
    edited = await client.put(
        f"/documents/{doc['id']}", json={"title": "Updated"}, headers={**h, "If-Match": etag}
    )
    assert edited.status_code == 200
    stale = await client.put(
        f"/documents/{doc['id']}", json={"title": "Stale"}, headers={**h, "If-Match": etag}
    )
    assert stale.status_code == 409


async def test_writer_waiting_for_lock_cannot_write_after_revocation(
    client, identities, organizations
):
    editor = await invite_member(client, identities, organizations, role="editor")
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("SELECT id FROM tenants WHERE id=:id FOR UPDATE"),
            {"id": UUID(organizations["alice"]["id"])},
        )
        pending = asyncio.create_task(
            client.post("/documents", json={"title": "Must not be created"}, headers=editor)
        )
        await asyncio.sleep(0.15)
        assert not pending.done()
        await conn.execute(
            text("DELETE FROM memberships WHERE tenant_id=:tenant AND user_id=:user"),
            {"tenant": UUID(organizations["alice"]["id"]), "user": identities["carol"]["id"]},
        )
    response = await pending
    assert response.status_code == 403
    async with admin_engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM documents")) == 0
