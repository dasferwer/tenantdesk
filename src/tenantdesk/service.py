import json
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import text

from .tenancy import lock_tenant


async def audit(conn, tenant, actor, action, entity=None, details=None):
    await conn.execute(
        text("""INSERT INTO audit_log(id,tenant_id,actor_id,action,entity_id,details)
        VALUES (:id,:tenant,:actor,:action,:entity,CAST(:details AS jsonb))"""),
        {
            "id": uuid4(),
            "tenant": tenant,
            "actor": actor,
            "action": action,
            "entity": entity,
            "details": json.dumps(details or {}),
        },
    )


async def usage(conn):
    active = await conn.scalar(text("SELECT count(*) FROM documents WHERE deleted_at IS NULL"))
    storage = await conn.scalar(text("SELECT COALESCE(sum(storage_bytes),0) FROM revisions"))
    return {"active_documents": active, "storage_bytes": storage}


def size_of(title, body):
    return len(title.encode()) + len(body.encode())


async def check_quota(context, tenant, new_document=False, extra_bytes=0):
    current = await usage(context.conn)
    if new_document and current["active_documents"] >= tenant["max_documents"]:
        raise HTTPException(409, "Active document quota exceeded")
    if current["storage_bytes"] + extra_bytes > tenant["max_storage_bytes"]:
        raise HTTPException(409, "Storage quota exceeded (includes retained revisions)")


async def add_revision(context, document):
    await context.conn.execute(
        text("""INSERT INTO revisions(id,tenant_id,document_id,version,title,body,storage_bytes,created_by)
        VALUES (:id,:tenant,:document,:version,:title,:body,:size,:actor)"""),
        {
            "id": uuid4(),
            "tenant": context.tenant_id,
            "document": document["id"],
            "version": document["version"],
            "title": document["title"],
            "body": document["body"],
            "size": size_of(document["title"], document["body"]),
            "actor": context.user.id,
        },
    )


async def create_document(context, title, body):
    context.require("owner", "editor")
    tenant = await lock_tenant(context)
    await check_quota(context, tenant, True, size_of(title, body))
    document = (
        (
            await context.conn.execute(
                text("""INSERT INTO documents(id,tenant_id,title,body,created_by)
        VALUES (:id,:tenant,:title,:body,:actor) RETURNING *"""),
                {
                    "id": uuid4(),
                    "tenant": context.tenant_id,
                    "title": title,
                    "body": body,
                    "actor": context.user.id,
                },
            )
        )
        .mappings()
        .one()
    )
    await add_revision(context, document)
    await audit(
        context.conn,
        context.tenant_id,
        context.user.id,
        "document.created",
        document["id"],
        {"version": 1},
    )
    return dict(document)


async def get_document(context, document_id):
    # Фильтр компании здесь добавляет PostgreSQL через RLS.
    row = (
        (
            await context.conn.execute(
                text("SELECT * FROM documents WHERE id=:id"), {"id": document_id}
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(404, "Document not found")
    return row


async def mutate_document(context, document_id, version, action, title=None, body=None):
    context.require("owner", "editor")
    tenant = await lock_tenant(context)
    document = await get_document(context, document_id)
    if document["version"] != version:
        raise HTTPException(409, "Document version changed; reload before retrying")
    if action == "edit":
        if document["deleted_at"] is not None:
            raise HTTPException(409, "Restore the document before editing")
        await check_quota(context, tenant, extra_bytes=size_of(title, body))
        row = (
            (
                await context.conn.execute(
                    text("""UPDATE documents SET title=:title,body=:body,version=version+1,
            updated_at=clock_timestamp() WHERE id=:id RETURNING *"""),
                    {"title": title, "body": body, "id": document_id},
                )
            )
            .mappings()
            .one()
        )
        await add_revision(context, row)
    elif action == "delete":
        if document["deleted_at"] is not None:
            return dict(document)
        row = (
            (
                await context.conn.execute(
                    text(
                        "UPDATE documents SET deleted_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp() WHERE id=:id RETURNING *"
                    ),
                    {"id": document_id},
                )
            )
            .mappings()
            .one()
        )
    elif action == "restore":
        if document["deleted_at"] is None:
            return dict(document)
        await check_quota(context, tenant, new_document=True)
        row = (
            (
                await context.conn.execute(
                    text(
                        "UPDATE documents SET deleted_at=NULL,version=version+1,updated_at=clock_timestamp() WHERE id=:id RETURNING *"
                    ),
                    {"id": document_id},
                )
            )
            .mappings()
            .one()
        )
    else:
        raise ValueError("Unknown document action")
    await audit(
        context.conn,
        context.tenant_id,
        context.user.id,
        "document." + action,
        document_id,
        {"version": row["version"]},
    )
    return dict(row)
