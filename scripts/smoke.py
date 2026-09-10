"""Live HTTP scenario covering organization isolation, invitations, restore and export."""

import json
import os
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

BASE = os.environ.get("BASE_URL", "http://localhost:8000")


def call(method, path, data=None, token=None, tenant=None, version=None, key=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if tenant:
        headers["X-Tenant-ID"] = tenant
    if version is not None:
        headers["If-Match"] = f'"{version}"'
    if key:
        headers["Idempotency-Key"] = key
    request = Request(
        BASE + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except HTTPError as error:
        return error.code, json.load(error)


def account():
    credentials = {"email": f"tenant-{uuid4().hex}@example.com", "password": "SmokePassword123!"}
    status, user = call("POST", "/auth/register", credentials)
    assert status == 201, user
    token = call("POST", "/auth/login", credentials)[1]["access_token"]
    return token, user


def main():
    token_a, user_a = account()
    token_b, _ = account()
    token_viewer, viewer = account()
    tenant_a = call("POST", "/tenants", {"name": "Smoke Alpha"}, token_a)[1]["id"]
    tenant_b = call("POST", "/tenants", {"name": "Smoke Beta"}, token_b)[1]["id"]
    a = call(
        "POST",
        "/documents",
        {"title": "Alpha document", "body": "PRIVATE ALPHA"},
        token_a,
        tenant_a,
    )[1]
    b = call(
        "POST", "/documents", {"title": "Beta document", "body": "PRIVATE BETA"}, token_b, tenant_b
    )[1]
    assert call("GET", f"/documents/{b['id']}", token=token_a, tenant=tenant_a)[0] == 404
    assert call("GET", "/documents", token=token_a, tenant=tenant_b)[0] == 403
    invitation = call(
        "POST", "/invitations", {"email": viewer["email"], "role": "viewer"}, token_a, tenant_a
    )[1]
    assert (
        call(
            "POST",
            "/invitations/accept",
            {"tenant_id": tenant_a, "token": invitation["token"]},
            token_viewer,
        )[0]
        == 200
    )
    assert call("GET", f"/documents/{a['id']}", token=token_viewer, tenant=tenant_a)[0] == 200
    assert call("POST", "/documents", {"title": "Forbidden"}, token_viewer, tenant_a)[0] == 403
    edited = call(
        "PUT",
        f"/documents/{a['id']}",
        {"title": "Alpha updated", "body": "PRIVATE ALPHA VERSION 2"},
        token_a,
        tenant_a,
        1,
    )
    assert edited[0] == 200 and edited[1]["version"] == 2, edited
    assert call("PUT", f"/documents/{a['id']}", {"title": "stale"}, token_a, tenant_a, 1)[0] == 409
    deleted = call("DELETE", f"/documents/{a['id']}", token=token_a, tenant=tenant_a, version=2)
    assert deleted[0] == 200 and deleted[1]["version"] == 3, deleted
    restored = call(
        "POST", f"/documents/{a['id']}/restore", token=token_a, tenant=tenant_a, version=3
    )
    assert restored[0] == 200 and restored[1]["body"] == "PRIVATE ALPHA VERSION 2", restored
    revisions = call("GET", f"/documents/{a['id']}/revisions", token=token_a, tenant=tenant_a)[1]
    assert [r["version"] for r in revisions] == [2, 1]
    job = call("POST", "/exports", token=token_a, tenant=tenant_a, key="snapshot")[1]
    assert (
        call("POST", "/exports", token=token_a, tenant=tenant_a, key="snapshot")[1]["id"]
        == job["id"]
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = call("GET", f"/exports/{job['id']}", token=token_a, tenant=tenant_a)[1]
        if result["status"] == "done":
            break
        time.sleep(0.2)
    assert result["status"] == "done", result
    exported = call("GET", f"/exports/{job['id']}/download", token=token_a, tenant=tenant_a)[1]
    assert exported["tenant_id"] == tenant_a
    assert [d["id"] for d in exported["documents"]] == [a["id"]], exported
    assert "PRIVATE BETA" not in json.dumps(exported)
    assert call("DELETE", f"/members/{viewer['id']}", token=token_a, tenant=tenant_a)[0] == 204
    assert call("GET", "/documents", token=token_viewer, tenant=tenant_a)[0] == 403
    health = call("GET", "/health")[1]
    assert health["rls_enforced"] and health["database_role"] == "tenantdesk_app", health
    assert health["exporter_age_seconds"] is not None and health["exporter_age_seconds"] < 10, (
        health
    )
    print(
        json.dumps(
            {
                "ok": True,
                "organizations": 2,
                "cross_tenant_access": "denied",
                "viewer_write": "denied",
                "restore": "verified",
                "isolated_export": "verified",
                "revocation": "verified",
                "tenant_id": tenant_a,
            }
        )
    )


if __name__ == "__main__":
    main()
