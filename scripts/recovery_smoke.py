"""Остановить worker своего стенда и проверить экспорт после отзыва членства."""

import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from smoke import account, call

ROOT = Path(__file__).resolve().parents[1]


def compose(*args):
    subprocess.run(
        ["docker", "compose", *args], cwd=ROOT, check=True, capture_output=True, timeout=180
    )


def expect(response, status):
    assert response[0] == status, response
    return response[1]


def verify_api_address():
    published = subprocess.check_output(
        ["docker", "compose", "port", "api", "8000"], cwd=ROOT, text=True, timeout=30
    ).splitlines()
    address = urlsplit(os.environ.get("BASE_URL", "http://localhost:8000"))
    matches = any(
        item in (f"127.0.0.1:{address.port}", f"0.0.0.0:{address.port}") for item in published
    )
    if (
        not matches
        or address.scheme != "http"
        or address.hostname not in ("127.0.0.1", "localhost")
        or address.path
        or address.query
        or address.fragment
        or address.username is not None
        or address.password is not None
    ):
        raise SystemExit("BASE_URL не соответствует API выбранного proof-проекта")


def finished(job, token, tenant):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = expect(call("GET", f"/exports/{job}", token=token, tenant=tenant), 200)
        if result["status"] in ("done", "rejected"):
            return result
        time.sleep(0.1)
    raise TimeoutError("Worker не завершил ожидающий экспорт")


def main():
    if not os.environ.get("COMPOSE_PROJECT_NAME", "").startswith("proof-"):
        raise SystemExit("Нужен отдельный COMPOSE_PROJECT_NAME с префиксом proof-")
    verify_api_address()
    compose("stop", "worker")
    try:
        owner, _ = account()
        other, _ = account()
        viewer, viewer_user = account()
        tenant = expect(call("POST", "/tenants", {"name": "Proof Alpha"}, owner), 201)["id"]
        foreign = expect(call("POST", "/tenants", {"name": "Proof Beta"}, other), 201)["id"]
        document = expect(
            call(
                "POST",
                "/documents",
                {
                    "title": "Alpha",
                    "body": "ALPHA-" + uuid4().hex,
                },
                owner,
                tenant,
            ),
            201,
        )
        secret = "BETA-" + uuid4().hex
        expect(call("POST", "/documents", {"title": "Beta", "body": secret}, other, foreign), 201)
        invite = expect(
            call(
                "POST",
                "/invitations",
                {
                    "email": viewer_user["email"],
                    "role": "viewer",
                },
                owner,
                tenant,
            ),
            201,
        )
        expect(
            call(
                "POST",
                "/invitations/accept",
                {
                    "tenant_id": tenant,
                    "token": invite["token"],
                },
                viewer,
            ),
            200,
        )
        key = uuid4().hex
        good = expect(call("POST", "/exports", token=owner, tenant=tenant, key=key), 202)
        revoked = expect(
            call("POST", "/exports", token=viewer, tenant=tenant, key=uuid4().hex), 202
        )
        replay = expect(call("POST", "/exports", token=owner, tenant=tenant, key=key), 202)
        assert replay["id"] == good["id"]
        assert (
            expect(call("GET", f"/exports/{good['id']}", token=owner, tenant=tenant), 200)["status"]
            == "queued"
        )
        assert (
            expect(call("GET", f"/exports/{revoked['id']}", token=owner, tenant=tenant), 200)[
                "status"
            ]
            == "queued"
        )
        expect(call("DELETE", f"/members/{viewer_user['id']}", token=owner, tenant=tenant), 204)
        compose("start", "worker")
        assert finished(good["id"], owner, tenant)["status"] == "done"
        denied = finished(revoked["id"], owner, tenant)
        assert denied["status"] == "rejected" and denied["error"] == "membership_revoked"
        exported = expect(
            call("GET", f"/exports/{good['id']}/download", token=owner, tenant=tenant), 200
        )
        assert exported["tenant_id"] == tenant
        assert exported["documents"] == [
            {
                "id": document["id"],
                "title": document["title"],
                "body": document["body"],
                "version": document["version"],
            }
        ]
        assert secret not in json.dumps(exported)
        expect(call("GET", f"/exports/{revoked['id']}/download", token=viewer, tenant=tenant), 403)
        expect(call("GET", f"/exports/{good['id']}/download", token=other, tenant=foreign), 404)
        print(
            json.dumps(
                {
                    "scenario": "worker_restart_after_membership_revocation",
                    "queued_while_worker_stopped": 2,
                    "same_key_same_job": True,
                    "valid_export": "done",
                    "revoked_export": "rejected",
                    "revocation_reason": denied["error"],
                    "revoked_download_status": 403,
                    "cross_tenant_download_status": 404,
                    "only_own_document": True,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    finally:
        compose("start", "worker")


if __name__ == "__main__":
    main()
