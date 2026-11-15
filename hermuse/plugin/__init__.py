"""Metadata only. The fail-closed policy lives in the independent local gateway."""
import hashlib
import os


def session_lineage(session, home):
    """Read IDs only. Preserve ancestry so unresolved private child IDs remain tainted."""
    from hermes_state import SessionDB
    db = SessionDB(db_path=home / "state.db", read_only=True)
    try:
        ids = []
        current = session
        while current:
            if current in ids or len(ids) >= 64:
                raise ValueError("Invalid or excessive session ancestry")
            ids.append(current)
            row = db.get_session(current)
            if not row:
                raise ValueError("Unresolved session ancestry")
            current = row.get("parent_session_id")
        return ids
    finally:
        db.close()


def register(ctx):
    ctx.register_middleware("llm_request", tag_request)


def tag_request(**kwargs):
    request = dict(kwargs["request"])
    base = (kwargs.get("base_url") or "").rstrip("/")
    # Never add local metadata to unrelated provider requests.
    if base != os.environ.get("HERMUSE_ROUTER_URL", "http://127.0.0.1:20129/v1").rstrip("/"):
        return None
    from hermes_constants import get_hermes_home
    import json
    home = get_hermes_home()
    profile = hashlib.sha256(str(home).encode()).hexdigest()[:16]
    session = kwargs.get("session_id") or "auxiliary"
    headers = dict(request.get("extra_headers") or {})
    headers["X-Hermuse-Session"] = f"{profile}:{session}"
    if session == "auxiliary":
        # Background/compression calls without a conversation identity are private.
        headers["X-Hermuse-Privacy"] = "required"
    else:
        try:
            ids = session_lineage(session, home)
            headers["X-Hermuse-Lineage"] = json.dumps([f"{profile}:{s}" for s in ids], separators=(",", ":"))
        except Exception:
            # The current ID is still sent and durably tainted by the gateway.
            # A later successful ancestry read will carry that taint to the root.
            headers["X-Hermuse-Privacy"] = "required"
    request["extra_headers"] = headers
    return {"request": request, "source": "hermuse-routing", "reason": "stable-conversation-metadata"}
