"""Metadata only. The fail-closed policy lives in the independent local gateway."""
import hashlib
import os


def candidate_homes(home):
    """Known profile databases, not arbitrary filesystem paths."""
    root = home.parent.parent if home.parent.name == "profiles" else home
    profiles = root / "profiles"
    return [root] + sorted((p for p in profiles.iterdir() if p.is_dir() and not p.is_symlink()), key=str) if profiles.is_dir() else [root]


def session_lineage(session, home):
    """Resolve unique cross-profile ancestry using metadata only, or fail closed."""
    from hermes_state import SessionDB
    homes = candidate_homes(home)
    databases = []
    try:
        for candidate in homes:
            if (candidate / "state.db").is_file():
                databases.append((candidate, SessionDB(db_path=candidate / "state.db", read_only=True)))
        ids = []
        private = False
        current = session
        while current:
            if any(s == current for s, _ in ids) or len(ids) >= 64:
                raise ValueError("Invalid or excessive session ancestry")
            matches = [(owner, row) for owner, db in databases if (row := db.get_session(current))]
            if len(matches) != 1:
                raise ValueError("Unresolved or ambiguous session ancestry")
            owner, row = matches[0]
            ids.append((current, owner))
            # Bot Chat receives aggregated background notices. Its descendants
            # retain the same privacy boundary after compaction or branching.
            private |= (owner.parent.name == "profiles" and owner.name.lower() in ("finance", "private") or
                        row.get("source") == "cron" or
                        row.get("title") == SessionDB.CANONICAL_BOT_CHAT_TITLE)
            current = row.get("parent_session_id")
        return ids, private
    finally:
        for _, db in databases:
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
            ids, private = session_lineage(session, home)
            # Retain the original active-profile identity as an alias. It may
            # already be privacy-tainted from an earlier unresolved child.
            lineage = []
            for s, owner in ids:
                for namespace in (profile, hashlib.sha256(str(owner).encode()).hexdigest()[:16]):
                    identity = f"{namespace}:{s}"
                    if identity not in lineage:
                        lineage.append(identity)
            if len(lineage) > 64:
                raise ValueError("Excessive session ancestry aliases")
            headers["X-Hermuse-Lineage"] = json.dumps(lineage, separators=(",", ":"))
            if private:
                headers["X-Hermuse-Privacy"] = "required"
        except Exception:
            # The current ID is still sent and durably tainted by the gateway.
            # A later successful ancestry read will carry that taint to the root.
            headers["X-Hermuse-Privacy"] = "required"
    request["extra_headers"] = headers
    return {"request": request, "source": "hermuse-routing", "reason": "stable-conversation-metadata"}
