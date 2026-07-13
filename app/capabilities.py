from collections.abc import Iterable, Mapping

from fastapi import HTTPException, Request, status


def require_rag_capability(
    request: Request, operation: str, file_ids: Iterable[str] = ()
) -> dict:
    """Enforce LibreChat's short-lived RAG capability claims when JWT auth is on."""
    if not hasattr(request.state, "user"):
        return {}
    claims = request.state.user
    expected_scope = f"rag:{operation}"
    if claims.get("scope") != expected_scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token scope must be {expected_scope}",
        )
    authorized = claims.get("files")
    requested = set(file_ids)
    if not isinstance(authorized, list) or not all(
        isinstance(file_id, str) for file_id in authorized
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token is missing its file capability set",
        )
    if not requested.issubset(set(authorized)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not authorize every requested file",
        )
    tenant = claims.get("tenant")
    if tenant is not None and (not isinstance(tenant, str) or not tenant):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid tenant capability"
        )
    return claims


def require_rag_tenant(claims: dict, metadata: Iterable[Mapping]) -> None:
    """Refuse access when a scoped token does not match persisted tenant identity."""
    tenant = claims.get("tenant")
    if tenant is None:
        return
    if any(row.get("tenant_id") != tenant for row in metadata):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token tenant does not authorize the requested file",
        )
