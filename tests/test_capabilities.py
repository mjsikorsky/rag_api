import pytest
from fastapi import HTTPException
from app.capabilities import require_rag_capability, require_rag_tenant


class Request:
    def __init__(self, claims=None):
        self.state = type("State", (), {})()
        if claims is not None:
            self.state.user = claims


def test_matching_scope_and_files_pass():
    claims = {"id": "u", "tenant": "t", "scope": "rag:query", "files": ["a", "b"]}
    assert require_rag_capability(Request(claims), "query", ["b"]) == claims


def test_wrong_operation_refuses():
    with pytest.raises(HTTPException) as error:
        require_rag_capability(
            Request({"scope": "rag:query", "files": ["a"]}), "delete", ["a"]
        )
    assert error.value.status_code == 403


def test_cross_file_refuses():
    with pytest.raises(HTTPException) as error:
        require_rag_capability(
            Request({"scope": "rag:query", "files": ["a"]}), "query", ["b"]
        )
    assert error.value.status_code == 403


def test_unscoped_authenticated_token_refuses():
    with pytest.raises(HTTPException):
        require_rag_capability(Request({"id": "u"}), "text", ["a"])


def test_auth_disabled_preserves_public_mode():
    assert require_rag_capability(Request(), "query", ["a"]) == {}


def test_matching_persisted_tenant_passes():
    metadata = [{"tenant_id": "tenant-a"}]
    require_rag_tenant({"tenant": "tenant-a"}, metadata)


def test_cross_tenant_document_refuses():
    metadata = [{"tenant_id": "tenant-a"}]
    with pytest.raises(HTTPException) as error:
        require_rag_tenant({"tenant": "tenant-b"}, metadata)
    assert error.value.status_code == 403


def test_scoped_tenant_refuses_legacy_unbound_document():
    metadata = [{}]
    with pytest.raises(HTTPException) as error:
        require_rag_tenant({"tenant": "tenant-a"}, metadata)
    assert error.value.status_code == 403


def test_unscoped_compatibility_accepts_legacy_document():
    metadata = [{}]
    require_rag_tenant({}, metadata)
