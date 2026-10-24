import httpx
import pytest
from pydantic import ValidationError
from boundary_bench.advisor import suggest_authorization_tests
from boundary_bench.app_secure import app_secure
from boundary_bench.app_vulnerable import app_vulnerable
from boundary_bench.models import StudentRecord, User, VerificationResult
from boundary_bench.verifier import verify_authorization_boundary


from fastapi.testclient import TestClient

@pytest.fixture
def vulnerable_client():
    with TestClient(app_vulnerable) as client:
        yield client


@pytest.fixture
def secure_client():
    with TestClient(app_secure) as client:
        yield client


# ============================================================================
# 1. Models & Validation Tests
# ============================================================================

def test_student_record_validation():
    # Valid record
    rec = StudentRecord(
        record_id="rec-1",
        owner_username="alice",
        student_name="Alice",
        gpa=3.85,
    )
    assert rec.record_id == "rec-1"
    assert rec.is_confidential is True

    # Invalid GPA out of bounds (> 4.0)
    with pytest.raises(ValidationError):
        StudentRecord(
            record_id="rec-bad",
            owner_username="alice",
            student_name="Alice",
            gpa=5.5,
        )

    # Invalid GPA (< 0.0)
    with pytest.raises(ValidationError):
        StudentRecord(
            record_id="rec-bad",
            owner_username="alice",
            student_name="Alice",
            gpa=-0.5,
        )


def test_user_model_defaults():
    user = User(username="carol", full_name="Carol Danvers")
    assert user.role == "student"


# ============================================================================
# 2. Vulnerable App Behavior & Verification Tests
# ============================================================================

def test_vulnerable_app_owner_can_access_own_record(vulnerable_client):
    """Alice accesses Alice's record -> 200 OK."""
    resp = vulnerable_client.get("/records/rec-alice-101", headers={"x-user": "alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["record_id"] == "rec-alice-101"
    assert data["owner_username"] == "alice"


def test_vulnerable_app_exhibits_bola_idor(vulnerable_client):
    """
    CRITICAL TEST:
    Alice attempts to access Bob's private record.
    In vulnerable mode, this succeeds (200 OK) and leaks Bob's confidential data.
    The deterministic verifier must inspect the payload and flag vulnerable=True.
    """
    # Raw HTTP inspection
    resp = vulnerable_client.get("/records/rec-bob-202", headers={"x-user": "alice"})
    assert resp.status_code == 200
    leaked_data = resp.json()

    # Verify that confidential payload belonging to Bob was exposed to Alice
    assert leaked_data["record_id"] == "rec-bob-202"
    assert leaked_data["owner_username"] == "bob"
    assert leaked_data["student_name"] == "Bob Jones"
    assert "Academic probation warning" in leaked_data["disciplinary_notes"]

    # Deterministic verifier inspection
    result: VerificationResult = verify_authorization_boundary(
        client=vulnerable_client,
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
    )
    assert result.status_code == 200
    assert result.vulnerable is True
    assert "VULNERABILITY CONFIRMED" in result.reason
    assert result.payload_received["owner_username"] == "bob"


# ============================================================================
# 3. Secure App Behavior & Verification Tests
# ============================================================================

def test_secure_app_owner_can_access_own_record(secure_client):
    """Alice accesses Alice's record -> 200 OK."""
    resp = secure_client.get("/records/rec-alice-101", headers={"x-user": "alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["record_id"] == "rec-alice-101"
    assert data["owner_username"] == "alice"


def test_secure_app_rejects_cross_user_access(secure_client):
    """
    CRITICAL TEST:
    Alice attempts to access Bob's private record.
    Secure mode rejects request with 403 Forbidden.
    Deterministic verifier verifies vulnerable=False.
    """
    resp = secure_client.get("/records/rec-bob-202", headers={"x-user": "alice"})
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"]

    result: VerificationResult = verify_authorization_boundary(
        client=secure_client,
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
    )
    assert result.status_code == 403
    assert result.vulnerable is False
    assert "SECURE: Request rejected with 403" in result.reason


def test_secure_app_bob_cannot_access_alice_record(secure_client):
    """Bob attempts to access Alice's private record -> 403 Forbidden."""
    result: VerificationResult = verify_authorization_boundary(
        client=secure_client,
        authenticated_user="bob",
        target_record_id="rec-alice-101",
        expected_owner="alice",
    )
    assert result.status_code == 403
    assert result.vulnerable is False


# ============================================================================
# 4. Authentication & Error Edge Cases
# ============================================================================

def test_unauthenticated_request_rejected(secure_client, vulnerable_client):
    for client in (secure_client, vulnerable_client):
        # Missing x-user header (FastAPI header validation gives 422)
        resp = client.get("/records/rec-alice-101")
        assert resp.status_code == 422

        # Unknown user
        resp = client.get("/records/rec-alice-101", headers={"x-user": "mallory"})
        assert resp.status_code == 401


def test_nonexistent_record_returns_404(secure_client, vulnerable_client):
    for client in (secure_client, vulnerable_client):
        resp = client.get("/records/rec-nonexistent", headers={"x-user": "alice"})
        assert resp.status_code == 404


# ============================================================================
# 5. AI Advisor: Mocked Tests & Opt-in Integration Test
# ============================================================================
from unittest.mock import MagicMock, patch
from boundary_bench.advisor import (
    DETERMINISTIC_FALLBACK_TESTS,
    suggest_authorization_tests,
    validate_test_safety,
)
from boundary_bench.models import SuggestedTestCase


def test_advisor_offline_when_ollama_down():
    with patch("boundary_bench.advisor.check_ollama_available", return_value=False):
        result = suggest_authorization_tests()
        assert result["source"] == "deterministic-fallback"
        assert result["tests"] == DETERMINISTIC_FALLBACK_TESTS


def test_advisor_fallback_when_model_tag_missing():
    with patch("boundary_bench.advisor.check_ollama_available", return_value=True), \
         patch("boundary_bench.advisor.get_installed_models", return_value=["other:tag"]):
        result = suggest_authorization_tests(model="gemma4:e2b")
        assert result["source"] == "deterministic-fallback"
        assert "not found" in result["reason"]
        assert result["tests"] == DETERMINISTIC_FALLBACK_TESTS


def test_advisor_parses_valid_mocked_ollama_response():
    mock_llm_json = {
        "tests": [
            {
                "test_type": "BOLA_CROSS_USER",
                "authenticated_user": "bob",
                "target_record_id": "rec-alice-101",
                "expected_owner": "alice",
                "description": "Bob tries to read Alice record",
                "expected_status_code": 403,
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": f"```json\n{import_json_str(mock_llm_json)}\n```"
    }

    with patch("boundary_bench.advisor.check_ollama_available", return_value=True), \
         patch("boundary_bench.advisor.get_installed_models", return_value=["gemma4:e2b"]), \
         patch("httpx.Client.post", return_value=mock_resp):
        result = suggest_authorization_tests(model="gemma4:e2b")
        assert result["source"] == "ollama:gemma4:e2b"
        assert len(result["tests"]) == 1
        t = result["tests"][0]
        assert t.test_type == "BOLA_CROSS_USER"
        assert t.authenticated_user == "bob"
        assert t.target_record_id == "rec-alice-101"


def test_advisor_rejects_unknown_test_type():
    mock_llm_json = {
        "tests": [
            {
                "test_type": "ARBITRARY_REMOTE_EXEC",
                "authenticated_user": "alice",
                "target_record_id": "rec-bob-202",
                "expected_owner": "bob",
                "description": "Exploit execution",
                "expected_status_code": 403,
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": import_json_str(mock_llm_json)
    }

    with patch("boundary_bench.advisor.check_ollama_available", return_value=True), \
         patch("boundary_bench.advisor.get_installed_models", return_value=["gemma4:e2b"]), \
         patch("httpx.Client.post", return_value=mock_resp):
        result = suggest_authorization_tests(model="gemma4:e2b")
        # Must fall back to deterministic tests upon validation failure
        assert result["source"] == "deterministic-fallback"
        assert result["tests"] == DETERMINISTIC_FALLBACK_TESTS


def test_advisor_rejects_unexpected_extra_fields():
    mock_llm_json = {
        "tests": [
            {
                "test_type": "BOLA_CROSS_USER",
                "authenticated_user": "alice",
                "target_record_id": "rec-bob-202",
                "expected_owner": "bob",
                "description": "Alice access",
                "expected_status_code": 403,
                "extra_malicious_field": "drop database",
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": import_json_str(mock_llm_json)
    }

    with patch("boundary_bench.advisor.check_ollama_available", return_value=True), \
         patch("boundary_bench.advisor.get_installed_models", return_value=["gemma4:e2b"]), \
         patch("httpx.Client.post", return_value=mock_resp):
        result = suggest_authorization_tests(model="gemma4:e2b")
        assert result["source"] == "deterministic-fallback"
        assert result["tests"] == DETERMINISTIC_FALLBACK_TESTS


def test_advisor_rejects_path_traversal_and_unsafe_identifier():
    # Target record contains path traversal "../"
    bad_test = SuggestedTestCase(
        test_type="BOLA_CROSS_USER",
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
        description="test",
        expected_status_code=403,
    )
    # validate_test_safety allows clean test
    validate_test_safety(bad_test)

    # Now verify safety check rejects traversal or unapproved record
    with pytest.raises(ValueError, match="Unsafe"):
        bad_traversal = bad_test.model_copy(update={"target_record_id": "rec-../../etc/passwd"})
        validate_test_safety(bad_traversal)

    with pytest.raises(ValueError, match="Unknown synthetic"):
        bad_user = bad_test.model_copy(update={"authenticated_user": "attacker_user"})
        validate_test_safety(bad_user)


def test_advisor_handles_timeout_gracefully():
    with patch("boundary_bench.advisor.check_ollama_available", return_value=True), \
         patch("boundary_bench.advisor.get_installed_models", return_value=["gemma4:e2b"]), \
         patch("httpx.Client.post", side_effect=httpx.TimeoutException("Timeout")):
        result = suggest_authorization_tests(model="gemma4:e2b")
        assert result["source"] == "deterministic-fallback"
        assert "TimeoutException" in result["reason"]
        assert result["tests"] == DETERMINISTIC_FALLBACK_TESTS


def test_advisor_handles_malformed_non_json():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": "I cannot fulfill this request as JSON. Here is plain text."
    }

    with patch("boundary_bench.advisor.check_ollama_available", return_value=True), \
         patch("boundary_bench.advisor.get_installed_models", return_value=["gemma4:e2b"]), \
         patch("httpx.Client.post", return_value=mock_resp):
        result = suggest_authorization_tests(model="gemma4:e2b")
        assert result["source"] == "deterministic-fallback"
        assert result["tests"] == DETERMINISTIC_FALLBACK_TESTS


@pytest.mark.integration
def test_real_local_gemma4_e2b_integration():
    """
    Opt-in live integration test.
    Requires local Ollama with gemma4:e2b running.
    Run with: pytest -v --run-integration
    """
    result = suggest_authorization_tests(model="gemma4:e2b", timeout=40.0)
    assert result["source"] == "ollama:gemma4:e2b"
    assert len(result["tests"]) >= 1
    for t in result["tests"]:
        assert isinstance(t, SuggestedTestCase)
        assert t.authenticated_user in {"alice", "bob"}
        assert t.target_record_id in {"rec-alice-101", "rec-bob-202"}


def import_json_str(data) -> str:
    import json
    return json.dumps(data)

