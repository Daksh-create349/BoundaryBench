from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import httpx
import pytest
from boundary_bench.app_secure import app_secure
from boundary_bench.app_vulnerable import app_vulnerable
from boundary_bench.models import SuggestedTestCase
from boundary_bench.runner import (
    MAX_TESTS_PER_RUN,
    SecurityTestRunner,
    sanitize_headers,
    validate_target_url,
)


@pytest.fixture
def vulnerable_client():
    with TestClient(app_vulnerable) as client:
        yield client


@pytest.fixture
def secure_client():
    with TestClient(app_secure) as client:
        yield client


# ============================================================================
# 1. Normal Runner Execution & Evidence Inspection
# ============================================================================

def test_runner_vulnerable_app_produces_reproducible_finding(vulnerable_client):
    runner = SecurityTestRunner(client=vulnerable_client, base_url="http://testserver")
    test_case = SuggestedTestCase(
        test_type="BOLA_CROSS_USER",
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
        description="Alice attempts to read Bob's record",
        expected_status_code=403,
    )

    record = runner.execute_test(test_case)

    # Vulnerability must be detected and classified as FAIL for the security check
    assert record.outcome == "FAIL"
    assert record.finding_detected is True
    assert "BOLA finding" in record.observed_behavior
    assert record.evidence.response_status_code == 200
    assert record.evidence.protected_data_exposed is True
    assert "gpa" in record.evidence.exposed_fields
    assert "disciplinary_notes" in record.evidence.exposed_fields
    assert record.evidence.response_body_snippet["owner_username"] == "bob"


def test_runner_secure_app_passes_authorization_check(secure_client):
    runner = SecurityTestRunner(client=secure_client, base_url="http://testserver")
    test_case = SuggestedTestCase(
        test_type="BOLA_CROSS_USER",
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
        description="Alice attempts to read Bob's record",
        expected_status_code=403,
    )

    record = runner.execute_test(test_case)

    # Secure app rejects unauthorized access -> Security check PASS
    assert record.outcome == "PASS"
    assert record.finding_detected is False
    assert record.evidence.response_status_code == 403
    assert record.evidence.protected_data_exposed is False
    assert record.evidence.exposed_fields == []


def test_runner_owner_self_read_passes_on_both(vulnerable_client, secure_client):
    test_case = SuggestedTestCase(
        test_type="OWNER_SELF_READ",
        authenticated_user="alice",
        target_record_id="rec-alice-101",
        expected_owner="alice",
        description="Alice reads her own record",
        expected_status_code=200,
    )

    for client in (vulnerable_client, secure_client):
        runner = SecurityTestRunner(client=client, base_url="http://testserver")
        record = runner.execute_test(test_case)
        assert record.outcome == "PASS"
        assert record.finding_detected is False
        assert record.evidence.response_status_code == 200


def test_runner_batch_run_reports_summary(vulnerable_client):
    runner = SecurityTestRunner(client=vulnerable_client, base_url="http://testserver")
    tests = [
        SuggestedTestCase(
            test_type="BOLA_CROSS_USER",
            authenticated_user="alice",
            target_record_id="rec-bob-202",
            expected_owner="bob",
            description="Alice -> Bob",
            expected_status_code=403,
        ),
        SuggestedTestCase(
            test_type="OWNER_SELF_READ",
            authenticated_user="alice",
            target_record_id="rec-alice-101",
            expected_owner="alice",
            description="Alice -> Alice",
            expected_status_code=200,
        ),
    ]

    report = runner.run_tests(tests)
    assert report.total_tests == 2
    assert report.failed == 1   # BOLA finding
    assert report.passed == 1   # Owner read
    assert report.findings_count == 1
    assert len(report.records) == 2


# ============================================================================
# 2. Inconclusive & Error Handling
# ============================================================================

def test_runner_inconclusive_when_record_missing():
    # Mock client returning 404 Not Found
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {"detail": "Not Found"}
    mock_client.get.return_value = mock_resp

    runner = SecurityTestRunner(client=mock_client, base_url="http://localhost:8000")
    test_case = SuggestedTestCase(
        test_type="BOLA_CROSS_USER",
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
        description="Test non-existent",
        expected_status_code=403,
    )

    record = runner.execute_test(test_case)
    assert record.outcome == "INCONCLUSIVE"
    assert record.finding_detected is False
    assert "Inconclusive" in record.observed_behavior


def test_runner_error_handling_on_timeout():
    mock_client = MagicMock()
    mock_client.get.side_effect = httpx.TimeoutException("Read timed out")

    runner = SecurityTestRunner(client=mock_client, base_url="http://localhost:8000")
    test_case = SuggestedTestCase(
        test_type="BOLA_CROSS_USER",
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
        description="Timeout test",
        expected_status_code=403,
    )

    record = runner.execute_test(test_case)
    assert record.outcome == "ERROR"
    assert record.finding_detected is False
    assert "TimeoutException" in record.error_detail
    assert record.evidence.response_status_code is None


# ============================================================================
# 3. Security Boundary, Target Restriction & Secret Sanitization
# ============================================================================

def test_validate_target_url_accepts_local_hosts():
    for valid_url in [
        "http://testserver",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://127.0.0.1:8443",
    ]:
        validate_target_url(valid_url)  # Must not raise


def test_validate_target_url_rejects_external_hosts():
    for untrusted_url in [
        "http://example.com",
        "https://google.com",
        "http://169.254.169.254",  # AWS metadata IP
        "http://192.168.1.50",
        "ftp://localhost",
    ]:
        with pytest.raises(ValueError, match="(rejected|scheme)"):
            validate_target_url(untrusted_url)


def test_sanitize_headers_masks_secrets():
    raw_headers = {
        "x-user": "alice",
        "Authorization": "Bearer super-secret-jwt-token",
        "Cookie": "session=sensitive_id_12345",
        "X-Api-Key": "secret-key-abcdef",
        "Content-Type": "application/json",
    }
    sanitized = sanitize_headers(raw_headers)
    assert sanitized["x-user"] == "alice"
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["X-Api-Key"] == "[REDACTED]"


def test_runner_rejects_batch_exceeding_max_limit(vulnerable_client):
    runner = SecurityTestRunner(client=vulnerable_client, base_url="http://testserver")
    excessive_tests = [
        SuggestedTestCase(
            test_type="OWNER_SELF_READ",
            authenticated_user="alice",
            target_record_id="rec-alice-101",
            expected_owner="alice",
            description=f"Test {i}",
            expected_status_code=200,
        )
        for i in range(MAX_TESTS_PER_RUN + 1)
    ]

    with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
        runner.run_tests(excessive_tests)


# ============================================================================
# 4. Invalid Generated Test Cases
# ============================================================================

def test_runner_rejects_unsafe_identifiers(vulnerable_client):
    runner = SecurityTestRunner(client=vulnerable_client, base_url="http://testserver")

    # Path traversal record ID
    with pytest.raises(ValueError, match="Unsafe"):
        bad_case = SuggestedTestCase(
            test_type="BOLA_CROSS_USER",
            authenticated_user="alice",
            target_record_id="rec-bob-202",
            expected_owner="bob",
            description="Normal",
            expected_status_code=403,
        ).model_copy(update={"target_record_id": "rec-../bob"})
        runner.execute_test(bad_case)
