import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx
from boundary_bench.advisor import validate_test_safety
from boundary_bench.models import (
    SanitizedEvidence,
    SuggestedTestCase,
    TestExecutionRecord,
    TestRunReport,
)

MAX_TESTS_PER_RUN = 10
DEFAULT_REQUEST_TIMEOUT = 5.0
ALLOWED_HOSTS = {"testserver", "localhost", "127.0.0.1"}
ALLOWED_TEST_TYPES = {"BOLA_CROSS_USER", "OWNER_SELF_READ"}
PROTECTED_FIELDS = {"gpa", "disciplinary_notes"}
SECRET_HEADER_PATTERN = re.compile(
    r"(authorization|cookie|token|secret|password|api-?key)", re.IGNORECASE
)


def validate_target_url(base_url: str) -> None:
    """
    Ensure the target URL points strictly to a local demo target.
    Rejects external targets, cloud IPs, or unexpected hosts.
    """
    parsed = urlparse(base_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Invalid URL scheme '{scheme}'. Only http/https supported.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError(f"Target URL must contain a valid hostname: {base_url}")

    if hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"Security policy violation: External or unexpected target host '{hostname}' rejected. "
            f"Allowed local hosts: {sorted(ALLOWED_HOSTS)}"
        )


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Redact any potential authentication secrets or sensitive tokens from logs and reports.
    """
    sanitized = {}
    for k, v in headers.items():
        if SECRET_HEADER_PATTERN.search(k):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


class SecurityTestRunner:
    """
    Controlled security test runner for BoundaryBench.
    Executes validated authorization test cases against local demo targets,
    inspects response bodies, captures sanitized evidence, and produces structured reports.
    """

    def __init__(
        self,
        client: httpx.Client,
        base_url: str = "http://testserver",
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ):
        validate_target_url(base_url)
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def execute_test(
        self, test: SuggestedTestCase, test_id: Optional[str] = None
    ) -> TestExecutionRecord:
        """
        Execute a single validated test case deterministically.
        """
        # 1. Enforce known test type
        if test.test_type not in ALLOWED_TEST_TYPES:
            raise ValueError(
                f"Unknown test type '{test.test_type}'. Allowed types: {sorted(ALLOWED_TEST_TYPES)}"
            )

        # 2. Enforce strict safety constraints on parameters
        validate_test_safety(test)

        tid = test_id or f"{test.test_type}-{test.authenticated_user}-{test.target_record_id}"
        endpoint = f"/records/{test.target_record_id}"
        full_url = f"{self.base_url}{endpoint}"

        raw_req_headers = {"x-user": test.authenticated_user}
        sanitized_req_headers = sanitize_headers(raw_req_headers)

        expected_behavior = (
            f"Access rejected with HTTP {test.expected_status_code} Forbidden (cross-user boundary protected)"
            if test.test_type == "BOLA_CROSS_USER"
            else f"Access permitted with HTTP {test.expected_status_code} OK (legitimate owner read)"
        )

        try:
            # 3. Controlled request: strictly avoid external calls, redirects, or long timeouts
            req_kwargs = {"headers": raw_req_headers, "follow_redirects": False}
            if type(self.client).__name__ != "TestClient":
                req_kwargs["timeout"] = self.timeout

            response = self.client.get(endpoint, **req_kwargs)

            status_code = response.status_code
            resp_headers = {
                k: v
                for k, v in response.headers.items()
                if k.lower() in {"content-type", "content-length", "date"}
            }

            payload: Optional[Dict[str, Any]] = None
            try:
                data = response.json()
                if isinstance(data, dict):
                    payload = data
            except Exception:
                pass

            # 4. Check protected data exposure based on actual payload
            protected_data_exposed = False
            exposed_fields: List[str] = []

            if payload:
                for field in PROTECTED_FIELDS:
                    if field in payload and payload[field] is not None:
                        exposed_fields.append(field)
                if "student_name" in payload:
                    exposed_fields.append("student_name")

            # 5. Evaluate outcome deterministically based on test type
            if test.test_type == "BOLA_CROSS_USER":
                if status_code in {403, 401}:
                    # Security boundary held
                    return TestExecutionRecord(
                        test_id=tid,
                        test_type=test.test_type,
                        endpoint=endpoint,
                        expected_behavior=expected_behavior,
                        observed_behavior=f"Authorization enforced: Server returned HTTP {status_code}.",
                        outcome="PASS",
                        finding_detected=False,
                        evidence=SanitizedEvidence(
                            target_url=full_url,
                            http_method="GET",
                            request_headers=sanitized_req_headers,
                            response_status_code=status_code,
                            response_headers=resp_headers,
                            response_body_snippet=payload,
                            protected_data_exposed=False,
                            exposed_fields=[],
                        ),
                    )

                if status_code == 200 and payload:
                    ret_id = payload.get("record_id")
                    ret_owner = payload.get("owner_username")

                    # Verify actual returned record belongs to victim
                    if ret_id == test.target_record_id and ret_owner == test.expected_owner:
                        protected_data_exposed = len(exposed_fields) > 0
                        return TestExecutionRecord(
                            test_id=tid,
                            test_type=test.test_type,
                            endpoint=endpoint,
                            expected_behavior=expected_behavior,
                            observed_behavior=(
                                f"BOLA finding: User '{test.authenticated_user}' accessed record "
                                f"'{test.target_record_id}' owned by '{test.expected_owner}' (HTTP 200). "
                                f"Exposed fields: {exposed_fields}."
                            ),
                            outcome="FAIL",
                            finding_detected=True,
                            evidence=SanitizedEvidence(
                                target_url=full_url,
                                http_method="GET",
                                request_headers=sanitized_req_headers,
                                response_status_code=status_code,
                                response_headers=resp_headers,
                                response_body_snippet=payload,
                                protected_data_exposed=protected_data_exposed,
                                exposed_fields=exposed_fields,
                            ),
                        )

                # Returned 200 with wrong body or 404 or other unexpected status
                return TestExecutionRecord(
                    test_id=tid,
                    test_type=test.test_type,
                    endpoint=endpoint,
                    expected_behavior=expected_behavior,
                    observed_behavior=f"Inconclusive response: HTTP {status_code} received without expected victim record payload.",
                    outcome="INCONCLUSIVE",
                    finding_detected=False,
                    evidence=SanitizedEvidence(
                        target_url=full_url,
                        http_method="GET",
                        request_headers=sanitized_req_headers,
                        response_status_code=status_code,
                        response_headers=resp_headers,
                        response_body_snippet=payload,
                        protected_data_exposed=False,
                        exposed_fields=[],
                    ),
                )

            elif test.test_type == "OWNER_SELF_READ":
                if status_code == 200 and payload and payload.get("owner_username") == test.authenticated_user:
                    return TestExecutionRecord(
                        test_id=tid,
                        test_type=test.test_type,
                        endpoint=endpoint,
                        expected_behavior=expected_behavior,
                        observed_behavior=f"Legitimate owner read succeeded with HTTP 200.",
                        outcome="PASS",
                        finding_detected=False,
                        evidence=SanitizedEvidence(
                            target_url=full_url,
                            http_method="GET",
                            request_headers=sanitized_req_headers,
                            response_status_code=status_code,
                            response_headers=resp_headers,
                            response_body_snippet=payload,
                            protected_data_exposed=True,
                            exposed_fields=exposed_fields,
                        ),
                    )
                else:
                    return TestExecutionRecord(
                        test_id=tid,
                        test_type=test.test_type,
                        endpoint=endpoint,
                        expected_behavior=expected_behavior,
                        observed_behavior=f"Owner read check failed: HTTP {status_code} received.",
                        outcome="FAIL",
                        finding_detected=False,
                        evidence=SanitizedEvidence(
                            target_url=full_url,
                            http_method="GET",
                            request_headers=sanitized_req_headers,
                            response_status_code=status_code,
                            response_headers=resp_headers,
                            response_body_snippet=payload,
                            protected_data_exposed=False,
                            exposed_fields=[],
                        ),
                    )

        except Exception as e:
            return TestExecutionRecord(
                test_id=tid,
                test_type=test.test_type,
                endpoint=endpoint,
                expected_behavior=expected_behavior,
                observed_behavior=f"Request error occurred during execution.",
                outcome="ERROR",
                finding_detected=False,
                error_detail=f"{type(e).__name__}: {str(e)}",
                evidence=SanitizedEvidence(
                    target_url=full_url,
                    http_method="GET",
                    request_headers=sanitized_req_headers,
                    response_status_code=None,
                    response_headers={},
                    response_body_snippet=None,
                    protected_data_exposed=False,
                    exposed_fields=[],
                ),
            )

    def run_tests(self, tests: List[SuggestedTestCase]) -> TestRunReport:
        """
        Execute a list of tests up to the MAX_TESTS_PER_RUN limit.
        """
        if len(tests) > MAX_TESTS_PER_RUN:
            raise ValueError(
                f"Test batch size {len(tests)} exceeds maximum allowed limit ({MAX_TESTS_PER_RUN})"
            )

        records: List[TestExecutionRecord] = []
        passed = 0
        failed = 0
        inconclusive = 0
        errors = 0
        findings = 0

        for idx, test in enumerate(tests, 1):
            tid = f"TEST-{idx:02d}-{test.test_type}"
            rec = self.execute_test(test, test_id=tid)
            records.append(rec)

            if rec.outcome == "PASS":
                passed += 1
            elif rec.outcome == "FAIL":
                failed += 1
            elif rec.outcome == "INCONCLUSIVE":
                inconclusive += 1
            elif rec.outcome == "ERROR":
                errors += 1

            if rec.finding_detected:
                findings += 1

        return TestRunReport(
            target_base_url=self.base_url,
            total_tests=len(records),
            passed=passed,
            failed=failed,
            inconclusive=inconclusive,
            errors=errors,
            findings_count=findings,
            records=records,
        )
