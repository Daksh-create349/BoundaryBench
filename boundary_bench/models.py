from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class User(BaseModel):
    username: str = Field(..., description="Unique user identifier")
    full_name: str = Field(..., description="Display name of user")
    role: str = Field(default="student", description="Role: student, faculty, admin")


class StudentRecord(BaseModel):
    record_id: str = Field(..., description="Unique identifier for record")
    owner_username: str = Field(..., description="Username of record owner")
    student_name: str = Field(..., description="Synthetic student name")
    gpa: float = Field(..., ge=0.0, le=4.0, description="Grade point average")
    disciplinary_notes: Optional[str] = Field(
        default=None, description="Confidential disciplinary notes"
    )
    is_confidential: bool = Field(
        default=True, description="Whether record contains private personal data"
    )


class VerificationResult(BaseModel):
    test_id: str
    target_endpoint: str
    authenticated_user: str
    target_record_id: str
    expected_owner: str
    status_code: int
    vulnerable: bool
    payload_received: Optional[Dict[str, Any]] = None
    reason: str


class SuggestedTestCase(BaseModel):
    model_config = {"extra": "forbid"}

    test_type: str = Field(
        ...,
        pattern=r"^(BOLA_CROSS_USER|OWNER_SELF_READ)$",
        description="Allowed test type: BOLA_CROSS_USER or OWNER_SELF_READ",
    )
    authenticated_user: str = Field(
        ...,
        pattern=r"^[a-z0-9_-]{2,32}$",
        description="Synthetic user ID (e.g. alice, bob)",
    )
    target_record_id: str = Field(
        ...,
        pattern=r"^rec-[a-z0-9_-]{1,32}$",
        description="Synthetic record ID starting with rec- without path traversal or code",
    )
    expected_owner: str = Field(
        ...,
        pattern=r"^[a-z0-9_-]{2,32}$",
        description="Expected legitimate owner username",
    )
    description: str = Field(
        ...,
        max_length=200,
        description="Short description of test scenario",
    )
    expected_status_code: int = Field(
        ...,
        ge=200,
        le=599,
        description="Expected HTTP status code in secure baseline",
    )


class AdvisorResponse(BaseModel):
    model_config = {"extra": "forbid"}

    tests: list[SuggestedTestCase] = Field(
        ...,
        min_length=1,
        max_length=5,
        description="List of 1 to 5 validated test cases",
    )


class SanitizedEvidence(BaseModel):
    target_url: str
    http_method: str = "GET"
    request_headers: Dict[str, str]
    response_status_code: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_snippet: Optional[Dict[str, Any]] = None
    protected_data_exposed: bool = False
    exposed_fields: list[str] = Field(default_factory=list)


class TestExecutionRecord(BaseModel):
    __test__ = False

    test_id: str
    test_type: str
    endpoint: str
    expected_behavior: str
    observed_behavior: str
    outcome: str = Field(
        ...,
        pattern=r"^(PASS|FAIL|INCONCLUSIVE|ERROR)$",
        description="Outcome: PASS, FAIL, INCONCLUSIVE, or ERROR",
    )
    finding_detected: bool = False
    evidence: SanitizedEvidence
    error_detail: Optional[str] = None


class TestRunReport(BaseModel):
    __test__ = False

    target_base_url: str
    total_tests: int
    passed: int
    failed: int
    inconclusive: int
    errors: int
    findings_count: int
    records: list[TestExecutionRecord]
