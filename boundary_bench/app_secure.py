from fastapi import FastAPI, Header, HTTPException, status
from boundary_bench.database import get_record, get_user
from boundary_bench.models import StudentRecord, User
from boundary_bench.policy import DEFAULT_POLICY_ENGINE

app_secure = FastAPI(
    title="BoundaryBench Secure Demo API",
    description="Secured API rejecting cross-tenant/cross-user unauthorized record access via declarative PolicyEngine.",
    version="0.1.0",
)


@app_secure.get("/health")
def health():
    return {"status": "ok", "mode": "secure"}


@app_secure.get("/records/{record_id}", response_model=StudentRecord)
def get_student_record(record_id: str, current_user: str = Header(..., alias="x-user")):
    # Authenticate synthetic user
    user = get_user(current_user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unknown user: {current_user}",
        )

    record = get_record(record_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Record {record_id} not found",
        )

    # SECURE AUTHORIZATION BOUNDARY CHECK:
    # Evaluate explicit declarative policy rule
    decision = DEFAULT_POLICY_ENGINE.evaluate(user=user, action="READ", record=record)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    return record
