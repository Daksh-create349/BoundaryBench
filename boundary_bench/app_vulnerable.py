from fastapi import FastAPI, Header, HTTPException, status
from boundary_bench.database import get_record, get_user
from boundary_bench.models import StudentRecord, User

app_vulnerable = FastAPI(
    title="BoundaryBench Vulnerable Demo API",
    description="Intentionally vulnerable API demo exhibiting Broken Object Level Authorization (BOLA/IDOR).",
    version="0.1.0",
)


def get_current_user(x_user: str = Header(..., description="Synthetic user header")) -> User:
    user = get_user(x_user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unknown synthetic user: {x_user}",
        )
    return user


@app_vulnerable.get("/health")
def health():
    return {"status": "ok", "mode": "vulnerable"}


@app_vulnerable.get("/records/{record_id}", response_model=StudentRecord)
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

    # VULNERABILITY (BOLA / IDOR):
    # Returns the record directly without verifying that record.owner_username == user.username
    return record
