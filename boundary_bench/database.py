from typing import Dict, Optional
from boundary_bench.models import StudentRecord, User

# Synthetic test users
USERS: Dict[str, User] = {
    "alice": User(username="alice", full_name="Alice Smith", role="student"),
    "bob": User(username="bob", full_name="Bob Jones", role="student"),
}

# Synthetic in-memory student records
RECORDS: Dict[str, StudentRecord] = {
    "rec-alice-101": StudentRecord(
        record_id="rec-alice-101",
        owner_username="alice",
        student_name="Alice Smith",
        gpa=3.90,
        disciplinary_notes="Dean's Honor List. Confidential scholarship file.",
        is_confidential=True,
    ),
    "rec-bob-202": StudentRecord(
        record_id="rec-bob-202",
        owner_username="bob",
        student_name="Bob Jones",
        gpa=2.70,
        disciplinary_notes="Academic probation warning issued 2026-09-12.",
        is_confidential=True,
    ),
}


def get_user(username: str) -> Optional[User]:
    return USERS.get(username)


def get_record(record_id: str) -> Optional[StudentRecord]:
    return RECORDS.get(record_id)
