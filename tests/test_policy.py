import pytest
from pydantic import ValidationError
from boundary_bench.models import StudentRecord, User
from boundary_bench.policy import (
    DEFAULT_POLICY_ENGINE,
    AuthorizationPolicy,
    PolicyEngine,
    PolicyRule,
)


@pytest.fixture
def alice_user():
    return User(username="alice", full_name="Alice Smith", role="student")


@pytest.fixture
def bob_user():
    return User(username="bob", full_name="Bob Jones", role="student")


@pytest.fixture
def alice_record():
    return StudentRecord(
        record_id="rec-alice-101",
        owner_username="alice",
        student_name="Alice Smith",
        gpa=3.9,
    )


# ============================================================================
# 1. Policy Schema Validation & Rejections
# ============================================================================

def test_policy_schema_rejects_unsupported_action():
    with pytest.raises(ValidationError, match="Unsupported action"):
        PolicyRule(
            rule_id="RULE-BAD-ACTION",
            action="EXECUTE_ARBITRARY",
            require_ownership=True,
        )


def test_policy_schema_rejects_unsupported_role():
    with pytest.raises(ValidationError, match="Unsupported role"):
        PolicyRule(
            rule_id="RULE-BAD-ROLE",
            action="READ",
            allowed_roles=["root_user"],
        )


def test_policy_schema_rejects_extra_fields():
    with pytest.raises(ValidationError):
        PolicyRule(
            rule_id="RULE-EXTRA",
            action="READ",
            unrecognized_field="malicious",
        )


def test_policy_rejects_empty_rules():
    with pytest.raises(ValidationError):
        AuthorizationPolicy(policy_id="POLICY-EMPTY", rules=[])


# ============================================================================
# 2. Policy Engine Evaluation Logic
# ============================================================================

def test_policy_engine_grants_access_to_legitimate_owner(alice_user, alice_record):
    decision = DEFAULT_POLICY_ENGINE.evaluate(user=alice_user, action="READ", record=alice_record)
    assert decision.allowed is True
    assert "Ownership and role constraints satisfied" in decision.reason
    assert decision.rule_applied == "RULE-STUDENT-READ-OWNER"


def test_policy_engine_denies_cross_user_access(bob_user, alice_record):
    decision = DEFAULT_POLICY_ENGINE.evaluate(user=bob_user, action="READ", record=alice_record)
    assert decision.allowed is False
    assert "does not own record" in decision.reason
    assert decision.rule_applied == "RULE-STUDENT-READ-OWNER"


def test_policy_engine_denies_unsupported_action(alice_user, alice_record):
    decision = DEFAULT_POLICY_ENGINE.evaluate(user=alice_user, action="DESTROY", record=alice_record)
    assert decision.allowed is False
    assert "not supported" in decision.reason


def test_policy_engine_evaluates_role_restrictions(alice_record):
    guest_user = User(username="alice", full_name="Alice Guest", role="admin")
    custom_policy = AuthorizationPolicy(
        policy_id="POLICY-STUDENT-ONLY",
        rules=[
            PolicyRule(
                rule_id="RULE-STUDENT-ONLY",
                action="READ",
                require_ownership=False,
                allowed_roles=["student"],
            )
        ],
    )
    engine = PolicyEngine(custom_policy)
    decision = engine.evaluate(user=guest_user, action="READ", record=alice_record)
    assert decision.allowed is False
    assert "not in permitted roles" in decision.reason
