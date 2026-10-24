import re
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from boundary_bench.models import StudentRecord, User

SUPPORTED_ACTIONS = {"READ", "UPDATE", "DELETE"}
ALLOWED_ROLES = {"student", "faculty", "admin"}
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9_-]{2,32}$")


class PolicyRule(BaseModel):
    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., description="Unique rule identifier")
    action: str = Field(..., description="Target operation: READ, UPDATE, DELETE")
    require_ownership: bool = Field(
        default=True, description="Enforce that resource owner equals requester"
    )
    allowed_roles: List[str] = Field(
        default_factory=lambda: ["student", "faculty"],
        description="Allowed requester roles",
    )

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        upper = v.upper()
        if upper not in SUPPORTED_ACTIONS:
            raise ValueError(
                f"Unsupported action '{v}'. Supported: {sorted(SUPPORTED_ACTIONS)}"
            )
        return upper

    @field_validator("allowed_roles")
    @classmethod
    def validate_roles(cls, roles: List[str]) -> List[str]:
        for role in roles:
            if role not in ALLOWED_ROLES:
                raise ValueError(
                    f"Unsupported role '{role}'. Allowed roles: {sorted(ALLOWED_ROLES)}"
                )
        return roles


class AuthorizationPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    policy_id: str = Field(..., description="Policy identifier")
    rules: List[PolicyRule] = Field(
        ..., min_length=1, description="List of explicit authorization rules"
    )


class PolicyDecision(BaseModel):
    model_config = {"extra": "forbid"}

    allowed: bool
    reason: str
    rule_applied: Optional[str] = None


class PolicyEngine:
    """
    Deterministic authorization policy evaluation engine.
    Applies explicit declarative rules to verify requester permissions and ownership.
    """

    def __init__(self, policy: AuthorizationPolicy):
        self.policy = policy
        self._rules_by_action = {rule.action: rule for rule in policy.rules}

    def evaluate(self, user: User, action: str, record: StudentRecord) -> PolicyDecision:
        action_upper = action.upper()
        if action_upper not in SUPPORTED_ACTIONS:
            return PolicyDecision(
                allowed=False,
                reason=f"Action '{action}' is not supported by policy engine",
            )

        rule = self._rules_by_action.get(action_upper)
        if not rule:
            return PolicyDecision(
                allowed=False,
                reason=f"No matching policy rule configured for action '{action_upper}'",
            )

        # 1. Role validation
        if user.role not in rule.allowed_roles:
            return PolicyDecision(
                allowed=False,
                reason=f"Forbidden: User role '{user.role}' not in permitted roles {rule.allowed_roles}",
                rule_applied=rule.rule_id,
            )

        # 2. Object ownership validation
        if rule.require_ownership and record.owner_username != user.username:
            return PolicyDecision(
                allowed=False,
                reason=(
                    f"Forbidden: Requester '{user.username}' does not own record "
                    f"'{record.record_id}' (owner: '{record.owner_username}')"
                ),
                rule_applied=rule.rule_id,
            )

        return PolicyDecision(
            allowed=True,
            reason="Authorization granted: Ownership and role constraints satisfied",
            rule_applied=rule.rule_id,
        )


# Default baseline policy enforcing strict object-level ownership on READ
DEFAULT_STUDENT_RECORD_POLICY = AuthorizationPolicy(
    policy_id="POLICY-STUDENT-RECORDS-STRICT",
    rules=[
        PolicyRule(
            rule_id="RULE-STUDENT-READ-OWNER",
            action="READ",
            require_ownership=True,
            allowed_roles=["student", "faculty"],
        ),
        PolicyRule(
            rule_id="RULE-STUDENT-UPDATE-OWNER",
            action="UPDATE",
            require_ownership=True,
            allowed_roles=["student"],
        ),
    ],
)

DEFAULT_POLICY_ENGINE = PolicyEngine(DEFAULT_STUDENT_RECORD_POLICY)
