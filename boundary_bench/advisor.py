import json
import logging
import re
from typing import Any, Dict, List, Optional
import httpx
from boundary_bench.models import AdvisorResponse, SuggestedTestCase

logger = logging.getLogger("boundary_bench.advisor")

DEFAULT_MODEL = "gemma4:e2b"
OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_TIMEOUT_SECONDS = 35.0

# Whitelisted synthetic entities
ALLOWED_USERS = {"alice", "bob"}
ALLOWED_RECORDS = {"rec-alice-101", "rec-bob-202"}
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9_-]{2,32}$")
SAFE_RECORD_PATTERN = re.compile(r"^rec-[a-z0-9_-]{1,32}$")

DETERMINISTIC_FALLBACK_TESTS: List[SuggestedTestCase] = [
    SuggestedTestCase(
        test_type="BOLA_CROSS_USER",
        authenticated_user="alice",
        target_record_id="rec-bob-202",
        expected_owner="bob",
        description="Deterministic BOLA check: Alice reads Bob private record.",
        expected_status_code=403,
    ),
    SuggestedTestCase(
        test_type="OWNER_SELF_READ",
        authenticated_user="alice",
        target_record_id="rec-alice-101",
        expected_owner="alice",
        description="Deterministic baseline: Alice reads own student record.",
        expected_status_code=200,
    ),
]


def check_ollama_available(base_url: str = OLLAMA_BASE_URL, timeout: float = 2.0) -> bool:
    """Check if local Ollama server is running and reachable."""
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base_url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


def get_installed_models(base_url: str = OLLAMA_BASE_URL, timeout: float = 2.0) -> List[str]:
    """List locally installed model tags in Ollama."""
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base_url}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                return [m.get("name") for m in data.get("models", []) if "name" in m]
    except Exception:
        pass
    return []


def extract_json_from_text(text: str) -> Optional[str]:
    """
    Safely extract JSON object from LLM response text,
    handling markdown blocks or surrounding thinking text.
    """
    cleaned = text.strip()
    if "```json" in cleaned:
        parts = cleaned.split("```json", 1)[1].split("```", 1)
        cleaned = parts[0].strip()
    elif "```" in cleaned:
        parts = cleaned.split("```", 1)[1].split("```", 1)
        cleaned = parts[0].strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start : end + 1]
    return None


def validate_test_safety(test: SuggestedTestCase) -> None:
    """
    Verify test case parameters to prevent code injection, path traversal,
    or arbitrary HTTP targets.
    """
    # 1. Enforce identifier formatting
    if not SAFE_IDENTIFIER_PATTERN.match(test.authenticated_user):
        raise ValueError(f"Unsafe authenticated_user identifier: {test.authenticated_user!r}")
    if not SAFE_IDENTIFIER_PATTERN.match(test.expected_owner):
        raise ValueError(f"Unsafe expected_owner identifier: {test.expected_owner!r}")
    if not SAFE_RECORD_PATTERN.match(test.target_record_id):
        raise ValueError(f"Unsafe target_record_id format: {test.target_record_id!r}")

    # 2. Reject path traversal sequences or special characters
    forbidden_tokens = ["..", "/", "\\", "\x00", "<", ">", ";", "&", "|", "$"]
    for token in forbidden_tokens:
        if token in test.target_record_id or token in test.authenticated_user:
            raise ValueError(f"Dangerous token '{token}' in test parameters")

    # 3. Known synthetic user boundary check
    if test.authenticated_user not in ALLOWED_USERS:
        raise ValueError(f"Unknown synthetic user: {test.authenticated_user}")
    if test.expected_owner not in ALLOWED_USERS:
        raise ValueError(f"Unknown synthetic expected owner: {test.expected_owner}")
    if test.target_record_id not in ALLOWED_RECORDS:
        raise ValueError(f"Unknown synthetic target record: {test.target_record_id}")


def build_system_prompt() -> str:
    return (
        "You are an API security testing assistant for BoundaryBench.\n"
        "Demo API Specification:\n"
        "- Endpoint: GET /records/{record_id}\n"
        "- Authentication: HTTP header 'x-user: <username>'\n"
        "- Synthetic users:\n"
        "  * 'alice' (owns record 'rec-alice-101')\n"
        "  * 'bob' (owns record 'rec-bob-202')\n"
        "- Authorization Rule: Users may only access records they own (HTTP 200). "
        "Cross-user access must be denied with HTTP 403.\n\n"
        "Task: Suggest 2 structured authorization test cases:\n"
        "1. A BOLA/IDOR cross-user test (e.g. Alice attempts to access Bob's record)\n"
        "2. An owner self-read test (Alice reads Alice's record)\n\n"
        "Allowed test_type values: 'BOLA_CROSS_USER', 'OWNER_SELF_READ'.\n"
        "Respond ONLY with a JSON object matching this exact schema:\n"
        "{\n"
        '  "tests": [\n'
        "    {\n"
        '      "test_type": "BOLA_CROSS_USER",\n'
        '      "authenticated_user": "alice",\n'
        '      "target_record_id": "rec-bob-202",\n'
        '      "expected_owner": "bob",\n'
        '      "description": "Alice attempts to access Bob private student record",\n'
        '      "expected_status_code": 403\n'
        "    },\n"
        "    {\n"
        '      "test_type": "OWNER_SELF_READ",\n'
        '      "authenticated_user": "alice",\n'
        '      "target_record_id": "rec-alice-101",\n'
        '      "expected_owner": "alice",\n'
        '      "description": "Alice legitimately reads own student record",\n'
        '      "expected_status_code": 200\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "Do not include explanation or Markdown outside the JSON."
    )


def suggest_authorization_tests(
    base_url: str = OLLAMA_BASE_URL,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """
    Query local Gemma 4 E2B via Ollama.
    Validates strictly via Pydantic and safety rules.
    Falls back gracefully to deterministic test cases if Ollama is
    unavailable, fails, or produces malformed output.
    """
    if not check_ollama_available(base_url, timeout=2.0):
        return {
            "source": "deterministic-fallback",
            "reason": f"Ollama server not reachable at {base_url}",
            "tests": DETERMINISTIC_FALLBACK_TESTS,
        }

    installed = get_installed_models(base_url, timeout=2.0)
    if model not in installed:
        return {
            "source": "deterministic-fallback",
            "reason": f"Model tag '{model}' not found in local Ollama tags: {installed}",
            "tests": DETERMINISTIC_FALLBACK_TESTS,
        }

    prompt = build_system_prompt()
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 1500,
        },
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{base_url}/api/generate", json=payload)
            if resp.status_code != 200:
                return {
                    "source": "deterministic-fallback",
                    "reason": f"Ollama HTTP error {resp.status_code}: {resp.text[:100]}",
                    "tests": DETERMINISTIC_FALLBACK_TESTS,
                }

            data = resp.json()
            raw_response = data.get("response", "")

            json_text = extract_json_from_text(raw_response)
            if not json_text:
                return {
                    "source": "deterministic-fallback",
                    "reason": "Could not extract valid JSON object from model response",
                    "raw_response": raw_response[:200],
                    "tests": DETERMINISTIC_FALLBACK_TESTS,
                }

            # Pydantic validation
            parsed_response = AdvisorResponse.model_validate_json(json_text)

            # Strict safety checks on each test case
            validated_tests: List[SuggestedTestCase] = []
            for test in parsed_response.tests:
                validate_test_safety(test)
                validated_tests.append(test)

            return {
                "source": f"ollama:{model}",
                "tests": validated_tests,
            }

    except Exception as e:
        return {
            "source": "deterministic-fallback",
            "reason": f"Advisor execution failed: {type(e).__name__}: {str(e)}",
            "tests": DETERMINISTIC_FALLBACK_TESTS,
        }
