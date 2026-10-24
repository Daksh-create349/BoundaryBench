from typing import Optional
import httpx
from boundary_bench.models import VerificationResult


def verify_authorization_boundary(
    client: httpx.Client,
    authenticated_user: str,
    target_record_id: str,
    expected_owner: str,
    endpoint_template: str = "/records/{record_id}",
    test_id: str = "AUTH-BOLA-01",
) -> VerificationResult:
    """
    Deterministically test cross-user authorization boundaries.
    
    Inspects BOTH HTTP status code AND returned payload content
    to confirm whether an unauthorized user actually obtained
    another user's private data.
    """
    path = endpoint_template.format(record_id=target_record_id)
    headers = {"x-user": authenticated_user}

    response = client.get(path, headers=headers)
    status_code = response.status_code

    payload = None
    try:
        payload = response.json()
    except Exception:
        pass

    # Inspect authorization outcome:
    # A vulnerability exists ONLY IF:
    # 1. HTTP status is 200 OK
    # 2. Returned payload is valid JSON dictionary
    # 3. Payload matches target record ID
    # 4. Payload belongs to expected_owner and NOT authenticated_user
    if status_code == 200 and isinstance(payload, dict):
        returned_id = payload.get("record_id")
        returned_owner = payload.get("owner_username")

        if returned_id == target_record_id and returned_owner == expected_owner:
            if returned_owner != authenticated_user:
                return VerificationResult(
                    test_id=test_id,
                    target_endpoint=path,
                    authenticated_user=authenticated_user,
                    target_record_id=target_record_id,
                    expected_owner=expected_owner,
                    status_code=status_code,
                    vulnerable=True,
                    payload_received=payload,
                    reason=(
                        f"VULNERABILITY CONFIRMED: User '{authenticated_user}' retrieved "
                        f"private record '{target_record_id}' owned by '{expected_owner}'. "
                        f"Confidential data leaked: gpa={payload.get('gpa')}, notes={payload.get('disciplinary_notes')!r}."
                    ),
                )

        return VerificationResult(
            test_id=test_id,
            target_endpoint=path,
            authenticated_user=authenticated_user,
            target_record_id=target_record_id,
            expected_owner=expected_owner,
            status_code=status_code,
            vulnerable=False,
            payload_received=payload,
            reason="HTTP 200 received but response did not leak target owner's private record.",
        )

    if status_code == 403:
        return VerificationResult(
            test_id=test_id,
            target_endpoint=path,
            authenticated_user=authenticated_user,
            target_record_id=target_record_id,
            expected_owner=expected_owner,
            status_code=status_code,
            vulnerable=False,
            payload_received=payload,
            reason=f"SECURE: Request rejected with 403 Forbidden. User '{authenticated_user}' denied access to '{target_record_id}'.",
        )

    if status_code == 401:
        return VerificationResult(
            test_id=test_id,
            target_endpoint=path,
            authenticated_user=authenticated_user,
            target_record_id=target_record_id,
            expected_owner=expected_owner,
            status_code=status_code,
            vulnerable=False,
            payload_received=payload,
            reason=f"Authentication failed with 401 Unauthorized for user '{authenticated_user}'.",
        )

    return VerificationResult(
        test_id=test_id,
        target_endpoint=path,
        authenticated_user=authenticated_user,
        target_record_id=target_record_id,
        expected_owner=expected_owner,
        status_code=status_code,
        vulnerable=False,
        payload_received=payload,
        reason=f"Unexpected status code {status_code} received.",
    )
