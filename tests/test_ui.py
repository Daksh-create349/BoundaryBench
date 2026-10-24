import json
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
import pytest
from boundary_bench.advisor import DETERMINISTIC_FALLBACK_TESTS
from boundary_bench.app_secure import app_secure
from boundary_bench.app_vulnerable import app_vulnerable
from boundary_bench.models import SuggestedTestCase, TestRunReport
from boundary_bench.runner import SecurityTestRunner


def test_ui_workflow_headless_vulnerable():
    """
    Test the exact workflow executed by the Streamlit UI:
    1. Select vulnerable app.
    2. Load / generate proposed tests.
    3. Run tests via SecurityTestRunner.
    4. Assert finding detected and report exportable to valid JSON.
    """
    with TestClient(app_vulnerable) as client:
        runner = SecurityTestRunner(client=client, base_url="http://testserver")
        report: TestRunReport = runner.run_tests(DETERMINISTIC_FALLBACK_TESTS)

        assert report.total_tests == 2
        assert report.findings_count == 1
        assert report.failed >= 1

        # Verify JSON export capability
        json_str = report.model_dump_json(indent=2)
        parsed = json.loads(json_str)
        assert parsed["findings_count"] == 1
        assert len(parsed["records"]) == 2
        assert parsed["records"][0]["evidence"]["protected_data_exposed"] is True


def test_ui_workflow_headless_secure():
    """
    Test the exact workflow executed by the Streamlit UI for secure mode:
    1. Select secure app.
    2. Run tests via SecurityTestRunner.
    3. Assert zero findings and authorization enforced.
    """
    with TestClient(app_secure) as client:
        runner = SecurityTestRunner(client=client, base_url="http://testserver")
        report: TestRunReport = runner.run_tests(DETERMINISTIC_FALLBACK_TESTS)

        assert report.total_tests == 2
        assert report.findings_count == 0
        assert report.failed == 0
        assert report.passed == 2

        # Verify JSON export
        json_str = report.model_dump_json(indent=2)
        parsed = json.loads(json_str)
        assert parsed["findings_count"] == 0
        assert parsed["records"][0]["outcome"] == "PASS"
