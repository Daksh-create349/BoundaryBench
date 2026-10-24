import argparse
import sys
import httpx
from fastapi.testclient import TestClient
from boundary_bench.advisor import (
    DETERMINISTIC_FALLBACK_TESTS,
    check_ollama_available,
    get_installed_models,
    suggest_authorization_tests,
)
from boundary_bench.app_secure import app_secure
from boundary_bench.app_vulnerable import app_vulnerable
from boundary_bench.runner import SecurityTestRunner
from boundary_bench.verifier import verify_authorization_boundary


def main():
    parser = argparse.ArgumentParser(
        description="BoundaryBench: Deterministic API Authorization Boundary Testing"
    )
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure", "both"],
        default="both",
        help="Target API mode to test (default: both)",
    )
    parser.add_argument(
        "--ai-suggest",
        action="store_true",
        help="Ask local Gemma 4 E2B via Ollama to suggest boundary tests",
    )
    parser.add_argument(
        "--export-report",
        type=str,
        default=None,
        help="Path to export JSON report file",
    )
    args = parser.parse_args()

    print("=" * 60)
    print(" BoundaryBench - API Authorization Testing")
    print("=" * 60)

    suggested_tests = None
    if args.ai_suggest:
        print("[AI Advisor] Connecting to local Ollama...")
        available = check_ollama_available()
        print(f"  Ollama Server Reachable: {available}")
        if available:
            models = get_installed_models()
            print(f"  Installed models: {', '.join(models) if models else 'None'}")
        advisor_res = suggest_authorization_tests()
        print(f"  Source: {advisor_res.get('source')}")
        if "reason" in advisor_res:
            print(f"  Note: {advisor_res.get('reason')}")
        suggested_tests = advisor_res.get("tests", [])
        print(f"  Generated Tests ({len(suggested_tests)}):")
        for idx, t in enumerate(suggested_tests, 1):
            print(f"    [{idx}] {t.test_type}: user='{t.authenticated_user}' -> '{t.target_record_id}' (owner: '{t.expected_owner}')")
        print("-" * 60)

    modes_to_test = ["vulnerable", "secure"] if args.mode == "both" else [args.mode]
    tests_to_run = suggested_tests if suggested_tests else DETERMINISTIC_FALLBACK_TESTS

    all_reports = []
    for mode in modes_to_test:
        app = app_vulnerable if mode == "vulnerable" else app_secure
        print(f"\n[Testing Mode: {mode.upper()}]")

        with TestClient(app) as client:
            runner = SecurityTestRunner(client=client, base_url="http://testserver")
            report = runner.run_tests(tests_to_run)
            all_reports.append(report)

            print(f"  Summary: {report.total_tests} tests | PASS: {report.passed} | FAIL: {report.failed} | FINDINGS: {report.findings_count}")
            for rec in report.records:
                flag = "[VULNERABILITY FOUND]" if rec.finding_detected else "[OK]"
                print(f"    - {rec.test_id} -> Outcome: {rec.outcome} {flag}")
                print(f"      Observed: {rec.observed_behavior}")
                if rec.evidence.protected_data_exposed:
                    print(f"      Exposed data: {rec.evidence.exposed_fields}")

    if args.export_report:
        import json
        export_data = [r.model_dump() for r in all_reports]
        with open(args.export_report, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        print(f"\n[Report Exported] Saved JSON report to: {args.export_report}")

    print("\n" + "=" * 60)
    print(" Boundary testing complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
