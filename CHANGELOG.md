# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-24

### Added
- **Core Models**: Strict Pydantic models for `User`, `StudentRecord`, `SuggestedTestCase`, `SanitizedEvidence`, `TestExecutionRecord`, and `TestRunReport`.
- **Demo APIs**:
  - `app_vulnerable`: Intentionally vulnerable FastAPI fixture exhibiting Broken Object Level Authorization (BOLA/IDOR).
  - `app_secure`: Hardened FastAPI endpoint enforcing object-level authorization via `PolicyEngine`.
- **Declarative Policy Engine**: `boundary_bench.policy` supporting strict schema validation, ownership rules, and role constraints.
- **AI Advisor**: Local Ollama connector targeting `gemma4:e2b` with prompt-based structured generation and deterministic offline fallback.
- **Deterministic Test Runner**: `SecurityTestRunner` enforcing local target restriction (`testserver`, `localhost`, `127.0.0.1`), request limits, secret sanitization, payload inspection, and standardized outcome classifications (`PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR`).
- **Interfaces**:
  - Command-line runner (`boundary_bench.cli`) with test execution and JSON report export (`--export-report`).
  - Interactive web interface (`boundary_bench.ui`) built with Streamlit providing live scenario review, execution, and JSON export.
- **Automated Test Suite**: 39 automated tests covering API endpoints, policy enforcement, runner boundaries, error handling, mocked AI responses, and opt-in real Gemma 4 integration.
