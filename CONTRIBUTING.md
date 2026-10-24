# Contributing to BoundaryBench

Thank you for your interest in contributing to BoundaryBench. BoundaryBench is an open-source, local-first API authorization testing tool designed for developer security auditing and benchmarking.

## 1. Development Environment Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<owner>/BoundaryBench.git
   cd BoundaryBench
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   pip install -e .
   ```

## 2. Pull Request & Branch Guidelines

- Branch naming: `feature/<feature-name>`, `fix/<issue-name>`, or `chore/<task>`.
- Keep pull requests focused on a single change with descriptive commits.
- Ensure all offline tests pass before submitting.
- Avoid modifying core security assertions to make failing checks artificially pass.

## 3. Code Style & Quality

- Python 3.10+ compatible code.
- Strict Pydantic models for any serialized data schemas (`extra = "forbid"`).
- Preserve existing type annotations and docstrings.
- Clean separation between vulnerable test fixtures and hardened production baselines.

## 4. Testing Expectations

- Run the full test suite locally:
  ```bash
  pytest -v
  ```
- Normal unit tests must **never** depend on internet access or a running Ollama daemon. Use mocks or deterministic fixtures.
- Live model tests must be annotated with `@pytest.mark.integration` and guarded by `--run-integration`.

## 5. Adding New Test Types Safely

When introducing new authorization test scenarios (e.g., role-based access, multi-tenant isolation):
1. Add the enum/literal to `boundary_bench.models.SuggestedTestCase`.
2. Add input validation rules and regex constraints in `boundary_bench.advisor.validate_test_safety`.
3. Implement execution and payload inspection logic in `boundary_bench.runner.SecurityTestRunner`.
4. Ensure target endpoints remain restricted to local synthetic paths (`/records/...`). Never allow arbitrary model-supplied paths.
5. Add comprehensive unit tests covering PASS, FAIL, INCONCLUSIVE, and ERROR states.

## 6. Security-Sensitive Contribution Rules

- **Zero Secrets / PII**: Never submit PRs containing real credentials, API tokens, passwords, or personal identity data. Use synthetic demo identities (`alice`, `bob`).
- **Localhost Targets Only**: BoundaryBench is designed strictly for local testing. Contributions enabling arbitrary remote scanning or external target execution will be rejected.
- **Reproducible Evidence**: All vulnerability claims must be supported by observable evidence in the response payload, not model assertions or status codes alone.

## 7. Reporting Bugs

- File an issue using the Bug Report template.
- Include Python version, OS, exact command run, and reproducible output.
