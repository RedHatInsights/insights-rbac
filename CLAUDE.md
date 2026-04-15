@AGENTS.md

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. Architecture, patterns, and domain guidelines are in AGENTS.md and the docs/*-guidelines.md files -- this file contains only Claude Code-specific commands and behaviors.

## Common Commands

### Testing

Django's test runner requires **dotted module paths**, not file paths. If `tox` is not on PATH, use `pipenv run tox`.

```bash
# Run all tests (with coverage)
pipenv run tox -e py312

# Run all tests without coverage (faster)
pipenv run tox -e py312-fast

# Run a specific test module
pipenv run tox -e py312-fast -- tests.management.workspace.test_view

# Run a specific test class
pipenv run tox -e py312-fast -- tests.management.workspace.test_view.WorkspaceTestsList

# Run a single test method
pipenv run tox -e py312-fast -- tests.management.workspace.test_view.WorkspaceTestsList.test_workspace_list_unfiltered
```

### Linting and Formatting
```bash
pipenv run tox -e lint                             # flake8 + black --check
pipenv run black -t py312 -l 119 rbac tests        # auto-format
```

### Local Development
```bash
# Docker (starts app on port 9080 + postgres + redis + celery)
make docker-up
make docker-logs
make docker-down

# Local python (app on port 8000, needs Docker for DB)
make start-db           # Postgres container on port 15432
make run-migrations
make serve
```

### Database
```bash
make make-migrations     # Generate new migration files
make run-migrations      # Apply migrations
make reinitdb            # Drop + recreate + migrate
psql postgres -U postgres -h localhost -p 15432  # Direct DB access
```

### OpenAPI Spec
```bash
make generate_v2_spec    # Regenerate v2 spec from TypeSpec (requires TypeSpec installed in docs/source/specs/typespec/)
```

## Pre-commit Hooks

The `.pre-commit-config.yaml` enforces:
- flake8 (line length 120)
- black (line length 119, target py312, check mode)
- trailing-whitespace, end-of-file-fixer, debug-statements
- django-upgrade (target 5.2)
- openapi-spec-validator

Run manually: `pipenv run pre-commit run --all-files`

## Claude Code Behavioral Preferences

- Do NOT include `Co-Authored-By` lines in commits
- Before running tests or linters, verify the database is running with `pg_isready -h localhost -p 15432`
- Always format code with black before creating commits
- Use dotted module paths for test commands, never file paths
