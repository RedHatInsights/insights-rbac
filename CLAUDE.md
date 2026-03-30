# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Insights RBAC is a Role Based Access Control service for Red Hat Insights. It's a Django REST API application that manages roles, permissions, groups, and access control for cloud.redhat.com services. The project uses Python 3.12, Django 4.2, PostgreSQL, and Redis.

## Development Commands

### Environment Setup
```bash
# Install dependencies and create virtual environment
pipenv install --dev
pipenv shell

# Copy environment file
cp .env.example .env
```

### Database Operations
```bash
# Start PostgreSQL container
make start-db

# Run migrations
make run-migrations

# Reset and reinitialize database
make reinitdb

# Create Django migrations
make make-migrations

# Show migration status
make show-migrations

# Access database directly
psql postgres -U postgres -h localhost -p 15432

# Django shell access
make shell

# Create Django superuser
make user
```

### Development Server
```bash
# Run development server (default port 8000)
make serve

# Run on specific port
make PORT=8111 serve

# Run with gunicorn
make gunicorn-serve
```

### Testing and Quality
```bash
# Run all tests (rebuilds tox environment)
tox -r

# Run unit tests with coverage
tox -e py312

# Run unit tests without coverage (faster)
tox -e py312-fast

# Run tests and show slowest tests
tox -e py312-profile

# Run specific test file
tox -e py312 -- tests.api.test_models

# Run specific test class
tox -e py312 -- tests.api.test_models.RoleModelTests

# Run specific test method
tox -e py312 -- tests.api.test_models.RoleModelTests.test_role_create

# Run specific test with --keepdb (faster, reuses test database)
tox -e py312 -- tests.api.test_models.RoleModelTests.test_role_create --keepdb

# Run tests using Django manage.py directly
python rbac/manage.py test tests.api.test_models

# Run tests in parallel with failfast
coverage run rbac/manage.py test --parallel --failfast -v 2 tests/

# Make targets for testing
make unittest           # Run tests with coverage
make unittest-fast      # Run tests without coverage (faster)
make unittest-profile   # Run tests showing slowest tests

# Run linting
make lint
tox -e lint

# Run type checking
make typecheck
tox -e mypy

# Format code
make format
```

**Note**: Tests expect PostgreSQL on port 15432 (configured in `tox.ini` and `docker-compose.yml`).

### Docker Environment
```bash
# Start all services (Django + PostgreSQL + Redis + Celery worker + Celery scheduler)
make docker-up

# View logs
make docker-logs

# Shell access to server container (for pdb debugging)
make docker-shell

# Stop all containers
make docker-down

# Stop docker-compose services only
make stop-compose

# Run security checks on images
make docker-grype
```

### Kafka Consumer
```bash
# Run Kafka consumer
make kafka-consumer

# Run with debug logging
make kafka-consumer-debug

# Run with custom Kafka broker (for external Kafka)
RBAC_KAFKA_CUSTOM_CONSUMER_BROKER=localhost:9092 make kafka-consumer
```

### Debezium + Kafka Setup (Change Data Capture)
```bash
# Complete automated setup - recommended
./scripts/debezium/setup_debezium.sh

# Show help and options
./scripts/debezium/setup_debezium.sh --help

# Run Kafka consumer
./scripts/debezium/setup_debezium.sh --consumer              # Interactive mode
./scripts/debezium/setup_debezium.sh --consumer-bg           # Background mode

# Send test message
./scripts/debezium/send_test_relations_message.sh

# Cleanup commands
./scripts/debezium/cleanup_debezium.sh              # Basic cleanup
./scripts/debezium/cleanup_debezium.sh --full       # Complete cleanup
./scripts/debezium/cleanup_debezium.sh --status     # Show current status

# Configuration files
# - scripts/debezium/debezium-connector-config.json  # Debezium connector configuration
# - docker-compose.debezium.yml                      # Kafka/Zookeeper/Connect services

# Monitor Kafka topics and messages
# - Kafdrop UI: http://localhost:9001
# - Kafka Connect API: http://localhost:8083

# The setup script will automatically:
# 1. Create Docker/Podman network
# 2. Start and configure PostgreSQL with logical replication
# 3. Start Kafka, Zookeeper, Kafka Connect, and Kafdrop services
# 4. Create Debezium connector from config file
# 5. Create RBAC replication topic
# 6. Generate helper scripts (test_kafka_consumer.sh, run_kafka_consumer.sh, send_test_relations_message.sh)
```

## Project Architecture

### Application Structure
- **rbac/**: Main Django project directory
  - **rbac/**: Django settings and configuration
  - **api/**: External API endpoints (cross-account requests, status)
  - **management/**: Core RBAC management (roles, groups, permissions, principals)
  - **internal/**: Internal API endpoints
  - **core/**: Shared utilities and Kafka consumers (see `kafka_consumer.py` for CDC processing)
  - **migration_tool/**: Data migration utilities for Kessel relations

### Celery Integration
- **rbac-worker**: Celery worker container for async task processing
- **rbac-scheduler**: Celery beat scheduler for periodic tasks
- **Redis**: Message broker for Celery (port 6379)

### Key Management Apps
- **management/role/**: Role management and definitions
- **management/group/**: Group management and membership
- **management/permission/**: Permission definitions and assignments
- **management/principal/**: User principal management
- **management/policy/**: Access policy management
- **management/workspace/**: Workspace-based access control
- **management/tenant_mapping/**: Multi-tenant organization mapping

### API Structure
- **v1 API**: `/api/rbac/v1/` - Primary stable API
- **v2 API**: `/api/rbac/v2/` - Newer API features (when V2_APIS_ENABLED=True)
- **Internal API**: `/_private/` - Internal service endpoints

### Database
- PostgreSQL primary database (version 14.5+)
- Multi-tenant architecture using django-tenants
- Redis for caching and session storage
- Parallel migrations supported with environment variables
- Docker and Podman both supported (scripts auto-detect runtime)

### Key Features
- **Multi-tenancy**: Organization-based data isolation using django-tenants
- **Service-to-Service Auth**: PSK and JWT support for internal services
- **Feature Flags**: Unleash integration for gradual rollouts
- **Seeding**: Automatic role/group/permission seeding from JSON configurations
- **Kafka Integration**: Event streaming for replication and notifications
- **Debezium CDC**: Change Data Capture for real-time database event streaming (see `docs/KAFKA_CONSUMER.md`)
- **Kessel Relations**: Migration tool for converting to relations-based model

### Core RBAC Model Relationships
- **Principal**: A user (identified by username) belonging to a tenant
- **Permission**: An application:resource:operation tuple (e.g., `inventory:hosts:read`)
- **Role**: A named collection of permissions (can be system-defined or custom)
- **Group**: A collection of principals that can be assigned roles
- **Policy**: Links groups to roles, granting permissions to group members
- **Workspace**: Hierarchical access control boundaries (when V2 enabled)

### Authentication & Authorization
- **x-rh-identity header**: Required for all requests (added by gateway in production)
  - Header contains principal info (tenant, username, account_number, is_org_admin, etc.)
  - Gateway automatically adds this header to all authenticated requests through Akamai/3scale
  - Service-to-service requests not going through gateway must add this header manually
  - Not reflected in openapi.json spec to avoid requiring it for cloud.redhat.com clients
- **Development mode**: Mock identity header automatically set in `rbac/rbac/dev_middleware.py`
  - Modify `username` (line 62) to simulate different users
  - Change `account_number` (line 57) to create new tenants
  - Change `org_id` (line 58) for organization-specific testing
  - Toggle `is_org_admin` (line 63) between `True`/`False` for permission testing
- **Service auth**: PSK authentication for service-to-service requests
- **JWT support**: JWT token validation for service requests

### Testing
- Tests located in `tests/` directory matching source structure
- Use `tox -e py312` for standard test runs with coverage
- Use `tox -e py312-fast` for faster test runs without coverage
- Use `tox -e py312-profile` to identify slow tests
- Add `--keepdb` to reuse test database for faster iteration
- Tox environments: py312 (tests), lint (code quality), mypy (type checking)
- Parallel test execution supported

### Configuration
- Environment variables in `.env` file
- Database settings in `rbac/rbac/database.py`
- Feature flags configuration via Unleash
- Multi-environment support (development, staging, production)

## TypeSpec API Generation

OpenAPI v2 specification is generated from TypeSpec files:
- Source: `docs/source/specs/typespec/main.tsp`
- Output: `docs/source/specs/v2/openapi.yaml` and `openapi.json`

```bash
# Generate v2 spec (requires TypeSpec installation in docs/source/specs/typespec/)
# Install TypeSpec: https://typespec.io/docs
make generate_v2_spec
```

## Seeds and Default Data

Default roles and groups are automatically seeded unless disabled by setting environment variables:
- `PERMISSION_SEEDING_ENABLED=False`
- `ROLE_SEEDING_ENABLED=False`
- `GROUP_SEEDING_ENABLED=False`

```bash
# Manual seeding (disable signals recommended)
ACCESS_CACHE_CONNECT_SIGNALS=False MAX_SEED_THREADS=2 ./rbac/manage.py seeds [--roles|--groups|--permissions]

# Quick seeding via make
make seeds

# Force update relations during seeding
make seeds-force-update
```

## Common Development Patterns

- Use Django REST Framework viewsets and serializers
- Follow multi-tenant patterns with tenant-aware querysets
- Implement proper permission checks in viewsets
- Use manager classes in `management/managers.py` for complex queries
- Cache frequently accessed data using management/cache.py
- Log important events for audit trails
- Seed data is sourced from `/rbac/management/role/definitions/*.json` locally
- For deployed instances, seed data comes from the [rbac-config repo](https://github.com/RedHatInsights/rbac-config.git)

## Pre-commit Hooks

The repository uses pre-commit hooks for code quality:
```bash
# Install pre-commit hooks
pre-commit install

# Manual run (all files)
pre-commit run --all-files
```

Code is automatically formatted with Black and linted with Flake8 on commit.

## Important Configuration Notes

### Service-to-Service Authentication
For testing PSK authentication locally:
1. Comment out the identity header setting in `rbac/rbac/dev_middleware.py:72`
2. Start server with PSK configuration:
   ```bash
   make serve SERVICE_PSKS='{"catalog": {"secret": "abc123"}}'
   ```
3. Test with headers:
   ```bash
   curl http://localhost:8000/api/rbac/v1/roles/ -H 'x-rh-rbac-psk: abc123' -H 'x-rh-rbac-org-id: 10001' -H 'x-rh-rbac-client-id: catalog'
   ```

### Feature Flags (Unleash)
```bash
# Local Unleash configuration
FEATURE_FLAGS_TOKEN=your_token
FEATURE_FLAGS_URL=http://localhost:4242/api
FEATURE_FLAGS_CACHE_DIR=/tmp/unleash_cache
```

### Parallel Migrations
```bash
# Configure parallel migration processing
TENANT_PARALLEL_MIGRATION_MAX_PROCESSES=4 TENANT_PARALLEL_MIGRATION_CHUNKS=2 ./rbac/manage.py migrate
```

### Ephemeral Cluster Commands
```bash
# Build and deploy to ephemeral cluster
make ephemeral-build
make ephemeral-deploy

# List RBAC pods in ephemeral cluster
make ephemeral-pods

# Port forward RBAC service (default port 9080)
make ephemeral-pf-rbac

# Reserve namespace (default 24h, override with HOURS="12h")
make ephemeral-reserve

# Release reserved namespace
make ephemeral-release
```

### Utility Commands
```bash
# Show Django URLs
make urls

# Clean project directory
make clean

# Generate HTML documentation
make html

# Create test database dump
make create-test-db-file
```

### Relations Migration
```bash
# Migrate RBAC data to Kessel relations format
DJANGO_READ_DOT_ENV_FILE=True ./rbac/manage.py migrate_relations [--org-list ORG_LIST [ORG_LIST ...]] [--exclude-apps EXCLUDE_APPS [EXCLUDE_APPS ...]] [--write-to-db]
```

## Kafka Consumer Details

The RBAC Kafka consumer (`rbac/core/kafka_consumer.py`) processes change data capture events from Debezium. See `docs/KAFKA_CONSUMER.md` for comprehensive documentation including message validation, retry logic, health monitoring, and Prometheus metrics.

Key implementation notes:
- Messages are processed sequentially within partitions to maintain ordering
- Failed messages block subsequent processing until resolved (no skipping)
- Manual offset commits ensure exactly-once processing
- Background health checks work during idle periods

## Known Issues

### SELinux and PostgreSQL Container
On Linux with SELinux enabled, you may see: `"mkdir: cannot create directory '/var/lib/pgsql/data/userdata': Permission denied"`

**Solution**: Grant `./pg_data` ownership to uid:26 (postgres user in the container)

### Database Connection in Tests
Test environment uses specific database settings (see `tox.ini`):
- Host: localhost:15432 (matches docker-compose port mapping)
- Database: postgres
- User/Password: postgres

## Quick API Testing

With development middleware enabled (default), requests automatically get mock identity headers:
```bash
# List roles
curl http://localhost:8000/api/rbac/v1/roles/

# List groups
curl http://localhost:8000/api/rbac/v1/groups/

# Get access for current user
curl http://localhost:8000/api/rbac/v1/access/

# Check permissions for an application
curl "http://localhost:8000/api/rbac/v1/access/?application=inventory"
```
