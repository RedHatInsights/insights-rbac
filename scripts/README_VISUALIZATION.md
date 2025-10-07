# RBAC Relations Visualization

This directory contains scripts for visualizing RBAC system role relations.

## Quick Start

### Using Make Commands (Recommended)

The easiest way to visualize relations:

```bash
# Visual graph (static display at end)
make seeds-relations-visual

# Compact zed format
make seeds-relations

# Execute to SpiceDB
make seeds-relations-execute

# Visual graph with SpiceDB execution
make seeds-relations-visual-execute
```

**All make commands automatically reset role versions before running.**

### Using Scripts Directly

To visualize all system role relations in a static graph:

```bash
./scripts/visualize_all_relations.sh
```

This will:
1. Reset all role versions to force recreation
2. Run seeds with `--force-create-relationships`
3. Display a complete graph of all role relations

## Scripts

### `visualize_all_relations.sh`

Main entry point for visualizing all relations. Combines version reset and visualization.

**Usage:**
```bash
# Static visualization (default)
./scripts/visualize_all_relations.sh

# Dynamic visualization (updates as relations are created)
./scripts/visualize_all_relations.sh --visual

# Show resource names from database
./scripts/visualize_all_relations.sh --show-names

# Enable colored output
./scripts/visualize_all_relations.sh --color
```

**Options:**
- `--visual`: Dynamic mode - updates graph as relations are created
- `--visual-static`: Static mode (default) - shows final graph once
- `--show-names`: Fetch and display resource names from database
- `--color`: Enable syntax highlighting (disabled by default for piping)

## Running Server with Relation Logging

The `serve-*` commands run the Django server and parse relation output in real-time:

```bash
# Run server with compact relation logging (filters out seeding messages)
make serve-execute

# Run server with visual graph updates
make serve-visual

# Run server with visual graph and SpiceDB execution
make serve-visual-execute
```

**Note**: All `serve-*` commands use `--filter-seeds` to hide seeding-related log messages, showing only clean relation output from API requests.

### `reset_role_versions.py`

Resets all system role versions to 1, forcing the next seeds run to update all roles.

**Usage:**
```bash
DJANGO_READ_DOT_ENV_FILE=True pipenv run python scripts/reset_role_versions.py
```

**Why needed:**
The `--force-create-relationships` flag only creates relations for roles that have changed (version mismatch). By resetting all versions to 1, every role will be updated and all relations recreated.

### `parse_relations.py`

Parses relation output from logs and provides various output formats.

**Usage:**
```bash
# Extract and colorize relations from seeds output
DJANGO_READ_DOT_ENV_FILE=True RBAC_LOG_RELATIONS=true pipenv run python rbac/manage.py seeds --force-create-relationships 2>&1 \
  | ./scripts/parse_relations.py --zed --compact --show-names

# Visual static mode
... | ./scripts/parse_relations.py --visual-static --no-color

# Visual dynamic mode
... | ./scripts/parse_relations.py --visual --show-names
```

**Options:**
- `--zed`: Convert to zed command format
- `--compact`: Show compact format (resource relation subject)
- `--visual`: Display as dynamic ASCII graph (updates during processing)
- `--visual-static`: Display as static ASCII graph (once at end)
- `--show-names`: Fetch resource names from database
- `--no-color`: Disable syntax highlighting
- `--execute`: Execute zed commands (requires `--zed`)
- `--quiet`: Suppress headers

**Output Modes:**
- **Raw**: Shows relations in original format
- **Zed**: Converts to `zed relationship touch` commands
- **Compact**: Shows `resource relation subject` only
- **Visual**: ASCII graph with hierarchy visualization

## Understanding the Output

### Graph Statistics

The visualization shows:
- **Nodes**: Total unique roles that have relations
- **Edges**: Total relation connections
- **Roots**: Top-level roles (default groups' policies)

### Expected Numbers

- **77 total system roles** in database
- **73 roles with relations** (shown in graph)
- **299 total relations** created
- **25 root nodes** (2 default group policies + 23 standalone roles)

### Why some roles don't appear

4 roles don't appear in the graph because they have:
- No access permissions defined
- No parent-child relationships (not admin_default or platform_default)

These are:
- OCM Cluster Editor
- OCM Idp Editor
- OCM Machine Pool Editor
- OCM Cluster Autoscaler Editor

## Workflow for Testing

When testing relation creation:

1. **Reset versions** (required before each test run):
   ```bash
   DJANGO_READ_DOT_ENV_FILE=True pipenv run python scripts/reset_role_versions.py
   ```

2. **Run seeds with logging**:
   ```bash
   DJANGO_READ_DOT_ENV_FILE=True RBAC_LOG_RELATIONS=true pipenv run python rbac/manage.py seeds --force-create-relationships
   ```

3. **Or use the combined script**:
   ```bash
   ./scripts/visualize_all_relations.sh
   ```

## Troubleshooting

### "Only seeing 20 roles on second run"

This happens because role versions haven't been reset. After the first run, roles are updated to their JSON versions, so subsequent runs with `--force-create-relationships` skip unchanged roles.

**Solution**: Always reset versions before testing:
```bash
DJANGO_READ_DOT_ENV_FILE=True pipenv run python scripts/reset_role_versions.py
```

### "Names not showing in visual mode"

The `--show-names` flag requires Django access. When piping from `manage.py seeds`, the parse script runs in a separate process and can't access the parent's Django connection.

**Solution**: This is expected behavior. Names work when running the script directly against log files.

### "Graph shows 73 nodes but expecting 77"

This is correct. The graph only shows roles that have actual relations (permissions or parent-child relationships). 4 OCM roles have no relations defined yet.
