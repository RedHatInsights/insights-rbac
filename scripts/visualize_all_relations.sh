#!/bin/bash
#
# Visualize all RBAC system role relations
#
# This script:
# 1. Resets all role versions to 1
# 2. Runs seeds with --force-create-relationships
# 3. Pipes output to parse_relations.py for visualization
#
# Usage:
#   ./scripts/visualize_all_relations.sh [--visual|--visual-static] [--show-names]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default options
VISUAL_MODE="--visual-static"
SHOW_NAMES=""
NO_COLOR="--no-color"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --visual)
            VISUAL_MODE="--visual"
            shift
            ;;
        --visual-static)
            VISUAL_MODE="--visual-static"
            shift
            ;;
        --show-names)
            SHOW_NAMES="--show-names"
            shift
            ;;
        --color)
            NO_COLOR=""
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--visual|--visual-static] [--show-names] [--color]"
            exit 1
            ;;
    esac
done

echo "=========================================="
echo "Visualizing RBAC System Role Relations"
echo "=========================================="
echo ""
echo "Step 1: Resetting all role versions to 1..."

cd "$PROJECT_ROOT"
DJANGO_READ_DOT_ENV_FILE=True pipenv run python "$SCRIPT_DIR/reset_role_versions.py" | grep "Reset"

echo ""
echo "Step 2: Running seeds with --force-create-relationships..."
echo ""

DJANGO_READ_DOT_ENV_FILE=True RBAC_LOG_RELATIONS=true pipenv run python rbac/manage.py seeds --force-create-relationships 2>&1 \
    | "$SCRIPT_DIR/parse_relations.py" $VISUAL_MODE $SHOW_NAMES $NO_COLOR
