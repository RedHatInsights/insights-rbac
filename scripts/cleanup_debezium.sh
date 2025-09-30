#!/bin/bash

# Debezium Cleanup Script for RBAC
# This script cleans up the Debezium Change Data Capture pipeline

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to stop Debezium services
stop_debezium_services() {
    print_status "Stopping Debezium services..."

    if docker-compose -f docker-compose.debezium.yml ps | grep -q "Up"; then
        docker-compose -f docker-compose.debezium.yml down
        print_success "Debezium services stopped"
    else
        print_warning "Debezium services are not running"
    fi
}

# Function to remove connector
remove_connector() {
    print_status "Removing Debezium connector..."

    # Check if connector exists
    if curl -s -f http://localhost:8083/connectors/rbac-postgres-connector > /dev/null 2>&1; then
        curl -s -X DELETE http://localhost:8083/connectors/rbac-postgres-connector
        print_success "Connector removed"
    else
        print_warning "Connector not found or Kafka Connect not running"
    fi
}

# Function to clean up PostgreSQL replication
cleanup_postgres_replication() {
    print_status "Cleaning up PostgreSQL replication..."

    if docker ps | grep -q rbac_db; then
        # Drop replication slot if it exists
        docker exec rbac_db psql -U postgres -c "SELECT pg_drop_replication_slot('debezium_slot');" 2>/dev/null || print_warning "Replication slot 'debezium_slot' not found"

        # Reset PostgreSQL configuration (optional)
        if [ "${1:-}" = "--reset-postgres" ]; then
            print_status "Resetting PostgreSQL configuration..."
            docker exec rbac_db psql -U postgres -c "ALTER SYSTEM RESET wal_level;" > /dev/null
            docker exec rbac_db psql -U postgres -c "ALTER SYSTEM RESET max_replication_slots;" > /dev/null
            docker exec rbac_db psql -U postgres -c "ALTER SYSTEM RESET max_wal_senders;" > /dev/null
            print_success "PostgreSQL configuration reset"

            print_status "Restarting PostgreSQL..."
            docker-compose restart db > /dev/null 2>&1
            print_success "PostgreSQL restarted"
        fi
    else
        print_warning "PostgreSQL container not running"
    fi
}

# Function to remove Docker network
remove_network() {
    print_status "Removing Docker network..."

    if docker network ls | grep -q rbac-network; then
        # Check if network is in use
        if docker network inspect rbac-network | grep -q '"Containers": {}'; then
            docker network rm rbac-network
            print_success "Docker network removed"
        else
            print_warning "Network 'rbac-network' is still in use by containers"
        fi
    else
        print_warning "Network 'rbac-network' not found"
    fi
}

# Function to clean up volumes (optional)
cleanup_volumes() {
    print_status "Cleaning up Docker volumes..."

    # List and optionally remove Kafka/Debezium related volumes
    local volumes=$(docker volume ls | grep -E "(kafka|debezium|zookeeper)" | awk '{print $2}' || true)

    if [ -n "$volumes" ]; then
        echo "Found the following volumes:"
        echo "$volumes"
        echo ""
        read -p "Do you want to remove these volumes? (y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "$volumes" | xargs docker volume rm
            print_success "Volumes removed"
        else
            print_warning "Volumes preserved"
        fi
    else
        print_warning "No Kafka/Debezium volumes found"
    fi
}

# Function to show status
show_status() {
    echo ""
    echo "========================================"
    echo "📊 Current Status"
    echo "========================================"
    echo ""

    echo "🐳 Docker Containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "(kafka|zookeeper|connect|kafdrop|rbac_db)" || echo "No related containers running"
    echo ""

    echo "🌐 Docker Networks:"
    docker network ls | grep rbac || echo "No rbac networks found"
    echo ""

    echo "💾 Docker Volumes:"
    docker volume ls | grep -E "(kafka|debezium|zookeeper)" || echo "No related volumes found"
    echo ""

    if docker ps | grep -q rbac_db; then
        echo "🔄 PostgreSQL Replication Slots:"
        docker exec rbac_db psql -U postgres -c "SELECT slot_name, plugin, slot_type, active FROM pg_replication_slots;" || true
    fi
}

# Main execution
main() {
    local reset_postgres=false
    local cleanup_vols=false
    local full_cleanup=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --reset-postgres)
                reset_postgres=true
                shift
                ;;
            --cleanup-volumes)
                cleanup_vols=true
                shift
                ;;
            --full)
                reset_postgres=true
                cleanup_vols=true
                full_cleanup=true
                shift
                ;;
            --status)
                show_status
                exit 0
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --reset-postgres     Reset PostgreSQL replication configuration"
                echo "  --cleanup-volumes    Remove Docker volumes (interactive)"
                echo "  --full              Full cleanup (reset postgres + volumes)"
                echo "  --status            Show current status"
                echo "  --help              Show this help message"
                echo ""
                echo "Default behavior (no options):"
                echo "  • Stop Debezium services"
                echo "  • Remove connector"
                echo "  • Drop replication slot"
                echo "  • Keep PostgreSQL configuration"
                echo "  • Keep Docker network and volumes"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    echo "========================================"
    echo "🧹 RBAC Debezium Cleanup Script"
    echo "========================================"
    echo ""

    # Step 1: Remove connector (if Kafka Connect is running)
    remove_connector

    # Step 2: Stop Debezium services
    stop_debezium_services

    # Step 3: Clean up PostgreSQL replication
    if [ "$reset_postgres" = true ]; then
        cleanup_postgres_replication --reset-postgres
    else
        cleanup_postgres_replication
    fi

    # Step 4: Remove network (only if not in use)
    remove_network

    # Step 5: Clean up volumes (if requested)
    if [ "$cleanup_vols" = true ]; then
        cleanup_volumes
    fi

    echo ""
    echo "========================================"
    echo "✅ Cleanup Complete!"
    echo "========================================"
    echo ""

    if [ "$full_cleanup" = false ]; then
        echo "💡 For complete cleanup, run:"
        echo "   $0 --full"
        echo ""
    fi

    echo "📊 To check current status:"
    echo "   $0 --status"
    echo ""
}

# Execute main function
main "$@"
