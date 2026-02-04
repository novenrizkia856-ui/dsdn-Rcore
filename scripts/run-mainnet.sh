#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# DSDN Mainnet Deployment Script
# ═══════════════════════════════════════════════════════════════════════════════
#
# This script starts DSDN Coordinator and Nodes connected to Celestia mainnet.
#
# Prerequisites:
# 1. Celestia light node running and synced to mainnet
# 2. Environment file (.env.mainnet) configured
# 3. TIA tokens available for blob fees
#
# Usage:
#   ./run-mainnet.sh coordinator    # Start coordinator only
#   ./run-mainnet.sh node <n>       # Start node n (1-based)
#   ./run-mainnet.sh all            # Start coordinator + 3 nodes
#   ./run-mainnet.sh stop           # Stop all DSDN processes
#
# ═══════════════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env.mainnet"
PID_DIR="${PROJECT_ROOT}/run"
LOG_DIR="${PROJECT_ROOT}/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check env file exists
    if [[ ! -f "$ENV_FILE" ]]; then
        log_error "Environment file not found: $ENV_FILE"
        log_info "Copy .env.mainnet.example to .env.mainnet and configure it"
        exit 1
    fi

    # Load environment
    set -a
    source "$ENV_FILE"
    set +a

    # Check required variables
    local required_vars=(
        "DA_RPC_URL"
        "DA_NAMESPACE"
        "DA_AUTH_TOKEN"
    )

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            log_error "Required environment variable not set: $var"
            exit 1
        fi
    done

    # Check Celestia light node is running
    log_info "Checking Celestia light node at $DA_RPC_URL..."
    
    if ! curl -s -o /dev/null -w "%{http_code}" "$DA_RPC_URL" | grep -q "200\|405"; then
        log_warn "Cannot reach Celestia light node at $DA_RPC_URL"
        log_warn "Make sure the light node is running and synced"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_info "✅ Celestia light node is reachable"
    fi

    # Create directories
    mkdir -p "$PID_DIR" "$LOG_DIR"
}

check_binary() {
    local binary="$1"
    local target="${PROJECT_ROOT}/target/release/$binary"
    
    if [[ ! -f "$target" ]]; then
        log_warn "Binary not found: $target"
        log_info "Building release binary..."
        cd "$PROJECT_ROOT"
        cargo rustsp build --release --bin "$binary"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# START FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

start_coordinator() {
    log_info "Starting Coordinator..."
    
    check_binary "dsdn-coordinator"
    
    local pid_file="${PID_DIR}/coordinator.pid"
    local log_file="${LOG_DIR}/coordinator.log"
    
    # Check if already running
    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        log_warn "Coordinator already running (PID: $(cat "$pid_file"))"
        return
    fi
    
    # Load environment
    set -a
    source "$ENV_FILE"
    set +a
    
    # Set coordinator-specific vars
    export DA_NETWORK="${DA_NETWORK:-mainnet}"
    export COORDINATOR_HOST="${COORDINATOR_HOST:-0.0.0.0}"
    export COORDINATOR_PORT="${COORDINATOR_PORT:-8080}"
    
    # Start coordinator
    nohup "${PROJECT_ROOT}/target/release/dsdn-coordinator" \
        > "$log_file" 2>&1 &
    
    local pid=$!
    echo "$pid" > "$pid_file"
    
    # Wait and verify it started
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        log_info "✅ Coordinator started (PID: $pid)"
        log_info "   Log: $log_file"
        log_info "   Health: http://${COORDINATOR_HOST}:${COORDINATOR_PORT}/health"
    else
        log_error "Coordinator failed to start. Check $log_file"
        exit 1
    fi
}

start_node() {
    local node_num="$1"
    
    if [[ -z "$node_num" ]]; then
        log_error "Node number required"
        exit 1
    fi
    
    log_info "Starting Node $node_num..."
    
    check_binary "dsdn-node"
    
    local pid_file="${PID_DIR}/node${node_num}.pid"
    local log_file="${LOG_DIR}/node${node_num}.log"
    
    # Check if already running
    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        log_warn "Node $node_num already running (PID: $(cat "$pid_file"))"
        return
    fi
    
    # Load environment
    set -a
    source "$ENV_FILE"
    set +a
    
    # Calculate port offset
    local base_port=${NODE_BASE_PORT:-8090}
    local http_port=$((base_port + node_num - 1))
    
    # Node-specific environment
    export NODE_ID="node-${node_num}"
    export NODE_STORAGE_PATH="${PROJECT_ROOT}/data/node${node_num}"
    export NODE_HTTP_PORT="$http_port"
    export DA_NETWORK="${DA_NETWORK:-mainnet}"
    
    # Create storage directory
    mkdir -p "$NODE_STORAGE_PATH"
    
    # Start node in env mode
    nohup "${PROJECT_ROOT}/target/release/dsdn-node" env \
        > "$log_file" 2>&1 &
    
    local pid=$!
    echo "$pid" > "$pid_file"
    
    # Wait and verify it started
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        log_info "✅ Node $node_num started (PID: $pid)"
        log_info "   Log: $log_file"
        log_info "   Health: http://0.0.0.0:${http_port}/health"
    else
        log_error "Node $node_num failed to start. Check $log_file"
        exit 1
    fi
}

start_all() {
    log_info "Starting all DSDN components..."
    
    start_coordinator
    
    local num_nodes="${NUM_NODES:-3}"
    for i in $(seq 1 "$num_nodes"); do
        start_node "$i"
    done
    
    log_info ""
    log_info "═══════════════════════════════════════════════════════════════"
    log_info "DSDN Mainnet Deployment Complete"
    log_info "═══════════════════════════════════════════════════════════════"
    log_info "Coordinator: http://${COORDINATOR_HOST:-0.0.0.0}:${COORDINATOR_PORT:-8080}"
    for i in $(seq 1 "$num_nodes"); do
        local port=$((${NODE_BASE_PORT:-8090} + i - 1))
        log_info "Node $i:      http://0.0.0.0:${port}"
    done
    log_info ""
    log_info "Use './run-mainnet.sh stop' to stop all processes"
    log_info "═══════════════════════════════════════════════════════════════"
}

# ═══════════════════════════════════════════════════════════════════════════════
# STOP FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

stop_process() {
    local name="$1"
    local pid_file="${PID_DIR}/${name}.pid"
    
    if [[ ! -f "$pid_file" ]]; then
        log_info "$name not running (no PID file)"
        return
    fi
    
    local pid=$(cat "$pid_file")
    
    if kill -0 "$pid" 2>/dev/null; then
        log_info "Stopping $name (PID: $pid)..."
        kill "$pid"
        
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Force killing $name"
            kill -9 "$pid" 2>/dev/null || true
        fi
        
        log_info "✅ $name stopped"
    else
        log_info "$name not running"
    fi
    
    rm -f "$pid_file"
}

stop_all() {
    log_info "Stopping all DSDN components..."
    
    # Stop nodes first
    for pid_file in "${PID_DIR}"/node*.pid; do
        if [[ -f "$pid_file" ]]; then
            local name=$(basename "$pid_file" .pid)
            stop_process "$name"
        fi
    done
    
    # Then stop coordinator
    stop_process "coordinator"
    
    log_info "All DSDN processes stopped"
}

# ═══════════════════════════════════════════════════════════════════════════════
# STATUS FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

show_status() {
    log_info "DSDN Process Status:"
    echo ""
    
    for pid_file in "${PID_DIR}"/*.pid; do
        if [[ -f "$pid_file" ]]; then
            local name=$(basename "$pid_file" .pid)
            local pid=$(cat "$pid_file")
            
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "  ${GREEN}●${NC} $name (PID: $pid) - RUNNING"
            else
                echo -e "  ${RED}●${NC} $name (PID: $pid) - STOPPED"
            fi
        fi
    done
    
    if [[ ! -f "${PID_DIR}"/*.pid ]] 2>/dev/null; then
        echo "  No DSDN processes running"
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  coordinator     Start coordinator only"
    echo "  node <n>        Start node n (1-based)"
    echo "  all             Start coordinator + nodes"
    echo "  stop            Stop all DSDN processes"
    echo "  status          Show process status"
    echo ""
    echo "Environment:"
    echo "  Configure .env.mainnet before running"
    echo ""
}

case "${1:-}" in
    coordinator)
        check_prerequisites
        start_coordinator
        ;;
    node)
        check_prerequisites
        start_node "$2"
        ;;
    all)
        check_prerequisites
        start_all
        ;;
    stop)
        stop_all
        ;;
    status)
        show_status
        ;;
    *)
        usage
        exit 1
        ;;
esac