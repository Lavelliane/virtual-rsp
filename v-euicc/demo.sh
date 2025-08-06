#!/bin/bash

# Virtual eUICC Demo Script
# This script demonstrates how to use the virtual eUICC system with lpac

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
V_EUICC_SOCKET="/tmp/v-euicc-demo.sock"
V_EUICC_PORT=8765
LPAC_PATH="../lpac"

echo -e "${BLUE}╔════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Virtual eUICC Demo           ║${NC}"
echo -e "${BLUE}║     SGP.22 eSIM Development        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════╝${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait for server to start
wait_for_server() {
    local socket_path="$1"
    local max_attempts=30
    local attempt=0
    
    echo -e "${YELLOW}Waiting for virtual eUICC server to start...${NC}"
    while [ $attempt -lt $max_attempts ]; do
        if [ -S "$socket_path" ]; then
            echo -e "${GREEN}✓ Virtual eUICC server is ready${NC}"
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
        echo -n "."
    done
    echo ""
    echo -e "${RED}✗ Failed to connect to virtual eUICC server${NC}"
    return 1
}

# Function to cleanup background processes
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if [ ! -z "$V_EUICC_PID" ]; then
        kill $V_EUICC_PID 2>/dev/null || true
        wait $V_EUICC_PID 2>/dev/null || true
    fi
    rm -f "$V_EUICC_SOCKET"
    echo -e "${GREEN}✓ Cleanup completed${NC}"
}

trap cleanup EXIT

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

if ! command_exists gcc; then
    echo -e "${RED}✗ gcc not found. Please install a C compiler.${NC}"
    exit 1
fi

if ! command_exists make; then
    echo -e "${RED}✗ make not found. Please install make.${NC}"
    exit 1
fi

if [ ! -d "$LPAC_PATH" ]; then
    echo -e "${RED}✗ lpac directory not found at $LPAC_PATH${NC}"
    echo -e "${YELLOW}Please ensure lpac is available in the parent directory${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites check passed${NC}"
echo ""

# Build virtual eUICC
echo -e "${BLUE}Building virtual eUICC...${NC}"
if make clean && make; then
    echo -e "${GREEN}✓ Virtual eUICC built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build virtual eUICC${NC}"
    exit 1
fi
echo ""

# Start virtual eUICC server
echo -e "${BLUE}Starting virtual eUICC server...${NC}"
./bin/v-euicc-server --debug --address "$V_EUICC_SOCKET" &
V_EUICC_PID=$!

# Wait for server to start
if ! wait_for_server "$V_EUICC_SOCKET"; then
    exit 1
fi
echo ""

# Configure environment for lpac
echo -e "${BLUE}Configuring lpac environment...${NC}"
export V_EUICC_ADDRESS="$V_EUICC_SOCKET"
export V_EUICC_CONNECTION_TYPE="unix"

echo -e "${GREEN}✓ Environment configured:${NC}"
echo -e "  V_EUICC_ADDRESS=$V_EUICC_ADDRESS"
echo -e "  V_EUICC_CONNECTION_TYPE=$V_EUICC_CONNECTION_TYPE"
echo ""

# Build lpac if needed
echo -e "${BLUE}Checking lpac build...${NC}"
cd "$LPAC_PATH"
if [ ! -f "output/lpac" ]; then
    echo -e "${YELLOW}Building lpac...${NC}"
    if command_exists cmake; then
        mkdir -p build
        cd build
        cmake .. -DLPAC_WITH_APDU_PCSC=OFF
        make
        cd ..
    else
        echo -e "${RED}✗ cmake not found. Please build lpac manually${NC}"
        exit 1
    fi
fi

if [ ! -f "output/lpac" ]; then
    echo -e "${RED}✗ lpac binary not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ lpac is available${NC}"
echo ""

# Demonstrate virtual eUICC functionality
echo -e "${BLUE}╔════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Running Demo Commands        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════╝${NC}"
echo ""

# Function to run lpac command with error handling
run_lpac_command() {
    local description="$1"
    shift
    echo -e "${YELLOW}$description${NC}"
    echo -e "${BLUE}Command: LPAC_APDU=v_euicc ./output/lpac $*${NC}"
    
    if LPAC_APDU=v_euicc ./output/lpac "$@"; then
        echo -e "${GREEN}✓ Success${NC}"
    else
        echo -e "${RED}✗ Command failed${NC}"
    fi
    echo ""
}

# Test basic connectivity
run_lpac_command "Testing virtual eUICC connectivity" chip info

# Test profile operations (these will likely fail as we don't have actual profiles)
run_lpac_command "Listing profiles" profile list

# Test eUICC information
run_lpac_command "Getting eUICC info" chip euiccinfo2

# Test configured addresses
run_lpac_command "Getting configured addresses" chip defaultsmdp

# Test additional RSP operations
run_lpac_command "Testing driver list" driver apdu list

# Test profile discovery (this will likely require a real SM-DP+ server)
echo -e "${YELLOW}Testing profile discovery (requires SM-DP+ server)${NC}"
echo -e "${BLUE}Command: LPAC_APDU=v_euicc ./output/lpac profile discovery${NC}"
if LPAC_APDU=v_euicc ./output/lpac profile discovery 2>/dev/null; then
    echo -e "${GREEN}✓ Profile discovery successful${NC}"
else
    echo -e "${YELLOW}⚠ Profile discovery failed (expected without SM-DP+ server)${NC}"
fi
echo ""

echo -e "${BLUE}╔════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Demo Complete             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════╝${NC}"
echo ""

echo -e "${GREEN}Demo completed successfully!${NC}"
echo ""
echo -e "${YELLOW}What happened:${NC}"
echo -e "1. Built the virtual eUICC server"
echo -e "2. Started the server on Unix socket: $V_EUICC_SOCKET"
echo -e "3. Configured lpac to use the virtual eUICC driver"
echo -e "4. Executed various lpac commands through the virtual eUICC"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "• Review the server debug logs above"
echo -e "• Implement actual SGP.22 APDU responses"
echo -e "• Add profile management functionality"
echo -e "• Integrate with SM-DP+ servers"
echo -e "• Add certificate handling"
echo ""
echo -e "${BLUE}The virtual eUICC server will be stopped when you press Ctrl+C${NC}"

# Keep server running until user interrupts
echo -e "${YELLOW}Press Ctrl+C to stop the demo...${NC}"
wait $V_EUICC_PID 