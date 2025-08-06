# eSIM Development Suite

A comprehensive eSIM development and testing suite implementing the complete SGP.22 (Remote SIM Provisioning) protocol stack with three integrated components working together to provide a full virtual eSIM environment.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│      lpac       │    │     v-euicc     │    │     pySim       │
│  (LPA Client)   │◄──►│ (Virtual eUICC) │◄──►│  (SM-DP+ Server)│
│                 │    │                 │    │                 │
│ • Profile Mgmt  │    │ • SGP.22 Impl  │    │ • eSIM Server   │
│ • ES10 Commands │    │ • ECDSA Crypto  │    │ • ES9+ Endpoints│
│ • APDU Protocol │    │ • Binary Proto  │    │ • Profile Store │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Main Demo Entrypoint

The primary way to run and test the complete system is through the comprehensive demo:

```bash
cd v-euicc
python3 comprehensive_sgp22_demo.py
```

This demo automatically:
- Builds and starts all three components
- Performs complete SGP.22 protocol testing
- Validates APDU command/response flows
- Tests cryptographic operations (ECDSA)
- Generates comprehensive compliance reports

## 📋 Components

### 1. lpac - Local Profile Assistant Client
**Location**: `lpac/`  
**Purpose**: SGP.22 compliant LPA client for eSIM profile management

**Features:**
- Profile discovery, download, installation
- ES10a/b/c interface implementation
- Support for activation and confirmation codes
- Virtual eUICC driver integration

### 2. v-euicc - Virtual eUICC Server
**Location**: `v-euicc/`  
**Purpose**: Software implementation of an eUICC (virtual smart card)

**Features:**
- SGP.22 compliant eUICC simulation
- ECDSA P-256 cryptographic operations
- Binary communication protocol
- No hardware dependencies

### 3. pySim - eSIM Toolkit & SM-DP+ Server
**Location**: `pysim/`  
**Purpose**: Python-based eSIM tools including SM-DP+ server

**Features:**
- SM-DP+ server with ES9+ endpoints
- eSIM profile management
- Certificate authority operations
- SIM/USIM/eUICC analysis tools

## ⚙️ Setup Instructions

### Prerequisites

#### System Dependencies (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcsclite-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    zip
```

#### macOS Dependencies
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake openssl libpcsclite python3
```

### Component Setup

#### 1. Setup lpac (LPA Client)
```bash
cd lpac

# Install dependencies (Debian/Ubuntu)
./scripts/setup-debian.sh

# Build lpac
cmake -B build -S .
cmake --build build
cp build/src/lpac output/

# Verify installation
./output/lpac --help
```

#### 2. Setup v-euicc (Virtual eUICC)
```bash
cd v-euicc

# Build the virtual eUICC server
make

# For debug build with detailed logging
make debug

# Verify installation
./bin/v-euicc-server --help
```

#### 3. Setup pySim (SM-DP+ Server)
```bash
cd pysim

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install pySim in development mode
pip install -e .

# Verify installation
python3 osmo-smdpp.py --help
```

## 🎯 Running the Complete Demo

### Comprehensive SGP.22 Demo

The main entrypoint provides complete end-to-end testing:

```bash
cd v-euicc
python3 comprehensive_sgp22_demo.py
```

**What the demo does:**
1. **Component Startup**: Builds and starts all three services
2. **Protocol Testing**: Executes complete SGP.22 authentication flow
3. **APDU Analysis**: Captures and analyzes all APDU exchanges
4. **Crypto Validation**: Tests ECDSA operations and certificate chains
5. **Compliance Report**: Generates detailed SGP.22 compliance assessment

**Expected Output:**
```
🔐 Comprehensive SGP.22 Mutual Authentication with Full Protocol Analysis
================================================================================

📱 Step 1: Starting Virtual eUICC Server with Comprehensive Logging
✅ Virtual eUICC server started (PID: 12345)

🌐 Step 2: Starting SM-DP+ Server with Authentication Endpoints  
✅ SM-DP+ server started (PID: 12346)

📋 Step 3: LPAC Integration and APDU Protocol Testing
✅ ES10c.GetEID Command: EID: 89049032000000000000000000000123

🔐 Step 4: Complete SGP.22 Authentication Flow Testing
✅ ES10b.GetEUICCInfo1 APDU Detected
✅ ES10b.GetEUICCChallenge APDU Detected

🔒 Step 5: TLS Configuration and Security Validation
✅ Certificate Chain Validation: CI → EUM → eUICC

📊 Step 6: Complete Protocol Flow Analysis
🎯 Overall SGP.22 Compliance: 95.0% - EXCELLENT
```

## 🔧 Manual Component Usage

### Individual Component Testing

#### Virtual eUICC Server
```bash
cd v-euicc

# Start server with debug logging
./bin/v-euicc-server --debug --address /tmp/v-euicc.sock

# Or use TCP socket
./bin/v-euicc-server --type tcp --port 8765 --debug
```

#### lpac with Virtual eUICC
```bash
cd lpac

# Configure environment for virtual eUICC
export V_EUICC_ADDRESS="/tmp/v-euicc.sock"
export V_EUICC_CONNECTION_TYPE="unix"
export LPAC_APDU="v_euicc"

# Get eUICC information
./output/lpac chip info

# List profiles
./output/lpac profile list

# Profile discovery
./output/lpac profile discovery -s http://localhost:8080
```

#### SM-DP+ Server
```bash
cd pysim
source venv/bin/activate

# Start SM-DP+ server
python3 osmo-smdpp.py \
    --host 127.0.0.1 \
    --port 8080 \
    --certdir certs \
    --nossl
```

## 📁 Configuration

### Virtual eUICC Configuration
Edit `v-euicc/config/v-euicc.json`:
```json
{
  "eid": "89049032000000000000000000000123",
  "default_smdp_address": "testsmdpplus1.example.com",
  "comm_method": 0,
  "comm_address": "/tmp/v-euicc.sock",
  "debug_mode": true,
  "certificate": {
    "euicc": {
      "type": "ecdsa_p256",
      "cert_path": "./certs/euicc_cert.pem",
      "private_key_path": "./certs/euicc_key.pem"
    }
  }
}
```

### Environment Variables

#### For v-euicc server:
- `V_EUICC_CONFIG`: Configuration file path
- `V_EUICC_DEBUG`: Enable debug mode

#### For lpac client:
- `V_EUICC_ADDRESS`: Socket path or IP address
- `V_EUICC_PORT`: TCP port (default: 8765)
- `V_EUICC_CONNECTION_TYPE`: `unix` or `tcp`
- `LPAC_APDU`: Set to `v_euicc` for virtual eUICC driver

## 🧪 Testing & Validation

### Demo Test Scenarios

The comprehensive demo includes:

1. **Component Integration**: All services start and communicate
2. **SGP.22 Protocol**: Complete authentication flow validation
3. **APDU Protocol**: Command/response analysis with protocol compliance
4. **Cryptographic Operations**: ECDSA signature generation and verification
5. **Certificate Chain**: Complete PKI validation (CI → EUM → eUICC)
6. **Error Handling**: Robust error detection and reporting

### Manual Testing

```bash
# Test individual components
cd v-euicc && make test
cd lpac && ./output/lpac chip info
cd pysim && python3 -m pytest tests/

# Comprehensive system test
cd v-euicc && python3 comprehensive_sgp22_demo.py
```

## 🔍 Troubleshooting

### Common Issues

1. **Build Failures**
   ```bash
   # Missing dependencies
   sudo apt-get install build-essential cmake libssl-dev
   
   # Clean and rebuild
   make clean && make
   ```

2. **Connection Issues**
   ```bash
   # Check if v-euicc server is running
   ps aux | grep v-euicc-server
   
   # Verify socket exists
   ls -la /tmp/v-euicc.sock
   
   # Check environment variables
   echo $V_EUICC_ADDRESS
   ```

3. **Python Dependencies**
   ```bash
   cd pysim
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Debug Mode

Enable comprehensive logging:
```bash
# v-euicc with debug output
./bin/v-euicc-server --debug

# lpac with verbose output  
LPAC_DEBUG=1 ./output/lpac chip info

# pySim with debug logging
python3 osmo-smdpp.py --debug
```

### Log Analysis

Debug logs include:
- APDU command/response exchanges
- SGP.22 protocol message analysis
- Certificate operations and validation
- Network communication details
- Error conditions with stack traces

## 📚 Documentation

### SGP.22 Standard Compliance

This implementation follows:
- **SGP.22 v2.2.1**: Remote SIM Provisioning Technical Specification
- **ES10a**: Local Profile Assistant to Local Discovery Service
- **ES10b**: Local Profile Assistant to eUICC
- **ES10c**: Local Profile Assistant to Profile Manager
- **ES9+**: SM-DP+ interface

### Key Features Implemented

- ✅ EID generation and retrieval
- ✅ eUICC information commands (GetEUICCInfo1/2)
- ✅ Challenge generation (GetEUICCChallenge)
- ✅ Server authentication (AuthenticateServer)
- ✅ ECDSA P-256 cryptographic operations
- ✅ Certificate chain validation
- ✅ APDU protocol with ASN.1 encoding
- ✅ Profile discovery and management
- ✅ SM-DP+ server endpoints

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Make changes with proper testing
4. Run the comprehensive demo to validate
5. Submit pull request with detailed description

## 📄 License

- **lpac**: AGPL-v3.0-only (src/, driver/), LGPL-v2.1-only (euicc/)
- **pySim**: GPL-v2
- **v-euicc**: Part of eSIM development framework

## 🔗 References

- [GSMA SGP.22 v2.2.2](https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2020/06/SGP.22-v2.2.2.pdf) - RSP Technical Specification
- [lpac GitHub](https://github.com/estkme-group/lpac) - Local Profile Assistant Client
- [pySim Documentation](https://osmocom.org/projects/pysim/) - Python SIM/eSIM toolkit
- [SGP.22 Standard](https://www.gsma.com/esim/) - GSMA eSIM specifications

---

**🎯 Ready to develop and test eSIM applications with a complete SGP.22 implementation!**
