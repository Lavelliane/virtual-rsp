<p align="center">
  <img src="./virtual.png" alt="Virtual eUICC Logo" width="220" />
</p>

# Virtual eUICC (v-euicc)

A software implementation of an eUICC (Embedded Universal Integrated Circuit Card) that conforms to the GSMA SGP.22 standard. This virtual eUICC eliminates the need for physical smart cards and PCSC readers when developing and testing eSIM applications.

## Features

- **SGP.22 Compliant**: Implements ES10a, ES10b, and ES10c interfaces
- **No Hardware Required**: Eliminates dependency on PCSC card readers
- **Flexible Certificate Support**: Designed to support current and future Post-Quantum Cryptography (PQC)
- **Multiple Communication Methods**: Unix sockets and TCP sockets
- **lpac Integration**: Custom APDU driver for seamless lpac integration
- **Profile Management**: Support for multiple eSIM profiles
- **Debug Mode**: Comprehensive logging for development and testing

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     lpac        │    │   v-euicc       │    │   SM-DP+        │
│                 │    │   server        │    │   server        │
│  ┌───────────┐  │    │                 │    │                 │
│  │ v_euicc   │  │◄──►│ Protocol        │    │                 │
│  │ driver    │  │    │ Handler         │    │                 │
│  └───────────┘  │    │                 │    │                 │
│                 │    │ ┌─────────────┐ │    │                 │
│  ┌───────────┐  │    │ │   Virtual   │ │    │                 │
│  │ ES10a/b/c │  │    │ │   eUICC     │ │◄──►│   ES9+ API      │
│  │ Interface │  │    │ │   Core      │ │    │                 │
│  └───────────┘  │    │ └─────────────┘ │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Build the Virtual eUICC

```bash
cd v-euicc
make
```

### 2. Start the Virtual eUICC Server

```bash
# Using Unix socket (default)
./bin/v-euicc-server --debug

# Using TCP socket
./bin/v-euicc-server --type tcp --port 8765 --debug
```

### 3. Configure lpac to Use Virtual eUICC

```bash
# Set environment variables for the virtual eUICC driver
export V_EUICC_ADDRESS="/tmp/v-euicc.sock"
export V_EUICC_CONNECTION_TYPE="unix"

# Run lpac with the virtual eUICC driver
cd ../lpac
./output/lpac -a v_euicc profile list
```

## Configuration

The virtual eUICC can be configured using a JSON configuration file:

```json
{
  "eid": "89049032000000000000000000000123",
  "default_smdp_address": "testsmdpplus1.example.com",
  "root_smds_address": "prod.smds.gsma.com",
  "comm_method": 0,
  "comm_address": "/tmp/v-euicc.sock",
  "comm_port": 8765,
  "debug_mode": true,
  "storage_path": "./v-euicc/storage"
}
```

## Certificate Management

The virtual eUICC supports flexible certificate handling:

### Current Support
- ECDSA P-256
- ECDSA P-384  
- RSA 2048/4096

### Future PQC Support
- Dilithium2/3/5
- Falcon-512/1024

Certificate paths can be configured per certificate type:

```json
"certificate": {
  "euicc": {
    "type": "ecdsa_p256",
    "cert_path": "./certs/euicc_cert.pem",
    "private_key_path": "./certs/euicc_key.pem",
    "pqc_enabled": false
  }
}
```

## Environment Variables

### For Virtual eUICC Server
- `V_EUICC_CONFIG`: Configuration file path
- `V_EUICC_DEBUG`: Enable debug mode

### For lpac Driver
- `V_EUICC_ADDRESS`: Socket path or IP address
- `V_EUICC_PORT`: TCP port (default: 8765)
- `V_EUICC_CONNECTION_TYPE`: `unix` or `tcp`

## Protocol

The virtual eUICC uses a custom binary protocol for communication:

- **Magic Number**: 0x56455543 ("VEUC")
- **Version**: 1
- **Message Types**: Connect, Disconnect, APDU Transmission, etc.
- **Error Handling**: Comprehensive error codes
- **Checksums**: CRC32 validation

## SGP.22 Operations

### ES10a (Local Profile Assistant)
- Get configured addresses
- Set default SM-DP+ address

### ES10b (Profile Download)
- Get eUICC challenge and info
- Authenticate server
- Prepare download
- Load bound profile package

### ES10c (Profile Management)
- List profiles
- Enable/disable profiles
- Delete profiles
- Get profile info

## Development

### Building with Debug Information

```bash
make debug
```

### Running Tests

```bash
make test
```

### Integration with lpac

The virtual eUICC driver is automatically integrated into lpac through the driver system. To use it:

1. Start the virtual eUICC server
2. Set the appropriate environment variables
3. Run lpac with `-a v_euicc`

## Future Enhancements

1. **Post-Quantum Cryptography**: Full support for PQC algorithms
2. **Hardware Security Module**: Integration with HSMs for key storage
3. **Multi-client Support**: Concurrent client connections
4. **Profile Templates**: Pre-configured profile templates
5. **Web Interface**: Browser-based management interface
6. **Docker Support**: Containerized deployment

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure the virtual eUICC server is running
2. **Permission Denied**: Check socket file permissions
3. **Port in Use**: Change the TCP port or kill existing processes

### Debug Mode

Enable debug mode for detailed logging:

```bash
./bin/v-euicc-server --debug
```

### Log Analysis

Debug logs include:
- Client connections/disconnections
- APDU commands and responses
- Protocol message details
- Certificate operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is part of the eSIM development framework and follows the same licensing as the lpac project.

## References

- [GSMA SGP.22](https://www.gsma.com/esim/wp-content/uploads/2020/06/SGP.22-v2.2.2.pdf) - RSP Technical Specification
- [lpac](https://github.com/estkme-group/lpac) - Local Profile Assistant Client
- [pySim](https://osmocom.org/projects/pysim/) - Python SIM/eSIM toolkit 